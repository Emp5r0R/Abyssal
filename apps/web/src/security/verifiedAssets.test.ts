import { describe, expect, it, vi } from "vitest";
import { MAX_VERIFIED_ASSET_BYTES, VerifiedAssetLoader, type VerifiableAsset } from "./verifiedAssets";

const ORIGIN = "https://abyssal.example";
const BYTES = new TextEncoder().encode("GIF89a-reaction");

async function sha256(value: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", Uint8Array.from(value)));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function asset(overrides: Partial<VerifiableAsset> = {}): Promise<VerifiableAsset> {
  return { path: "/abyssal-emojis/wave.gif", sha256Hex: await sha256(BYTES), size: BYTES.byteLength, mimeType: "image/gif", ...overrides };
}

function serving(body: Uint8Array = BYTES, init: ResponseInit = {}) {
  return vi.fn<typeof fetch>(async () => new Response(body.slice(), {
    headers: { "Content-Length": String(body.byteLength) },
    ...init,
  }));
}

function loader(fetcher: typeof fetch) {
  let next = 0;
  const revoked: string[] = [];
  const instance = new VerifiedAssetLoader({
    fetch: fetcher,
    origin: ORIGIN,
    createObjectUrl: () => `blob:${ORIGIN}/${next++}`,
    revokeObjectUrl: (url) => revoked.push(url),
  });
  return { instance, revoked };
}

describe("VerifiedAssetLoader", () => {
  it("releases bytes only when they match the compiled digest, fetching each asset once", async () => {
    const fetcher = serving();
    const { instance } = loader(fetcher);
    const wave = await asset();

    const [first, second] = await Promise.all([instance.load(wave), instance.load(wave)]);
    expect(first).toBe(second);
    expect(first.type).toBe("image/gif");
    expect(Array.from(new Uint8Array(await first.arrayBuffer()))).toEqual(Array.from(BYTES));
    expect(fetcher).toHaveBeenCalledTimes(1);
    const [url, init] = fetcher.mock.calls[0];
    expect(url).toBe(`${ORIGIN}/abyssal-emojis/wave.gif`);
    expect(init).toMatchObject({ credentials: "omit", redirect: "error", referrerPolicy: "no-referrer" });
  });

  it("hands out one blob URL per asset and revokes them on dispose", async () => {
    const { instance, revoked } = loader(serving());
    const wave = await asset();
    const url = await instance.objectUrl(wave);
    expect(await instance.objectUrl(wave)).toBe(url);
    expect(url.startsWith("blob:")).toBe(true);
    instance.dispose();
    expect(revoked).toEqual([url]);
  });

  it("rejects tampered, resized, unavailable or cross-origin content without exposing it", async () => {
    const wave = await asset();
    const tampered = new TextEncoder().encode("GIF89a-REACTION");
    await expect(loader(serving(tampered)).instance.load(wave)).rejects.toThrow("digest");
    await expect(loader(serving(BYTES.slice(1))).instance.load(wave)).rejects.toThrow("size");
    await expect(loader(serving(BYTES, { headers: { "Content-Length": "999" } })).instance.load(wave)).rejects.toThrow("size");
    await expect(loader(serving(BYTES, { status: 404 })).instance.load(wave)).rejects.toThrow("unavailable");

    const fetcher = serving();
    const { instance } = loader(fetcher);
    await expect(instance.load(await asset({ path: "//evil.example/wave.gif" }))).rejects.toThrow("same-origin");
    await expect(instance.load(await asset({ path: "/abyssal-emojis/wave.gif?x=1" }))).rejects.toThrow("same-origin");
    await expect(instance.load(await asset({ sha256Hex: "" }))).rejects.toThrow("verifiable");
    await expect(instance.load(await asset({ size: MAX_VERIFIED_ASSET_BYTES + 1 }))).rejects.toThrow("verifiable");
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("forgets a failed load so a later attempt can succeed", async () => {
    const fetcher = vi.fn<typeof fetch>()
      .mockRejectedValueOnce(new TypeError("offline"))
      .mockResolvedValueOnce(new Response(BYTES.slice()));
    const { instance } = loader(fetcher);
    const wave = await asset();
    await expect(instance.objectUrl(wave)).rejects.toThrow("offline");
    await expect(instance.objectUrl(wave)).resolves.toMatch(/^blob:/);
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
});

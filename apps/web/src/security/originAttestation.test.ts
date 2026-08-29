import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../generated/abyssal_core/abyssal_core", () => ({
  inspectReleaseManifest: (manifest: Uint8Array) => new TextDecoder().decode(manifest),
  releaseTrustAnchorConfigured: () => true,
}));

import { verifyOriginAttestation } from "./originAttestation";

const ORIGIN = "https://abyssal.example";
const MANIFEST_URL = `${ORIGIN}/.well-known/abyssal-release-manifest-v1.json`;
const SIGNATURE_URL = `${ORIGIN}/.well-known/abyssal-release-manifest-v1.sig`;
const IDENTITY = Object.freeze({
  buildId: "web@2.1.0",
  buildSignatureB64: "A".repeat(86),
  sourceCommit: "1".repeat(40),
  configured: true,
});

beforeEach(() => vi.restoreAllMocks());

describe("origin release attestation", () => {
  it("accepts only when signed identity and every served asset digest agree", async () => {
    const fixture = await releaseFixture();
    const result = await verifyOriginAttestation({
      fetch: fixture.fetcher,
      origin: ORIGIN,
      nowMs: 1_500,
      identity: IDENTITY,
    });
    expect(result).toEqual({ status: "OK" });
    expect(fixture.requested).toEqual([
      MANIFEST_URL,
      SIGNATURE_URL,
      `${ORIGIN}/build-id.json`,
      `${ORIGIN}/assets/app.js`,
      `${ORIGIN}/assets/core.wasm`,
      `${ORIGIN}/build-id.json`,
      `${ORIGIN}/index.html`,
    ]);
    expect(fixture.requested.every((url) => new URL(url).origin === ORIGIN)).toBe(true);
    expect(fixture.requests).toHaveLength(fixture.requested.length);
    for (const { init } of fixture.requests) {
      expect(init).toMatchObject({
        method: "GET",
        cache: "no-store",
        credentials: "omit",
        referrerPolicy: "no-referrer",
        redirect: "error",
      });
      expect(init.signal).toBeInstanceOf(AbortSignal);
    }
  });

  it("fails closed for a changed asset, stale approval, and network failure", async () => {
    const changed = await releaseFixture({ corrupt: `${ORIGIN}/assets/app.js` });
    await expectStatus(changed.fetcher, 1_500, "MISMATCH");
    expect(changed.requested.filter((url) => url === `${ORIGIN}/assets/app.js`)).toHaveLength(1);

    const stale = await releaseFixture();
    await expectStatus(stale.fetcher, 2_000, "STALE");

    const unavailable = vi.fn<typeof fetch>().mockRejectedValue(new TypeError("offline"));
    await expectStatus(unavailable, 1_500, "UNAVAILABLE");
    expect(unavailable).toHaveBeenCalledTimes(3);
  });

  it("recovers from bounded transient body availability failures", async () => {
    const assetUrl = `${ORIGIN}/assets/app.js`;
    const fixture = await releaseFixture({
      transientFailures: { [assetUrl]: 2 },
    });
    const result = await verifyOriginAttestation({
      fetch: fixture.fetcher,
      origin: ORIGIN,
      nowMs: 1_500,
      identity: IDENTITY,
    });
    expect(result).toEqual({ status: "OK" });
    expect(fixture.requested.filter((url) => url === assetUrl)).toHaveLength(3);
  });

  it("rejects unconfigured build identity before making a request", async () => {
    const fetcher = vi.fn<typeof fetch>();
    const result = await verifyOriginAttestation({
      fetch: fetcher,
      origin: ORIGIN,
      nowMs: 1_500,
      identity: { ...IDENTITY, configured: false },
    });
    expect(result.status).toBe("MISMATCH");
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("rejects a release response redirected outside the page origin", async () => {
    const redirected = await releaseFixture({
      manifestFinalUrl: "https://evil.example/release-manifest-v1.json",
    });
    await expectStatus(redirected.fetcher, 1_500, "MISMATCH");
    expect(redirected.requested.every((url) => new URL(url).origin === ORIGIN)).toBe(true);
  });

  it("accepts an explicit port when every response remains on that exact origin", async () => {
    const portOrigin = "https://abyssal.example:4443";
    const fixture = await releaseFixture({ origin: portOrigin });
    const result = await verifyOriginAttestation({
      fetch: fixture.fetcher,
      origin: portOrigin,
      nowMs: 1_500,
      identity: IDENTITY,
    });
    expect(result).toEqual({ status: "OK" });
    expect(fixture.requested.every((url) => new URL(url).origin === portOrigin)).toBe(true);
  });

  it("verifies the complete asset set with bounded parallelism", async () => {
    const fixture = await releaseFixture({ extraAssets: 12, assetDelayMs: 10 });
    const result = await verifyOriginAttestation({
      fetch: fixture.fetcher,
      origin: ORIGIN,
      nowMs: 1_500,
      identity: IDENTITY,
    });
    expect(result).toEqual({ status: "OK" });
    expect(fixture.requested.filter((url) => url.includes("/assets/parallel-"))).toHaveLength(12);
    expect(fixture.maxActiveAssetRequests()).toBeGreaterThan(1);
    expect(fixture.maxActiveAssetRequests()).toBeLessThanOrEqual(4);
  });
});

async function expectStatus(
  fetcher: typeof fetch,
  nowMs: number,
  status: "MISMATCH" | "STALE" | "UNAVAILABLE",
): Promise<void> {
  const result = await verifyOriginAttestation({
    fetch: fetcher,
    origin: ORIGIN,
    nowMs,
    identity: IDENTITY,
  });
  expect(result.status).toBe(status);
}

async function releaseFixture(options: {
  corrupt?: string;
  manifestFinalUrl?: string;
  origin?: string;
  extraAssets?: number;
  assetDelayMs?: number;
  transientFailures?: Readonly<Record<string, number>>;
} = {}): Promise<{
  fetcher: typeof fetch;
  requested: string[];
  requests: Array<{ url: string; init: RequestInit }>;
  maxActiveAssetRequests: () => number;
}> {
  const origin = options.origin ?? ORIGIN;
  const manifestUrl = `${origin}/.well-known/abyssal-release-manifest-v1.json`;
  const signatureUrl = `${origin}/.well-known/abyssal-release-manifest-v1.sig`;
  const identityBytes = bytes(JSON.stringify({
    schema: "abyssal-build-identity-v1",
    build_id: IDENTITY.buildId,
    source_commit: IDENTITY.sourceCommit,
    build_signature_b64: IDENTITY.buildSignatureB64,
  }));
  const content = new Map<string, Uint8Array>([
    [`${origin}/assets/app.js`, bytes("console.log('verified')")],
    [`${origin}/assets/core.wasm`, new Uint8Array([0, 97, 115, 109])],
    [`${origin}/build-id.json`, identityBytes],
    [`${origin}/index.html`, bytes("<!doctype html><main>Abyssal</main>")],
  ]);
  for (let index = 0; index < (options.extraAssets ?? 0); index += 1) {
    content.set(`${origin}/assets/parallel-${index}.bin`, bytes(`asset-${index}`));
  }
  const assets = await Promise.all([...content.entries()].map(async ([name, data]) => ({
    name: name.slice(origin.length + 1),
    sha256_hex: await sha256(data),
    size: String(data.byteLength),
  })));
  assets.sort((left, right) => left.name.localeCompare(right.name));
  const manifest = bytes(JSON.stringify({
    not_before_ms: "1000",
    expires_at_ms: "2000",
    builds: [{
      build_id: IDENTITY.buildId,
      source_commit: IDENTITY.sourceCommit,
      build_signature_b64: IDENTITY.buildSignatureB64,
      assets,
    }],
    revoked_build_ids: [],
  }));
  const requested: string[] = [];
  const requests: Array<{ url: string; init: RequestInit }> = [];
  let activeAssetRequests = 0;
  let maxActiveAssetRequests = 0;
  const transientFailures = new Map(Object.entries(options.transientFailures ?? {}));
  const fetcher = vi.fn<typeof fetch>(async (input, init) => {
    const url = String(input);
    requested.push(url);
    requests.push({ url, init: init ?? {} });
    const failuresRemaining = transientFailures.get(url) ?? 0;
    if (failuresRemaining > 0) {
      transientFailures.set(url, failuresRemaining - 1);
      throw new TypeError("transient body failure");
    }
    if (url === manifestUrl) return response(manifest, options.manifestFinalUrl ?? manifestUrl);
    if (url === signatureUrl) return response(new Uint8Array(64), signatureUrl);
    const expected = content.get(url);
    if (!expected) return response(bytes("missing"), url, 404);
    if ((options.assetDelayMs ?? 0) > 0 && url.startsWith(`${origin}/assets/`)) {
      activeAssetRequests += 1;
      maxActiveAssetRequests = Math.max(maxActiveAssetRequests, activeAssetRequests);
      try {
        await new Promise((resolve) => setTimeout(resolve, options.assetDelayMs));
      } finally {
        activeAssetRequests -= 1;
      }
    }
    const body = options.corrupt === url ? bytes("changed") : expected;
    return response(body, url);
  });
  return {
    fetcher,
    requested,
    requests,
    maxActiveAssetRequests: () => maxActiveAssetRequests,
  };
}

function response(body: Uint8Array, url: string, status = 200): Response {
  const result = new Response(body.slice(), {
    status,
    headers: { "Content-Length": String(body.byteLength) },
  });
  Object.defineProperty(result, "url", { value: url });
  return result;
}

function bytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

async function sha256(value: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", Uint8Array.from(value)));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

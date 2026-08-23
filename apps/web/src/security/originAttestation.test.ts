import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../generated/abyssal_core/abyssal_core", () => ({
  inspectReleaseManifest: (manifest: Uint8Array) => new TextDecoder().decode(manifest),
  releaseTrustAnchorConfigured: () => true,
}));

import { verifyOriginAttestation } from "./originAttestation";

const ORIGIN = "https://abyssal.example";
const API = "https://api.github.com/repos/Emp5r0R/Abyssal/releases/latest";
const MANIFEST_URL = "https://github.com/Emp5r0R/Abyssal/releases/download/v2/release-manifest-v1.json";
const SIGNATURE_URL = "https://github.com/Emp5r0R/Abyssal/releases/download/v2/release-manifest-v1.sig";
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
      API,
      MANIFEST_URL,
      SIGNATURE_URL,
      `${ORIGIN}/build-id.json`,
      `${ORIGIN}/assets/app.js`,
      `${ORIGIN}/assets/core.wasm`,
      `${ORIGIN}/build-id.json`,
      `${ORIGIN}/index.html`,
    ]);
  });

  it("fails closed for a changed asset, stale approval, and network failure", async () => {
    const changed = await releaseFixture({ corrupt: `${ORIGIN}/assets/app.js` });
    await expectStatus(changed.fetcher, 1_500, "MISMATCH");

    const stale = await releaseFixture();
    await expectStatus(stale.fetcher, 2_000, "STALE");

    const unavailable = vi.fn<typeof fetch>().mockRejectedValue(new TypeError("offline"));
    await expectStatus(unavailable, 1_500, "UNAVAILABLE");
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

async function releaseFixture(options: { corrupt?: string } = {}): Promise<{
  fetcher: typeof fetch;
  requested: string[];
}> {
  const identityBytes = bytes(JSON.stringify({
    schema: "abyssal-build-identity-v1",
    build_id: IDENTITY.buildId,
    source_commit: IDENTITY.sourceCommit,
    build_signature_b64: IDENTITY.buildSignatureB64,
  }));
  const content = new Map<string, Uint8Array>([
    [`${ORIGIN}/assets/app.js`, bytes("console.log('verified')")],
    [`${ORIGIN}/assets/core.wasm`, new Uint8Array([0, 97, 115, 109])],
    [`${ORIGIN}/build-id.json`, identityBytes],
    [`${ORIGIN}/index.html`, bytes("<!doctype html><main>Abyssal</main>")],
  ]);
  const assets = await Promise.all([...content.entries()].map(async ([name, data]) => ({
    name: name.slice(ORIGIN.length + 1),
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
  const api = bytes(JSON.stringify({
    draft: false,
    prerelease: false,
    assets: [
      { name: "release-manifest-v1.json", browser_download_url: MANIFEST_URL },
      { name: "release-manifest-v1.sig", browser_download_url: SIGNATURE_URL },
    ],
  }));
  const requested: string[] = [];
  const fetcher = vi.fn<typeof fetch>(async (input) => {
    const url = String(input);
    requested.push(url);
    if (url === API) return response(api, API);
    if (url === MANIFEST_URL) return response(manifest, MANIFEST_URL);
    if (url === SIGNATURE_URL) return response(new Uint8Array(64), SIGNATURE_URL);
    const expected = content.get(url);
    if (!expected) return response(bytes("missing"), url, 404);
    const body = options.corrupt === url ? bytes("changed") : expected;
    return response(body, url);
  });
  return { fetcher, requested };
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

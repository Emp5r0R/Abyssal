import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../generated/abyssal_core/abyssal_core", () => ({
  inspectReleaseManifest: (manifest: Uint8Array) => new TextDecoder().decode(manifest),
  releaseTrustAnchorConfigured: () => true,
}));

vi.mock("../buildIdentity", () => ({
  RELEASE_BUILD_IDENTITY: Object.freeze({
    buildId: "web@2.1.0",
    buildSignatureB64: "A".repeat(86),
    sourceCommit: "1".repeat(40),
    configured: true,
  }),
}));

import { verifyOriginAttestation, verifyOriginPreflight } from "./originAttestation";

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

  it("performs a fresh lightweight preflight without replacing the full startup audit", async () => {
    const fixture = await releaseFixture();
    const result = await verifyOriginPreflight({
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
    ]);
  });

  it("does not reuse a completed preflight for a later account submit", async () => {
    vi.spyOn(Date, "now").mockReturnValue(1_500);
    const origin = window.location.origin;
    const fixture = await releaseFixture({ origin });
    vi.stubGlobal("fetch", fixture.fetcher);
    try {
      await expect(verifyOriginPreflight()).resolves.toEqual({ status: "OK" });
      await expect(verifyOriginPreflight()).resolves.toEqual({ status: "OK" });
      expect(fixture.requested).toEqual([
        `${origin}/.well-known/abyssal-release-manifest-v1.json`,
        `${origin}/.well-known/abyssal-release-manifest-v1.sig`,
        `${origin}/build-id.json`,
        `${origin}/.well-known/abyssal-release-manifest-v1.json`,
        `${origin}/.well-known/abyssal-release-manifest-v1.sig`,
        `${origin}/build-id.json`,
      ]);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("shares concurrent default startup audits but starts a later audit fresh", async () => {
    vi.spyOn(Date, "now").mockReturnValue(1_500);
    const origin = window.location.origin;
    const firstFixture = await releaseFixture({ origin });
    vi.stubGlobal("fetch", firstFixture.fetcher);
    try {
      const first = verifyOriginAttestation();
      const concurrent = verifyOriginAttestation();
      await expect(Promise.all([first, concurrent])).resolves.toEqual([
        { status: "OK" },
        { status: "OK" },
      ]);
      expect(firstFixture.requested).toHaveLength(7);

      const laterFixture = await releaseFixture({ origin });
      vi.stubGlobal("fetch", laterFixture.fetcher);
      await expect(verifyOriginAttestation()).resolves.toEqual({ status: "OK" });
      expect(laterFixture.requested).toHaveLength(7);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("fails the lightweight preflight for a revoked build", async () => {
    const fixture = await releaseFixture({ revokedBuildIds: [IDENTITY.buildId] });
    const result = await verifyOriginPreflight({
      fetch: fixture.fetcher,
      origin: ORIGIN,
      nowMs: 1_500,
      identity: IDENTITY,
    });
    expect(result).toEqual({ status: "MISMATCH" });
    expect(fixture.requested).toEqual([MANIFEST_URL, SIGNATURE_URL]);
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

  it("aborts a never-resolving request at the total deadline and retries fresh", async () => {
    vi.useFakeTimers();
    try {
      const fetcher = vi.fn<typeof fetch>(() => new Promise<Response>(() => undefined));
      const overrides = {
        fetch: fetcher,
        origin: ORIGIN,
        nowMs: 1_500,
        identity: IDENTITY,
        timeoutMs: 10,
      };

      const first = verifyOriginAttestation(overrides);
      await vi.advanceTimersByTimeAsync(10);
      await expect(first).resolves.toEqual({ status: "UNAVAILABLE" });
      expect(fetcher.mock.calls[0]?.[1]?.signal).toBeInstanceOf(AbortSignal);
      expect(fetcher.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);

      const second = verifyOriginAttestation(overrides);
      await vi.advanceTimersByTimeAsync(10);
      await expect(second).resolves.toEqual({ status: "UNAVAILABLE" });
      expect(fetcher).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it("aborts a never-resolving asset request at the total audit deadline", async () => {
    vi.useFakeTimers();
    try {
      const fixture = await releaseFixture({ hang: `${ORIGIN}/assets/core.wasm` });
      const verification = verifyOriginAttestation({
        fetch: fixture.fetcher,
        origin: ORIGIN,
        nowMs: 1_500,
        identity: IDENTITY,
        timeoutMs: 10,
      });

      await vi.advanceTimersByTimeAsync(10);

      await expect(verification).resolves.toEqual({ status: "UNAVAILABLE" });
      expect(fixture.requested).toContain(`${ORIGIN}/assets/core.wasm`);
    } finally {
      vi.useRealTimers();
    }
  });

  it("keeps a download that is still making progress alive past the stall timeout", async () => {
    vi.useFakeTimers();
    try {
      const fixture = await releaseFixture({ slow: { url: `${ORIGIN}/assets/app.js`, intervalMs: 8_000 } });
      const verification = verifyOriginAttestation({ fetch: fixture.fetcher, origin: ORIGIN, nowMs: 1_500, identity: IDENTITY });
      await vi.advanceTimersByTimeAsync(60_000);
      await expect(verification).resolves.toEqual({ status: "OK" });
      expect(fixture.requested.filter((url) => url === `${ORIGIN}/assets/app.js`)).toHaveLength(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("abandons a download that stops making progress, after bounded retries", async () => {
    vi.useFakeTimers();
    try {
      const assetUrl = `${ORIGIN}/assets/app.js`;
      const fixture = await releaseFixture({ slow: { url: assetUrl, intervalMs: 1_000, stallAfterChunks: 1 } });
      const verification = verifyOriginAttestation({ fetch: fixture.fetcher, origin: ORIGIN, nowMs: 1_500, identity: IDENTITY });
      await vi.advanceTimersByTimeAsync(11_000);
      expect(fixture.requested.filter((url) => url === assetUrl)).toHaveLength(1);
      await vi.advanceTimersByTimeAsync(40_000);
      await expect(verification).resolves.toEqual({ status: "UNAVAILABLE" });
      expect(fixture.requested.filter((url) => url === assetUrl)).toHaveLength(3);
    } finally {
      vi.useRealTimers();
    }
  });

  it("skips downloading assets whose digests ship in the bundle, but requires the manifest to agree", async () => {
    const gif = bytes("GIF89a-reaction");
    const fixture = await releaseFixture({ deferred: { "abyssal-emojis/wave.gif": gif } });
    const digest = { sha256Hex: await sha256(gif), size: gif.byteLength };
    const verify = (deferredAssets: Record<string, { sha256Hex: string; size: number }>) => verifyOriginAttestation({
      fetch: fixture.fetcher, origin: ORIGIN, nowMs: 1_500, identity: IDENTITY, deferredAssets,
    });

    await expect(verify({ "abyssal-emojis/wave.gif": digest })).resolves.toEqual({ status: "OK" });
    expect(fixture.requested).not.toContain(`${ORIGIN}/abyssal-emojis/wave.gif`);

    await expect(verify({ "abyssal-emojis/wave.gif": { ...digest, sha256Hex: "0".repeat(64) } }))
      .resolves.toEqual({ status: "MISMATCH" });
    await expect(verify({ "abyssal-emojis/wave.gif": { ...digest, size: digest.size + 1 } }))
      .resolves.toEqual({ status: "MISMATCH" });

    fixture.requested.length = 0;
    await expect(verify({})).resolves.toEqual({ status: "OK" });
    expect(fixture.requested).toContain(`${ORIGIN}/abyssal-emojis/wave.gif`);
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

  it("verifies the complete asset set with conservative bounded parallelism", async () => {
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
  hang?: string;
  transientFailures?: Readonly<Record<string, number>>;
  revokedBuildIds?: string[];
  deferred?: Readonly<Record<string, Uint8Array>>;
  slow?: { url: string; intervalMs: number; stallAfterChunks?: number };
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
  for (const [name, data] of Object.entries(options.deferred ?? {})) content.set(`${origin}/${name}`, data);
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
    revoked_build_ids: options.revokedBuildIds ?? [],
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
    if (url === options.hang) return new Promise<Response>(() => undefined);
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
    if (options.slow?.url === url) {
      return streamingResponse(body, url, options.slow.intervalMs, options.slow.stallAfterChunks);
    }
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

/** Delivers the body in four chunks, one per interval, optionally going silent after some chunks. */
function streamingResponse(body: Uint8Array, url: string, intervalMs: number, stallAfterChunks?: number): Response {
  const chunkSize = Math.max(1, Math.ceil(body.byteLength / 4));
  let offset = 0;
  let sent = 0;
  const stream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (stallAfterChunks !== undefined && sent >= stallAfterChunks) return new Promise<void>(() => undefined);
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
      if (offset >= body.byteLength) {
        controller.close();
        return;
      }
      controller.enqueue(body.slice(offset, offset + chunkSize));
      offset += chunkSize;
      sent += 1;
    },
  });
  const result = new Response(stream, { headers: { "Content-Length": String(body.byteLength) } });
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

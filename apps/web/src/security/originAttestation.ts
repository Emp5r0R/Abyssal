import {
  inspectReleaseManifest,
  releaseTrustAnchorConfigured,
} from "../generated/abyssal_core/abyssal_core";
import { RELEASE_BUILD_IDENTITY, type ReleaseBuildIdentity } from "../buildIdentity";

export type OriginAttestationStatus =
  | "CHECKING"
  | "OK"
  | "MISMATCH"
  | "STALE"
  | "UNAVAILABLE"
  | "ATTESTATION_REJECTED";

export interface OriginAttestationResult {
  status: Exclude<OriginAttestationStatus, "CHECKING" | "ATTESTATION_REJECTED">;
}

interface AttestationContext {
  fetch: typeof globalThis.fetch;
  origin: string;
  nowMs: number;
  identity: Readonly<ReleaseBuildIdentity>;
}

interface ManifestAsset {
  name: string;
  sha256_hex: string;
  size: string;
}

interface ManifestBuild {
  build_id: string;
  source_commit: string;
  build_signature_b64: string;
  assets: ManifestAsset[];
}

interface VerifiedManifest {
  not_before_ms: string;
  expires_at_ms: string;
  builds: ManifestBuild[];
  revoked_build_ids: string[];
}

const RELEASE_MANIFEST_ENDPOINT = "/.well-known/abyssal-release-manifest-v1.json";
const RELEASE_SIGNATURE_ENDPOINT = "/.well-known/abyssal-release-manifest-v1.sig";
const MAX_MANIFEST_BYTES = 256 * 1024;
const SIGNATURE_BYTES = 64;
const MAX_WEB_ASSET_BYTES = 64 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 30_000;
const REQUEST_RETRY_DELAYS_MS = [250, 750] as const;
const REQUEST_ATTEMPTS = REQUEST_RETRY_DELAYS_MS.length + 1;
const ASSET_VERIFICATION_CONCURRENCY = 2;
const SAFE_ASSET_NAME = /^(?!\/)(?!.*(?:^|\/)\.{1,2}(?:\/|$))[A-Za-z0-9._/-]{1,192}$/u;
const LOWER_SHA256 = /^[0-9a-f]{64}$/u;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/u;

class MismatchError extends Error {}
class StaleError extends Error {}

export async function verifyOriginAttestation(
  overrides: Partial<AttestationContext> = {},
): Promise<OriginAttestationResult> {
  const context: AttestationContext = {
    fetch: overrides.fetch ?? globalThis.fetch.bind(globalThis),
    origin: overrides.origin ?? window.location.origin,
    nowMs: overrides.nowMs ?? Date.now(),
    identity: overrides.identity ?? RELEASE_BUILD_IDENTITY,
  };
  try {
    if (!context.identity.configured || !releaseTrustAnchorConfigured()) throw new MismatchError();
    const manifestUrl = sameOriginUrl(context.origin, RELEASE_MANIFEST_ENDPOINT);
    const manifestResponse = await boundedFetchWithRetry(
      context.fetch,
      manifestUrl,
      MAX_MANIFEST_BYTES,
    );
    requireSameOriginResponse(manifestResponse.url, context.origin, RELEASE_MANIFEST_ENDPOINT);
    const signatureUrl = sameOriginUrl(context.origin, RELEASE_SIGNATURE_ENDPOINT);
    const signatureResponse = await boundedFetchWithRetry(
      context.fetch,
      signatureUrl,
      SIGNATURE_BYTES,
    );
    requireSameOriginResponse(signatureResponse.url, context.origin, RELEASE_SIGNATURE_ENDPOINT);
    let canonical: string;
    try {
      if (signatureResponse.bytes.byteLength !== SIGNATURE_BYTES) throw new MismatchError();
      canonical = inspectReleaseManifest(manifestResponse.bytes, signatureResponse.bytes);
    } catch {
      throw new MismatchError();
    } finally {
      manifestResponse.bytes.fill(0);
      signatureResponse.bytes.fill(0);
    }
    const manifest = parseVerifiedManifest(canonical);
    const notBefore = parseSafeDecimal(manifest.not_before_ms);
    const expiresAt = parseSafeDecimal(manifest.expires_at_ms);
    if (context.nowMs < notBefore || context.nowMs >= expiresAt) throw new StaleError();
    if (manifest.revoked_build_ids.includes(context.identity.buildId)) throw new MismatchError();
    const webBuilds = manifest.builds.filter((build) => build.build_id.startsWith("web@"));
    if (webBuilds.length !== 1) throw new MismatchError();
    const webBuild = webBuilds[0];
    if (webBuild.build_id !== context.identity.buildId ||
      webBuild.source_commit !== context.identity.sourceCommit ||
      webBuild.build_signature_b64 !== context.identity.buildSignatureB64) {
      throw new MismatchError();
    }

    await verifyOriginBuildIdentity(context, webBuild);
    await verifyServedAssets(context, webBuild);
    return { status: "OK" };
  } catch (error) {
    if (error instanceof StaleError) return { status: "STALE" };
    if (error instanceof MismatchError) return { status: "MISMATCH" };
    return { status: "UNAVAILABLE" };
  }
}

async function verifyOriginBuildIdentity(
  context: AttestationContext,
  build: ManifestBuild,
): Promise<void> {
  const url = new URL("/build-id.json", context.origin);
  if (url.origin !== context.origin) throw new MismatchError();
  const response = await boundedFetchWithRetry(context.fetch, url.toString(), 1024);
  requireSameOriginResponse(response.url, context.origin, "/build-id.json");
  const identity = parseObjectJson(response.bytes);
  if (Object.keys(identity).sort().join("\0") !==
      ["build_id", "build_signature_b64", "schema", "source_commit"].sort().join("\0") ||
    identity.schema !== "abyssal-build-identity-v1" ||
    identity.build_id !== build.build_id ||
    identity.source_commit !== build.source_commit ||
    identity.build_signature_b64 !== build.build_signature_b64) {
    throw new MismatchError();
  }
}

async function verifyServedAssets(context: AttestationContext, build: ManifestBuild): Promise<void> {
  const version = build.build_id.slice("web@".length);
  const archiveName = `abyssal-web-${version}.tar.gz`;
  const servedAssets = build.assets.filter((asset) => asset.name !== archiveName);
  if (servedAssets.length < 4 || !servedAssets.some((asset) => asset.name === "index.html") ||
    !servedAssets.some((asset) => asset.name === "build-id.json") ||
    !servedAssets.some((asset) => asset.name.endsWith(".js")) ||
    !servedAssets.some((asset) => asset.name.endsWith(".wasm"))) {
    throw new MismatchError();
  }
  const candidates = servedAssets.map((asset) => {
    if (!SAFE_ASSET_NAME.test(asset.name) || !LOWER_SHA256.test(asset.sha256_hex)) {
      throw new MismatchError();
    }
    const expectedSize = parseSafeDecimal(asset.size);
    if (expectedSize > MAX_WEB_ASSET_BYTES) throw new MismatchError();
    const url = new URL(`/${asset.name}`, context.origin);
    if (url.origin !== context.origin || url.pathname !== `/${asset.name}`) throw new MismatchError();
    return { asset, expectedSize, url };
  });

  let nextIndex = 0;
  let failed = false;
  let failure: unknown;
  async function worker(): Promise<void> {
    while (!failed) {
      const index = nextIndex++;
      if (index >= candidates.length) return;
      try {
        await verifyServedAsset(context, candidates[index]);
      } catch (error) {
        if (!failed) {
          failed = true;
          failure = error;
        }
      }
    }
  }
  const workerCount = Math.min(ASSET_VERIFICATION_CONCURRENCY, candidates.length);
  await Promise.all(Array.from({ length: workerCount }, () => worker()));
  if (failed) throw failure;
}

async function verifyServedAsset(
  context: AttestationContext,
  candidate: { asset: ManifestAsset; expectedSize: number; url: URL },
): Promise<void> {
  const { asset, expectedSize, url } = candidate;
  const response = await boundedFetchWithRetry(context.fetch, url.toString(), expectedSize);
  let actual: string;
  try {
    requireSameOriginResponse(response.url, context.origin, url.pathname);
    if (response.bytes.byteLength !== expectedSize) throw new MismatchError();
    const digestInput = Uint8Array.from(response.bytes);
    let digest: Uint8Array | null = null;
    try {
      digest = new Uint8Array(await crypto.subtle.digest("SHA-256", digestInput));
      actual = Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
    } finally {
      digestInput.fill(0);
      digest?.fill(0);
    }
  } finally {
    response.bytes.fill(0);
  }
  if (actual !== asset.sha256_hex) throw new MismatchError();
}

async function boundedFetch(
  fetcher: typeof globalThis.fetch,
  url: string,
  maximum: number,
  init: RequestInit = {},
): Promise<{ bytes: Uint8Array; url: string }> {
  if (!Number.isSafeInteger(maximum) || maximum < 0 || maximum > MAX_WEB_ASSET_BYTES) {
    throw new MismatchError();
  }
  const response = await fetcher(url, {
    ...init,
    method: "GET",
    cache: "no-store",
    credentials: "omit",
    referrerPolicy: "no-referrer",
    redirect: "error",
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  if (!response.ok) throw new Error("unavailable");
  const declared = response.headers.get("Content-Length");
  if (declared !== null && (!DECIMAL.test(declared) || Number(declared) > maximum)) {
    throw new MismatchError();
  }
  const reader = response.body?.getReader();
  if (!reader) throw new Error("unavailable");
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maximum) throw new MismatchError();
      chunks.push(value);
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
      chunk.fill(0);
    }
    return { bytes, url: response.url || url };
  } finally {
    chunks.forEach((chunk) => chunk.fill(0));
    reader.releaseLock();
  }
}

async function boundedFetchWithRetry(
  fetcher: typeof globalThis.fetch,
  url: string,
  maximum: number,
  init: RequestInit = {},
): Promise<{ bytes: Uint8Array; url: string }> {
  let lastAvailabilityError: unknown;
  for (let attempt = 0; attempt < REQUEST_ATTEMPTS; attempt += 1) {
    try {
      return await boundedFetch(fetcher, url, maximum, init);
    } catch (error) {
      if (error instanceof MismatchError) throw error;
      lastAvailabilityError = error;
      const retryDelay = REQUEST_RETRY_DELAYS_MS[attempt];
      if (retryDelay !== undefined) {
        await new Promise((resolve) => setTimeout(resolve, retryDelay));
      }
    }
  }
  throw lastAvailabilityError;
}

function sameOriginUrl(origin: string, path: string): string {
  const url = new URL(path, origin);
  if (url.origin !== origin || url.pathname !== path) throw new MismatchError();
  return url.toString();
}

function requireSameOriginResponse(raw: string, origin: string, pathname: string): void {
  const url = new URL(raw);
  if (url.origin !== origin || url.pathname !== pathname || url.username || url.password ||
    url.search || url.hash) {
    throw new MismatchError();
  }
}

function parseVerifiedManifest(raw: string): VerifiedManifest {
  const value = JSON.parse(raw) as unknown;
  if (!plainObject(value) || !Array.isArray(value.builds) ||
    !Array.isArray(value.revoked_build_ids) || typeof value.not_before_ms !== "string" ||
    typeof value.expires_at_ms !== "string") throw new MismatchError();
  const builds = value.builds.filter(isManifestBuild);
  if (builds.length !== value.builds.length ||
    !value.revoked_build_ids.every((entry) => typeof entry === "string")) throw new MismatchError();
  return {
    not_before_ms: value.not_before_ms,
    expires_at_ms: value.expires_at_ms,
    builds,
    revoked_build_ids: value.revoked_build_ids as string[],
  };
}

function isManifestBuild(value: unknown): value is ManifestBuild {
  return plainObject(value) && typeof value.build_id === "string" &&
    typeof value.source_commit === "string" && typeof value.build_signature_b64 === "string" &&
    Array.isArray(value.assets) && value.assets.every((asset) =>
      plainObject(asset) && typeof asset.name === "string" &&
      typeof asset.sha256_hex === "string" && typeof asset.size === "string");
}

function parseObjectJson(bytes: Uint8Array): Record<string, unknown> {
  try {
    const raw = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const value = JSON.parse(raw) as unknown;
    if (!plainObject(value)) throw new MismatchError();
    return value;
  } catch (error) {
    if (error instanceof MismatchError) throw error;
    throw new MismatchError();
  } finally {
    bytes.fill(0);
  }
}

function parseSafeDecimal(value: string): number {
  if (!DECIMAL.test(value)) throw new MismatchError();
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) throw new MismatchError();
  return parsed;
}

function plainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

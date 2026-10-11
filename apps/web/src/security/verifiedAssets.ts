/** A same-origin static file whose expected digest ships inside the verified bundle. */
export interface VerifiableAsset {
  readonly path: string;
  readonly sha256Hex: string;
  readonly size: number;
  readonly mimeType: string;
}

export interface VerifiedAssetLoaderDependencies {
  fetch: typeof globalThis.fetch;
  origin: string;
  createObjectUrl: (blob: Blob) => string;
  revokeObjectUrl: (url: string) => void;
}

export const MAX_VERIFIED_ASSET_BYTES = 8 * 1024 * 1024;
const LOWER_SHA256 = /^[0-9a-f]{64}$/u;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/u;

/**
 * Loads static assets that the startup audit defers, and releases them only after
 * their bytes match the digest compiled into the release-verified bundle. Each asset
 * is fetched at most once while it succeeds; a failure is forgotten so it can be retried.
 */
export class VerifiedAssetLoader {
  readonly #dependencies: VerifiedAssetLoaderDependencies;
  readonly #blobs = new Map<string, Promise<Blob>>();
  readonly #urls = new Map<string, Promise<string>>();
  readonly #issuedUrls = new Set<string>();

  constructor(dependencies: Partial<VerifiedAssetLoaderDependencies> = {}) {
    this.#dependencies = {
      fetch: dependencies.fetch ?? globalThis.fetch.bind(globalThis),
      origin: dependencies.origin ?? window.location.origin,
      createObjectUrl: dependencies.createObjectUrl ?? ((blob) => URL.createObjectURL(blob)),
      revokeObjectUrl: dependencies.revokeObjectUrl ?? ((url) => URL.revokeObjectURL(url)),
    };
  }

  /** Resolves with the verified bytes, or rejects without exposing unverified content. */
  load(asset: VerifiableAsset): Promise<Blob> {
    return this.#memoize(this.#blobs, asset.path, () => this.#fetchVerified(asset));
  }

  /** Resolves with a `blob:` URL over verified bytes, safe to use as an image source. */
  objectUrl(asset: VerifiableAsset): Promise<string> {
    return this.#memoize(this.#urls, asset.path, async () => {
      const url = this.#dependencies.createObjectUrl(await this.load(asset));
      this.#issuedUrls.add(url);
      return url;
    });
  }

  dispose(): void {
    this.#issuedUrls.forEach((url) => this.#dependencies.revokeObjectUrl(url));
    this.#issuedUrls.clear();
    this.#urls.clear();
    this.#blobs.clear();
  }

  #memoize<T>(cache: Map<string, Promise<T>>, key: string, create: () => Promise<T>): Promise<T> {
    const cached = cache.get(key);
    if (cached) return cached;
    const pending = create();
    cache.set(key, pending);
    pending.catch(() => {
      if (cache.get(key) === pending) cache.delete(key);
    });
    return pending;
  }

  async #fetchVerified(asset: VerifiableAsset): Promise<Blob> {
    if (!LOWER_SHA256.test(asset.sha256Hex) || !Number.isSafeInteger(asset.size) ||
      asset.size < 1 || asset.size > MAX_VERIFIED_ASSET_BYTES) {
      throw new Error("Asset is not verifiable");
    }
    const { origin } = this.#dependencies;
    const url = new URL(asset.path, origin);
    if (url.origin !== origin || url.pathname !== asset.path || url.search || url.hash) {
      throw new Error("Asset is not same-origin");
    }
    const response = await this.#dependencies.fetch(url.toString(), {
      method: "GET",
      credentials: "omit",
      referrerPolicy: "no-referrer",
      redirect: "error",
    });
    if (!response.ok) throw new Error("Asset unavailable");
    const declared = response.headers.get("Content-Length");
    if (declared !== null && (!DECIMAL.test(declared) || Number(declared) !== asset.size)) {
      throw new Error("Asset size mismatch");
    }
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.byteLength !== asset.size) throw new Error("Asset size mismatch");
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
    const actual = Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
    if (actual !== asset.sha256Hex) throw new Error("Asset digest mismatch");
    return new Blob([bytes], { type: asset.mimeType });
  }
}

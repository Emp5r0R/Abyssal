import initWasm from "../generated/abyssal_core/abyssal_core";

export interface SecurityRuntime {
  initialize(): Promise<void>;
}

export interface SecurityRuntimeOptions {
  timeoutMs?: number;
}

// Backstop for the whole initialization. The download itself fails sooner, as
// soon as it stops making progress, so slow links finish and dead ones do not hang.
const DEFAULT_RUNTIME_TIMEOUT_MS = 180_000;
const WASM_STALL_TIMEOUT_MS = 15_000;
const MAX_WASM_BYTES = 32 * 1024 * 1024;
const WASM_ASSET_URL = new URL(
  "../generated/abyssal_core/abyssal_core_bg.wasm",
  import.meta.url,
);

export function createSecurityRuntime(
  loader: (signal?: AbortSignal) => Promise<unknown>,
  options: SecurityRuntimeOptions = {},
): SecurityRuntime {
  const timeoutMs = options.timeoutMs ?? DEFAULT_RUNTIME_TIMEOUT_MS;
  let ready: Promise<void> | null = null;
  return {
    initialize(): Promise<void> {
      if (ready) return ready;
      const controller = new AbortController();
      const attempt = runWithDeadline(
        () => loader(controller.signal),
        controller,
        timeoutMs,
      ).then(
        () => undefined,
        (error: unknown) => {
          if (ready === attempt) ready = null;
          throw error;
        },
      );
      ready = attempt;
      return attempt;
    },
  };
}

function runWithDeadline(
  load: () => Promise<unknown>,
  controller: AbortController,
  timeoutMs: number,
): Promise<unknown> {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    return Promise.reject(new Error("Security runtime initialization timed out"));
  }
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      const error = new Error("Security runtime initialization timed out");
      error.name = "TimeoutError";
      reject(error);
    }, timeoutMs);
  });
  const operation = Promise.resolve().then(load);
  return Promise.race([operation, timeout]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
    controller.abort();
  });
}

export async function loadSecurityWasm(
  signal?: AbortSignal,
  fetcher: typeof fetch = (input, init) => globalThis.fetch(input, init),
): Promise<unknown> {
  const origin = window.location.origin;
  const url = new URL(WASM_ASSET_URL.pathname, origin);
  if (url.origin !== origin || url.search || url.hash) {
    throw new Error("Security runtime asset origin mismatch");
  }
  const request = new Request(url.toString(), {
    method: "GET",
    mode: "same-origin",
    cache: "no-store",
    credentials: "omit",
    referrerPolicy: "no-referrer",
    redirect: "error",
  });
  // Compile from downloaded bytes: streaming compilation throttles the download
  // on slow links, and the bytes let the stall timer see real progress.
  const bytes = await downloadWithStallTimeout(request, fetcher, signal);
  return initWasm({ module_or_path: bytes });
}

/**
 * Downloads `request`, aborting only when no bytes arrive for `stallMs`, so a slow
 * but working connection completes. The body is bounded by `maxBytes`.
 */
export async function downloadWithStallTimeout(
  request: Request,
  fetcher: typeof fetch,
  parent?: AbortSignal,
  stallMs = WASM_STALL_TIMEOUT_MS,
  maxBytes = MAX_WASM_BYTES,
): Promise<Uint8Array> {
  const controller = new AbortController();
  const abort = () => controller.abort();
  parent?.addEventListener("abort", abort, { once: true });
  if (parent?.aborted) abort();
  let timer = setTimeout(abort, stallMs);
  const progress = () => {
    clearTimeout(timer);
    timer = setTimeout(abort, stallMs);
  };
  try {
    const response = await fetcher(new Request(request, { signal: controller.signal }));
    if (!response.ok) throw new Error("Security runtime asset unavailable");
    progress();
    const reader = response.body?.getReader();
    if (!reader) {
      const buffer = new Uint8Array(await response.arrayBuffer());
      if (buffer.byteLength > maxBytes) throw new Error("Security runtime asset too large");
      return buffer;
    }
    const chunks: Uint8Array[] = [];
    let total = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      progress();
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined);
        throw new Error("Security runtime asset too large");
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return bytes;
  } finally {
    clearTimeout(timer);
    parent?.removeEventListener("abort", abort);
  }
}

const runtime = createSecurityRuntime(loadSecurityWasm);

export function initializeSecurityRuntime(): Promise<void> {
  return runtime.initialize();
}

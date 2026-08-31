import initWasm from "../generated/abyssal_core/abyssal_core";

export interface SecurityRuntime {
  initialize(): Promise<void>;
}

export interface SecurityRuntimeOptions {
  timeoutMs?: number;
}

const DEFAULT_RUNTIME_TIMEOUT_MS = 30_000;
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

export async function loadSecurityWasm(signal?: AbortSignal): Promise<unknown> {
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
    signal,
  });
  return initWasm({ module_or_path: request });
}

const runtime = createSecurityRuntime(loadSecurityWasm);

export function initializeSecurityRuntime(): Promise<void> {
  return runtime.initialize();
}

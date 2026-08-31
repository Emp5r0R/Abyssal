import { describe, expect, it, vi } from "vitest";
import { createSecurityRuntime } from "./runtime";

const { initWasm } = vi.hoisted(() => ({ initWasm: vi.fn() }));
vi.mock("../generated/abyssal_core/abyssal_core", () => ({ default: initWasm }));

interface WasmInitRequest {
  module_or_path: Request;
}

describe("security runtime", () => {
  it("shares one in-flight initialization across callers", async () => {
    const loader = vi.fn(async () => ({ initialized: true }));
    const runtime = createSecurityRuntime(loader);

    await Promise.all([runtime.initialize(), runtime.initialize(), runtime.initialize()]);

    expect(loader).toHaveBeenCalledTimes(1);
  });

  it("allows an explicit retry after initialization fails closed", async () => {
    const loader = vi.fn<() => Promise<unknown>>()
      .mockRejectedValueOnce(new Error("unavailable"))
      .mockResolvedValueOnce({ initialized: true });
    const runtime = createSecurityRuntime(loader);

    await expect(runtime.initialize()).rejects.toThrow("unavailable");
    await expect(runtime.initialize()).resolves.toBeUndefined();
    expect(loader).toHaveBeenCalledTimes(2);
  });

  it("aborts a stalled load and starts a fresh retry", async () => {
    vi.useFakeTimers();
    try {
      const signals: AbortSignal[] = [];
      const loader = vi.fn((signal?: AbortSignal) => {
        signals.push(signal ?? new AbortController().signal);
        return new Promise<unknown>(() => undefined);
      });
      const runtime = createSecurityRuntime(loader, { timeoutMs: 10 });

      const first = runtime.initialize();
      const firstFailure = expect(first).rejects.toThrow("timed out");
      await vi.advanceTimersByTimeAsync(10);
      await firstFailure;
      expect(signals[0].aborted).toBe(true);

      const second = runtime.initialize();
      await Promise.resolve();
      expect(loader).toHaveBeenCalledTimes(2);
      const secondFailure = expect(second).rejects.toThrow("timed out");
      await vi.advanceTimersByTimeAsync(10);
      await secondFailure;
      expect(signals[1].aborted).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("aborts the production WASM fetch and retries it with a fresh signal", async () => {
    vi.useFakeTimers();
    initWasm.mockReset();
    const fetchAborted = vi.fn();
    const fetcher = vi.fn<typeof fetch>((input) => new Promise<Response>((_, reject) => {
      expect(input).toBeInstanceOf(Request);
      const signal = (input as Request).signal;
      if (signal?.aborted) {
        fetchAborted();
        reject(new DOMException("The operation was aborted", "AbortError"));
        return;
      }
      signal?.addEventListener("abort", () => {
        fetchAborted();
        reject(new DOMException("The operation was aborted", "AbortError"));
      }, { once: true });
    }));
    initWasm.mockImplementation(({ module_or_path }: WasmInitRequest) => fetch(module_or_path));
    vi.stubGlobal("fetch", fetcher);
    try {
      const { initializeSecurityRuntime } = await import("./runtime");
      const first = initializeSecurityRuntime();
      const firstFailure = expect(first).rejects.toThrow("timed out");
      await vi.advanceTimersByTimeAsync(30_000);
      await firstFailure;
      expect(fetcher).toHaveBeenCalledTimes(1);
      expect(fetchAborted).toHaveBeenCalledTimes(1);
      const firstRequest = fetcher.mock.calls[0]?.[0] as Request | undefined;
      const firstSignal = firstRequest?.signal;
      expect(firstSignal).toBeInstanceOf(AbortSignal);
      expect(firstSignal?.aborted).toBe(true);

      const second = initializeSecurityRuntime();
      const secondFailure = expect(second).rejects.toThrow("timed out");
      await vi.advanceTimersByTimeAsync(30_000);
      await secondFailure;
      expect(fetcher).toHaveBeenCalledTimes(2);
      expect((fetcher.mock.calls[1]?.[0] as Request | undefined)?.signal).not.toBe(firstSignal);
      expect(fetchAborted).toHaveBeenCalledTimes(2);
    } finally {
      vi.unstubAllGlobals();
      vi.useRealTimers();
    }
  });

  it("passes a same-origin no-store Request to the generated initializer", async () => {
    initWasm.mockReset();
    initWasm.mockResolvedValue({ initialized: true });
    try {
      const { loadSecurityWasm } = await import("./runtime");
      const signal = new AbortController().signal;

      await expect(loadSecurityWasm(signal)).resolves.toEqual({ initialized: true });

      expect(initWasm).toHaveBeenCalledTimes(1);
      const input = initWasm.mock.calls[0]?.[0] as WasmInitRequest | undefined;
      const request = input?.module_or_path;
      expect(request).toBeInstanceOf(Request);
      expect(new URL(request?.url ?? "").origin).toBe(window.location.origin);
      expect(request).toEqual(expect.objectContaining({
        method: "GET",
        mode: "same-origin",
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
      }));
      expect(request?.signal.aborted).toBe(false);
    } finally {
      initWasm.mockReset();
    }
  });
});

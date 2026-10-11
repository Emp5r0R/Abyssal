import { describe, expect, it, vi } from "vitest";
import { createSecurityRuntime } from "./runtime";

const { initWasm } = vi.hoisted(() => ({ initWasm: vi.fn() }));
vi.mock("../generated/abyssal_core/abyssal_core", () => ({ default: initWasm }));

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

  it("abandons a WASM download that stops making progress, and retries with a fresh signal", async () => {
    vi.useFakeTimers();
    initWasm.mockReset();
    const requests: Request[] = [];
    const fetcher = vi.fn<typeof fetch>((input) => new Promise<Response>((_, reject) => {
      const request = input as Request;
      requests.push(request);
      request.signal.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")), { once: true });
    }));
    try {
      const { loadSecurityWasm } = await import("./runtime");
      const first = loadSecurityWasm(undefined, fetcher);
      const firstFailure = expect(first).rejects.toThrow();
      await vi.advanceTimersByTimeAsync(14_999);
      expect(requests[0].signal.aborted).toBe(false);
      await vi.advanceTimersByTimeAsync(1);
      await firstFailure;
      expect(requests[0].signal.aborted).toBe(true);

      const second = loadSecurityWasm(undefined, fetcher);
      const secondFailure = expect(second).rejects.toThrow();
      await vi.advanceTimersByTimeAsync(15_000);
      await secondFailure;
      expect(requests[1].signal).not.toBe(requests[0].signal);
      expect(initWasm).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it("finishes a slow download that keeps making progress, then compiles the bytes", async () => {
    vi.useFakeTimers();
    initWasm.mockReset();
    initWasm.mockResolvedValue({ initialized: true });
    const body = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]);
    let sent = 0;
    const fetcher = vi.fn<typeof fetch>(async () => new Response(new ReadableStream<Uint8Array>({
      async pull(controller) {
        await new Promise((resolve) => setTimeout(resolve, 10_000));
        if (sent >= body.length) { controller.close(); return; }
        controller.enqueue(body.slice(sent, sent + 2));
        sent += 2;
      },
    })));
    try {
      const { loadSecurityWasm } = await import("./runtime");
      const loaded = loadSecurityWasm(undefined, fetcher);
      await vi.advanceTimersByTimeAsync(60_000);
      await expect(loaded).resolves.toEqual({ initialized: true });
      const input = initWasm.mock.calls[0]?.[0] as { module_or_path: Uint8Array };
      expect(Array.from(input.module_or_path)).toEqual(Array.from(body));
    } finally {
      vi.useRealTimers();
      initWasm.mockReset();
    }
  });

  it("requests the WASM same-origin, no-store, and stops at the size bound", async () => {
    initWasm.mockReset();
    initWasm.mockResolvedValue({ initialized: true });
    const fetcher = vi.fn<typeof fetch>(async () => new Response(new Uint8Array([0, 97, 115, 109])));
    const { downloadWithStallTimeout, loadSecurityWasm } = await import("./runtime");
    await expect(loadSecurityWasm(new AbortController().signal, fetcher)).resolves.toEqual({ initialized: true });
    const request = fetcher.mock.calls[0]?.[0] as Request;
    expect(new URL(request.url).origin).toBe(window.location.origin);
    expect(request).toEqual(expect.objectContaining({
      method: "GET",
      mode: "same-origin",
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
    }));

    const oversized = vi.fn<typeof fetch>(async () => new Response(new Uint8Array(10)));
    await expect(downloadWithStallTimeout(new Request(window.location.origin), oversized, undefined, 1_000, 4))
      .rejects.toThrow("too large");
    const missing = vi.fn<typeof fetch>(async () => new Response("", { status: 404 }));
    await expect(downloadWithStallTimeout(new Request(window.location.origin), missing)).rejects.toThrow("unavailable");
    initWasm.mockReset();
  });
});

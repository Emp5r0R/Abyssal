import { describe, expect, it, vi } from "vitest";
import { createSecurityRuntime } from "./runtime";

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
});

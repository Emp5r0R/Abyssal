import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { startQrCamera } from "./qrCamera";

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}
function fixture() {
  const track = Object.assign(new EventTarget(), { stop: vi.fn() });
  const stream = { getTracks: () => [track] } as unknown as MediaStream;
  const video = document.createElement("video");
  const onState = vi.fn();
  const onValue = vi.fn(async () => true);
  const readFrame = vi.fn(() => "abyssal:invite:fixture");
  return { track, stream, video, onState, onValue, readFrame };
}

describe("bounded offline QR camera lifetime", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.spyOn(HTMLMediaElement.prototype, "play").mockResolvedValue();
    vi.spyOn(HTMLMediaElement.prototype, "pause").mockImplementation(() => undefined);
  });
  afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });

  it("stops tracks and clears video exactly once after acceptance", async () => {
    const f = fixture();
    const dispose = startQrCamera({ ...f, requestStream: async () => f.stream });
    await vi.advanceTimersByTimeAsync(300);
    expect(f.onValue).toHaveBeenCalledOnce();
    expect(f.track.stop).toHaveBeenCalledOnce();
    expect(f.video.srcObject).toBeNull();
    dispose();
    expect(f.track.stop).toHaveBeenCalledOnce();
  });

  it.each(["dispose", "pagehide", "deadline"])("releases a late permission result after %s", async (kind) => {
    const f = fixture();
    const pending = deferred<MediaStream>();
    const dispose = startQrCamera({ ...f, requestStream: () => pending.promise });
    if (kind === "dispose") dispose();
    if (kind === "pagehide") window.dispatchEvent(new Event("pagehide"));
    if (kind === "deadline") await vi.advanceTimersByTimeAsync(60_001);
    pending.resolve(f.stream);
    await vi.advanceTimersByTimeAsync(300);
    expect(f.track.stop).toHaveBeenCalledOnce();
    expect(f.onValue).not.toHaveBeenCalled();
    dispose();
  });

  it("does not restart or publish when verification finishes after cancellation", async () => {
    const f = fixture();
    const verified = deferred<boolean>();
    let signal: AbortSignal | undefined;
    const onValue = vi.fn((_value: string, cancellation: AbortSignal) => {
      signal = cancellation;
      return verified.promise;
    });
    const dispose = startQrCamera({ ...f, onValue, requestStream: async () => f.stream });
    await vi.advanceTimersByTimeAsync(300);
    dispose();
    expect(signal?.aborted).toBe(true);
    verified.resolve(true);
    await vi.advanceTimersByTimeAsync(1000);
    expect(onValue).toHaveBeenCalledOnce();
    expect(f.track.stop).toHaveBeenCalledOnce();
  });

  it("rejects permission and play failures without leaking tracks", async () => {
    const f = fixture();
    const dispose = startQrCamera({ ...f, requestStream: async () => { throw new Error("denied"); } });
    await vi.advanceTimersByTimeAsync(1);
    expect(f.onState).toHaveBeenLastCalledWith("unavailable");
    dispose();
    vi.mocked(HTMLMediaElement.prototype.play).mockRejectedValue(new Error("failed"));
    startQrCamera({ ...f, requestStream: async () => f.stream });
    await vi.advanceTimersByTimeAsync(1);
    expect(f.track.stop).toHaveBeenCalledOnce();
  });

  it("bounds invalid QR retries and handles ended tracks", async () => {
    const f = fixture();
    f.onValue.mockResolvedValue(false);
    startQrCamera({ ...f, requestStream: async () => f.stream });
    await vi.advanceTimersByTimeAsync(1000);
    expect(f.onValue).toHaveBeenCalledTimes(4);
    expect(f.onState).toHaveBeenLastCalledWith("invalid");
    f.track.dispatchEvent(new Event("ended"));
    await vi.advanceTimersByTimeAsync(1000);
    expect(f.onValue).toHaveBeenCalledTimes(4);
    expect(f.track.stop).toHaveBeenCalledOnce();
  });

  it("bounds a stalled play operation and never emits oversized text", async () => {
    const f = fixture();
    vi.mocked(HTMLMediaElement.prototype.play).mockReturnValue(new Promise(() => undefined));
    startQrCamera({ ...f, requestStream: async () => f.stream });
    await vi.advanceTimersByTimeAsync(60_001);
    expect(f.track.stop).toHaveBeenCalledOnce();
    expect(f.onValue).not.toHaveBeenCalled();
    vi.mocked(HTMLMediaElement.prototype.play).mockResolvedValue();
    f.readFrame.mockReturnValue("x".repeat(2049));
    const dispose = startQrCamera({ ...f, requestStream: async () => f.stream });
    await vi.advanceTimersByTimeAsync(1000);
    expect(f.onValue).not.toHaveBeenCalled();
    dispose();
  });
});

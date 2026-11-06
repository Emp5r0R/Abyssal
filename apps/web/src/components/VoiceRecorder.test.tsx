import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { VoiceRecorder } from "./VoiceRecorder";

class FakeRecorder {
  static isTypeSupported = (type: string) => type === "audio/webm;codecs=opus";
  state: "inactive" | "recording" = "inactive";
  mimeType: string;
  ondataavailable: ((event: { data: Blob }) => void) | null = null;
  onstop: (() => void) | null = null;
  constructor(_stream: MediaStream, options?: { mimeType?: string }) { this.mimeType = options?.mimeType ?? ""; }
  start() { this.state = "recording"; }
  stop() {
    this.state = "inactive";
    this.ondataavailable?.({ data: new Blob([new Uint8Array([1, 2, 3])]) });
    this.onstop?.();
  }
}

const track = { stop: vi.fn() };
let clock = 1_000;

beforeEach(() => {
  clock = 1_000;
  vi.spyOn(Date, "now").mockImplementation(() => clock);
  vi.stubGlobal("MediaRecorder", FakeRecorder);
  Object.defineProperty(navigator, "mediaDevices", {
    configurable: true,
    value: { getUserMedia: vi.fn(async () => ({ getTracks: () => [track] })) },
  });
  track.stop.mockClear();
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("voice recorder", () => {
  it("records in memory, sends a named audio file with its length, and releases the microphone", async () => {
    const onSend = vi.fn().mockResolvedValue(true);
    const onRecordingChange = vi.fn();
    render(<VoiceRecorder disabled={false} onSend={onSend} onRecordingChange={onRecordingChange} />);
    fireEvent.click(screen.getByRole("button", { name: "Record voice message" }));
    expect(await screen.findByRole("group", { name: "Recording voice message" })).toBeInTheDocument();
    expect(onRecordingChange).toHaveBeenLastCalledWith(true);

    clock += 4_200;
    await act(async () => { fireEvent.click(screen.getByRole("button", { name: "Send voice message" })); });
    await waitFor(() => expect(onSend).toHaveBeenCalledOnce());
    const [file, durationMs] = onSend.mock.calls[0] as [File, number];
    expect(file.name).toBe("Voice message.webm");
    expect(file.type).toBe("audio/webm");
    expect(durationMs).toBe(4_200);
    expect(track.stop).toHaveBeenCalled();
    expect(onRecordingChange).toHaveBeenLastCalledWith(false);
  });

  it("discards a recording without sending it", async () => {
    const onSend = vi.fn().mockResolvedValue(true);
    render(<VoiceRecorder disabled={false} onSend={onSend} />);
    fireEvent.click(screen.getByRole("button", { name: "Record voice message" }));
    await screen.findByRole("group", { name: "Recording voice message" });
    clock += 3_000;
    await act(async () => { fireEvent.click(screen.getByRole("button", { name: "Discard recording" })); });
    expect(onSend).not.toHaveBeenCalled();
    expect(track.stop).toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "Record voice message" })).toBeInTheDocument();
  });

  it("explains when the microphone is unavailable", async () => {
    Object.defineProperty(navigator, "mediaDevices", {
      configurable: true,
      value: { getUserMedia: vi.fn(async () => { throw new Error("denied"); }) },
    });
    render(<VoiceRecorder disabled={false} onSend={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: "Record voice message" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Microphone unavailable");
  });
});

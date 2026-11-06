import { describe, expect, it } from "vitest";
import { MAX_VOICE_DURATION_MS, formatVoiceDuration, isAudioMime, readVoiceDuration, voiceFileName } from "./voiceNotes";

describe("voice notes", () => {
  it("reads the voice flag only from audio FILE attachments and clamps the duration", () => {
    expect(readVoiceDuration({ voice: true, duration_ms: 7_400 }, "FILE", "audio/webm;codecs=opus")).toBe(7_400);
    expect(readVoiceDuration({ voice: true, duration_ms: 1e9 }, "FILE", "audio/wav")).toBe(MAX_VOICE_DURATION_MS);
    expect(readVoiceDuration({ voice: true, duration_ms: "x" }, "FILE", "audio/ogg")).toBe(0);
    expect(readVoiceDuration({ voice: true }, "IMAGE", "audio/ogg")).toBeUndefined();
    expect(readVoiceDuration({ voice: true }, "FILE", "application/pdf")).toBeUndefined();
    expect(readVoiceDuration({}, "FILE", "audio/ogg")).toBeUndefined();
  });

  it("names and formats recordings", () => {
    expect(isAudioMime("audio/webm;codecs=opus")).toBe(true);
    expect(isAudioMime("video/webm")).toBe(false);
    expect(voiceFileName("audio/webm;codecs=opus")).toBe("Voice message.webm");
    expect(voiceFileName("audio/mp4")).toBe("Voice message.m4a");
    expect(voiceFileName("audio/wav")).toBe("Voice message.wav");
    expect(formatVoiceDuration(7_400)).toBe("0:07");
    expect(formatVoiceDuration(105_000)).toBe("1:45");
  });
});

/**
 * Voice messages are ordinary encrypted FILE attachments with an audio MIME
 * type, plus `voice: true` and `duration_ms` in the encrypted metadata. Older
 * clients show them as a file that can be saved and played.
 */

/** Longest recording, so a voice message stays a few megabytes. */
export const MAX_VOICE_DURATION_MS = 120_000;

/** Recorder formats to try, best first; the browser picks the first it supports. */
export const VOICE_MIME_CANDIDATES = ["audio/webm;codecs=opus", "audio/ogg;codecs=opus", "audio/mp4", "audio/webm"] as const;

export function isAudioMime(mimeType: string): boolean {
  return /^audio\/[a-z0-9.+-]+(?:;.*)?$/iu.test(mimeType);
}

/** The duration to show for a voice message, or undefined when the payload is not one. */
export function readVoiceDuration(payload: Record<string, unknown>, mediaType: string, mimeType: string): number | undefined {
  if (payload.voice !== true || mediaType !== "FILE" || !isAudioMime(mimeType)) return undefined;
  const value = payload.duration_ms;
  if (typeof value !== "number" || !Number.isFinite(value)) return 0;
  return Math.min(MAX_VOICE_DURATION_MS, Math.max(0, Math.round(value)));
}

/** File name for a recording, by container. */
export function voiceFileName(mimeType: string): string {
  const base = mimeType.split(";")[0].toLowerCase();
  const extension = base === "audio/ogg" ? "ogg" : base === "audio/mp4" ? "m4a" : base === "audio/wav" ? "wav" : "webm";
  return `Voice message.${extension}`;
}

/** "0:07", "1:45". */
export function formatVoiceDuration(durationMs: number): string {
  const seconds = Math.max(0, Math.round(durationMs / 1000));
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
}

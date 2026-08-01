import type { ChatMessage, MediaType, RoomRecord } from "./types";

export const MEDIA_LIMIT_BYTES: Record<MediaType, number> = {
  IMAGE: 20 * 1024 * 1024,
  VIDEO: 100 * 1024 * 1024,
  FILE: 200 * 1024 * 1024,
};

export function classifyMedia(file: File): MediaType {
  if (file.type.startsWith("image/")) return "IMAGE";
  if (file.type.startsWith("video/")) return "VIDEO";
  return "FILE";
}

export function mediaAllowed(room: RoomRecord | undefined, mediaType: MediaType): boolean {
  if (!room) return false;
  if (mediaType === "IMAGE") return room.allow_images;
  if (mediaType === "VIDEO") return room.allow_videos;
  return room.allow_files;
}

export function readRetention(room: RoomRecord | undefined, mediaType?: MediaType): number {
  if (!room) return 5;
  if (mediaType === "IMAGE") return room.image_read_timer_sec;
  if (mediaType === "VIDEO") return room.video_read_timer_sec;
  if (mediaType === "FILE") return room.file_read_timer_sec;
  return room.self_destruct_timer_sec;
}

export function absoluteRetention(room: RoomRecord | undefined, mediaType?: MediaType): number {
  if (!room) return 0;
  // A room-wide absolute lifetime is the safe default for every payload.  Media
  // rules can opt into a shorter, media-specific lifetime, but must never make
  // an attachment outlive the room's enabled absolute policy.
  const roomAbsolute = room.enforce_text_absolute_expiry ? room.overall_expiry_sec : 0;
  if (mediaType === "IMAGE") {
    return shortestRetention(roomAbsolute, room.enforce_image_absolute_expiry ? room.image_overall_expiry_sec : 0);
  }
  if (mediaType === "VIDEO") {
    return shortestRetention(roomAbsolute, room.enforce_video_absolute_expiry ? room.video_overall_expiry_sec : 0);
  }
  if (mediaType === "FILE") {
    return shortestRetention(roomAbsolute, room.enforce_file_absolute_expiry ? room.file_overall_expiry_sec : 0);
  }
  return roomAbsolute;
}

function shortestRetention(...retentions: number[]): number {
  const enabled = retentions.filter((retention) => retention > 0);
  return enabled.length ? Math.min(...enabled) : 0;
}

export function isExpired(message: ChatMessage, nowMs: number): boolean {
  const absoluteExpired =
    message.absoluteExpirySec > 0 && nowMs >= message.createdAtMs + message.absoluteExpirySec * 1000;
  const readExpired =
    message.selfDestructSec > 0 &&
    message.readAtMs !== undefined &&
    nowMs >= message.readAtMs + message.selfDestructSec * 1000;
  return absoluteExpired || readExpired;
}

export function remainingSeconds(message: ChatMessage, nowMs: number): number | null {
  const deadlines: number[] = [];
  if (message.absoluteExpirySec > 0) deadlines.push(message.createdAtMs + message.absoluteExpirySec * 1000);
  if (message.selfDestructSec > 0 && message.readAtMs !== undefined) {
    deadlines.push(message.readAtMs + message.selfDestructSec * 1000);
  }
  if (!deadlines.length) return null;
  return Math.max(0, Math.ceil((Math.min(...deadlines) - nowMs) / 1000));
}

export function clampRoom(room: RoomRecord): RoomRecord {
  const clamp = (value: number, min: number, max: number) => {
    const finite = Number.isFinite(value) ? value : min;
    return Math.min(max, Math.max(min, Math.floor(finite)));
  };
  return {
    ...room,
    name: room.name.trim().slice(0, 36),
    self_destruct_timer_sec: clamp(room.self_destruct_timer_sec, 0, 86_400),
    overall_expiry_sec: clamp(room.overall_expiry_sec, 0, 86_400),
    image_read_timer_sec: clamp(room.image_read_timer_sec, 0, 86_400),
    image_overall_expiry_sec: clamp(room.image_overall_expiry_sec, 0, 86_400),
    video_read_timer_sec: clamp(room.video_read_timer_sec, 0, 86_400),
    video_overall_expiry_sec: clamp(room.video_overall_expiry_sec, 0, 86_400),
    file_read_timer_sec: clamp(room.file_read_timer_sec, 0, 86_400),
    file_overall_expiry_sec: clamp(room.file_overall_expiry_sec, 0, 86_400),
  };
}

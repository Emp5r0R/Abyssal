import { describe, expect, it } from "vitest";
import { absoluteRetention, isExpired, mediaAllowed, readRetention } from "./messagePolicy";
import type { ChatMessage, RoomRecord } from "./types";

const room: RoomRecord = {
  id: "forum_test",
  name: "Test",
  self_destruct_timer_sec: 5,
  overall_expiry_sec: 60,
  allow_images: true,
  allow_videos: false,
  allow_files: true,
  enforce_text_absolute_expiry: true,
  image_read_timer_sec: 7,
  image_overall_expiry_sec: 70,
  enforce_image_absolute_expiry: false,
  video_read_timer_sec: 8,
  video_overall_expiry_sec: 80,
  enforce_video_absolute_expiry: true,
  file_read_timer_sec: 9,
  file_overall_expiry_sec: 90,
  enforce_file_absolute_expiry: true,
};

describe("room message policy", () => {
  it("uses room policy instead of sender choices", () => {
    expect(readRetention(room)).toBe(5);
    expect(readRetention(room, "IMAGE")).toBe(7);
    expect(absoluteRetention(room)).toBe(60);
    expect(absoluteRetention(room, "IMAGE")).toBe(0);
    expect(absoluteRetention(room, "FILE")).toBe(90);
  });

  it("enforces media allow-list", () => {
    expect(mediaAllowed(room, "IMAGE")).toBe(true);
    expect(mediaAllowed(room, "VIDEO")).toBe(false);
  });

  it("expires on earliest absolute or read deadline", () => {
    const message: ChatMessage = {
      id: "message",
      chatId: room.id,
      sender: "User",
      content: "text",
      kind: "text",
      createdAtMs: 1_000,
      receivedAtMs: 1_000,
      readAtMs: 2_000,
      selfDestructSec: 5,
      absoluteExpirySec: 60,
      mine: false,
    };
    expect(isExpired(message, 6_999)).toBe(false);
    expect(isExpired(message, 7_000)).toBe(true);
  });
});

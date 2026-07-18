import { describe, expect, it } from "vitest";
import { absoluteRetention, clampRoom, isExpired, mediaAllowed, readRetention, remainingSeconds } from "./messagePolicy";
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
    expect(absoluteRetention(room, "IMAGE")).toBe(60);
    expect(absoluteRetention(room, "FILE")).toBe(60);
  });

  it("uses the shortest enabled absolute lifetime for an attachment", () => {
    const mediaLimitedRoom = { ...room, file_overall_expiry_sec: 30 };
    expect(absoluteRetention(mediaLimitedRoom, "FILE")).toBe(30);
  });

  it("still enforces a media lifetime when the room-wide timer is disabled", () => {
    const mediaOnlyRoom = {
      ...room,
      enforce_text_absolute_expiry: false,
      enforce_image_absolute_expiry: true,
      image_overall_expiry_sec: 25,
    };
    expect(absoluteRetention(mediaOnlyRoom)).toBe(0);
    expect(absoluteRetention(mediaOnlyRoom, "IMAGE")).toBe(25);
    expect(absoluteRetention(mediaOnlyRoom, "VIDEO")).toBe(80);
  });

  it("does not invent an absolute lifetime when every relevant timer is disabled", () => {
    const noAbsoluteRoom = {
      ...room,
      enforce_text_absolute_expiry: false,
      enforce_image_absolute_expiry: false,
      enforce_video_absolute_expiry: false,
      enforce_file_absolute_expiry: false,
    };
    expect(absoluteRetention(noAbsoluteRoom, "IMAGE")).toBe(0);
    expect(absoluteRetention(noAbsoluteRoom, "VIDEO")).toBe(0);
    expect(absoluteRetention(noAbsoluteRoom, "FILE")).toBe(0);
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
    expect(remainingSeconds(message, 6_001)).toBe(1);
  });

  it("uses the absolute deadline before a message has been read", () => {
    const message: ChatMessage = {
      id: "absolute-message",
      chatId: room.id,
      sender: "User",
      content: "attachment",
      kind: "attachment",
      createdAtMs: 1_000,
      receivedAtMs: 1_000,
      selfDestructSec: 30,
      absoluteExpirySec: 5,
      mine: false,
    };
    expect(remainingSeconds(message, 5_000)).toBe(1);
    expect(isExpired(message, 6_000)).toBe(true);
  });

  it("clamps malformed room timers to safe policy bounds", () => {
    const clamped = clampRoom({
      ...room,
      name: "x".repeat(50),
      self_destruct_timer_sec: -1,
      overall_expiry_sec: 99_999,
      image_read_timer_sec: 0,
      file_overall_expiry_sec: -4,
    });
    expect(clamped.name).toHaveLength(36);
    expect(clamped.self_destruct_timer_sec).toBe(1);
    expect(clamped.overall_expiry_sec).toBe(86_400);
    expect(clamped.image_read_timer_sec).toBe(1);
    expect(clamped.file_overall_expiry_sec).toBe(0);
  });
});

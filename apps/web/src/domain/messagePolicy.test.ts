import { describe, expect, it } from "vitest";
import { absoluteRetention, classifyMedia, clampRoom, isExpired, mediaAllowed, readRetention, remainingSeconds } from "./messagePolicy";
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

  it("returns safe defaults for undefined room", () => {
    expect(readRetention(undefined)).toBe(5);
    expect(readRetention(undefined, "IMAGE")).toBe(5);
    expect(readRetention(undefined, "VIDEO")).toBe(5);
    expect(readRetention(undefined, "FILE")).toBe(5);
    expect(absoluteRetention(undefined)).toBe(0);
    expect(absoluteRetention(undefined, "IMAGE")).toBe(0);
    expect(absoluteRetention(undefined, "VIDEO")).toBe(0);
    expect(absoluteRetention(undefined, "FILE")).toBe(0);
    expect(mediaAllowed(undefined, "IMAGE")).toBe(false);
    expect(mediaAllowed(undefined, "VIDEO")).toBe(false);
    expect(mediaAllowed(undefined, "FILE")).toBe(false);
  });

  it("readRetention returns correct values for FILE type", () => {
    expect(readRetention(room, "FILE")).toBe(9);
  });

  it("absoluteRetention returns correct value for VIDEO when media-only", () => {
    const mediaOnlyRoom = {
      ...room,
      enforce_text_absolute_expiry: false,
      enforce_video_absolute_expiry: true,
      video_overall_expiry_sec: 15,
    };
    expect(absoluteRetention(mediaOnlyRoom, "VIDEO")).toBe(15);
  });

  it("isExpired returns false when no deadlines are set", () => {
    const noDeadline: ChatMessage = {
      id: "no-deadline",
      chatId: "chat",
      sender: "User",
      content: "hi",
      kind: "text",
      createdAtMs: 1_000,
      receivedAtMs: 1_000,
      selfDestructSec: 0,
      absoluteExpirySec: 0,
      mine: false,
    };
    expect(isExpired(noDeadline, 999_999)).toBe(false);
  });

  it("isExpired returns false when absoluteExpirySec is zero and readAtMs is undefined", () => {
    const message: ChatMessage = {
      id: "never-expires",
      chatId: "chat",
      sender: "User",
      content: "hi",
      kind: "text",
      createdAtMs: 1_000,
      receivedAtMs: 1_000,
      selfDestructSec: 5,
      absoluteExpirySec: 0,
      mine: false,
    };
    expect(isExpired(message, 999_999_000)).toBe(false);
  });

  it("isExpired checks read deadline when absoluteExpirySec is zero", () => {
    const message: ChatMessage = {
      id: "read-only",
      chatId: "chat",
      sender: "User",
      content: "hi",
      kind: "text",
      createdAtMs: 1_000,
      receivedAtMs: 1_000,
      readAtMs: 2_000,
      selfDestructSec: 5,
      absoluteExpirySec: 0,
      mine: false,
    };
    expect(isExpired(message, 6_999)).toBe(false);
    expect(isExpired(message, 7_000)).toBe(true);
  });

  it("remainingSeconds returns null when no deadlines exist", () => {
    const message: ChatMessage = {
      id: "no-deadline",
      chatId: "chat",
      sender: "User",
      content: "hi",
      kind: "text",
      createdAtMs: 1_000,
      receivedAtMs: 1_000,
      selfDestructSec: 0,
      absoluteExpirySec: 0,
      mine: false,
    };
    expect(remainingSeconds(message, 5_000)).toBeNull();
  });

  it("remainingSeconds returns 0 after expiry", () => {
    const message: ChatMessage = {
      id: "expired",
      chatId: "chat",
      sender: "User",
      content: "hi",
      kind: "text",
      createdAtMs: 1_000,
      receivedAtMs: 1_000,
      selfDestructSec: 5,
      absoluteExpirySec: 10,
      mine: false,
    };
    expect(remainingSeconds(message, 12_000)).toBe(0);
  });

  it("clampRoom floors floating point values", () => {
    const clamped = clampRoom({
      ...room,
      name: "  trimmed  ",
      self_destruct_timer_sec: 1.9,
      overall_expiry_sec: 59.4,
      image_read_timer_sec: 2.7,
      image_overall_expiry_sec: 0.3,
      video_read_timer_sec: 3.1,
      video_overall_expiry_sec: 80.9,
      file_read_timer_sec: 0.9,
      file_overall_expiry_sec: 10.1,
    });
    expect(clamped.name).toBe("trimmed");
    expect(clamped.self_destruct_timer_sec).toBe(1);
    expect(clamped.overall_expiry_sec).toBe(59);
    expect(clamped.image_read_timer_sec).toBe(2);
    expect(clamped.image_overall_expiry_sec).toBe(0);
    expect(clamped.video_read_timer_sec).toBe(3);
    expect(clamped.video_overall_expiry_sec).toBe(80);
    expect(clamped.file_read_timer_sec).toBe(1);
    expect(clamped.file_overall_expiry_sec).toBe(10);
  });

  it("clampRoom converts non-finite timer values to safe minima", () => {
    const clamped = clampRoom({
      ...room,
      self_destruct_timer_sec: NaN,
      overall_expiry_sec: NaN,
    });
    expect(clamped.self_destruct_timer_sec).toBe(1);
    expect(clamped.overall_expiry_sec).toBe(0);
  });

  it("classifyMedia returns correct types", () => {
    expect(classifyMedia(new File([], "a.jpg", { type: "image/jpeg" }))).toBe("IMAGE");
    expect(classifyMedia(new File([], "a.mp4", { type: "video/mp4" }))).toBe("VIDEO");
    expect(classifyMedia(new File([], "a.pdf", { type: "application/pdf" }))).toBe("FILE");
    expect(classifyMedia(new File([], "a.txt", { type: "text/plain" }))).toBe("FILE");
    expect(classifyMedia(new File([], "a.gif", { type: "image/gif" }))).toBe("IMAGE");
    expect(classifyMedia(new File([], "a.webm", { type: "video/webm" }))).toBe("VIDEO");
  });

  it("shortestRetention returns 0 when all retentions are 0", () => {
    const emptyRoom: RoomRecord = {
      ...room,
      enforce_text_absolute_expiry: false,
      enforce_image_absolute_expiry: false,
      overall_expiry_sec: 0,
      image_overall_expiry_sec: 0,
    };
    expect(absoluteRetention(emptyRoom)).toBe(0);
    expect(absoluteRetention(emptyRoom, "IMAGE")).toBe(0);
  });
});

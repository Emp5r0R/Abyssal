import { describe, expect, it } from "vitest";
import { withTextReadTimer } from "./roomTimers";
import type { RoomRecord } from "./types";

const room = {
  id: "r", name: "R", self_destruct_timer_sec: 10, overall_expiry_sec: 0, allow_images: true, allow_videos: true,
  allow_files: true, enforce_text_absolute_expiry: false, image_read_timer_sec: 10, image_overall_expiry_sec: 0,
  enforce_image_absolute_expiry: false, video_read_timer_sec: 30, video_overall_expiry_sec: 0,
  enforce_video_absolute_expiry: false, file_read_timer_sec: 10, file_overall_expiry_sec: 0, enforce_file_absolute_expiry: false,
} satisfies RoomRecord;

describe("room timers", () => {
  it("moves media timers that matched the text timer and keeps customised ones", () => {
    const next = withTextReadTimer(room, 0);
    expect(next).toMatchObject({ self_destruct_timer_sec: 0, image_read_timer_sec: 0, file_read_timer_sec: 0, video_read_timer_sec: 30 });
  });
});

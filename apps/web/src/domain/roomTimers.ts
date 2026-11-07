import type { RoomRecord } from "./types";

/**
 * Sets the room's text after-reading timer. Image, video and file timers that
 * still match the old value follow it, so choosing "never" keeps media too; a
 * media timer changed separately keeps its own value.
 */
export function withTextReadTimer(room: RoomRecord, seconds: number): RoomRecord {
  const previous = room.self_destruct_timer_sec;
  const follow = (value: number) => (value === previous ? seconds : value);
  return {
    ...room,
    self_destruct_timer_sec: seconds,
    image_read_timer_sec: follow(room.image_read_timer_sec),
    video_read_timer_sec: follow(room.video_read_timer_sec),
    file_read_timer_sec: follow(room.file_read_timer_sec),
  };
}

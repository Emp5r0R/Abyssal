import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { RoomRecord } from "../domain/types";
import { AttachmentDialog } from "./AttachmentDialog";

const room: RoomRecord = {
  id: "forum_private",
  name: "Private",
  self_destruct_timer_sec: 0,
  overall_expiry_sec: 0,
  allow_images: true,
  allow_videos: true,
  allow_files: true,
  enforce_text_absolute_expiry: false,
  image_read_timer_sec: 0,
  image_overall_expiry_sec: 0,
  enforce_image_absolute_expiry: false,
  video_read_timer_sec: 0,
  video_overall_expiry_sec: 0,
  enforce_video_absolute_expiry: false,
  file_read_timer_sec: 0,
  file_overall_expiry_sec: 0,
  enforce_file_absolute_expiry: false,
};

describe("AttachmentDialog privacy boundary", () => {
  it("conceals the selected attachment name and metadata", () => {
    const { container } = render(
      <AttachmentDialog
        room={room}
        retentionSec={0}
        onCancel={vi.fn()}
        onPickerState={vi.fn()}
        onSend={vi.fn(async () => true)}
      />,
    );
    const input = container.querySelector<HTMLInputElement>("input[type='file']");
    expect(input).not.toBeNull();
    fireEvent.change(input!, {
      target: { files: [new File(["secret"], "private-notes.txt", { type: "text/plain" })] },
    });

    expect(screen.getByText("private-notes.txt").closest("[data-privacy-blur='true']")).not.toBeNull();
    expect(screen.getByText(/FILE/u).closest("[data-privacy-blur='true']")).not.toBeNull();
  });
});

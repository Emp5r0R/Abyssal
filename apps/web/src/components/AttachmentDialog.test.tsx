import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MEDIA_LIMIT_BYTES } from "../domain/messagePolicy";
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
  afterEach(cleanup);

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

  it("reports invalid selections and resets the picker for the same file", async () => {
    const onSend = vi.fn(async () => true);
    const { container } = render(
      <AttachmentDialog
        room={room}
        retentionSec={0}
        onCancel={vi.fn()}
        onPickerState={vi.fn()}
        onSend={onSend}
      />,
    );
    const input = container.querySelector<HTMLInputElement>("input[type='file']")!;
    const empty = new File([], "empty.txt", { type: "text/plain" });
    fireEvent.change(input, { target: { files: [empty] } });
    expect(screen.getByRole("status")).toHaveTextContent("Choose a non-empty file.");
    expect(input.value).toBe("");

    const valid = new File(["secret"], "private-notes.txt", { type: "text/plain" });
    fireEvent.change(input, { target: { files: [valid] } });
    fireEvent.change(input, { target: { files: [valid] } });
    expect(screen.getByText("private-notes.txt")).toBeInTheDocument();
    expect(input.value).toBe("");
    fireEvent.click(screen.getByRole("button", { name: "SEND" }));
    await waitFor(() => expect(onSend).toHaveBeenCalledOnce());
  });

  it("clears picker state when the native chooser is canceled or the dialog unmounts", () => {
    const onPickerState = vi.fn();
    const { container, unmount } = render(
      <AttachmentDialog
        room={room}
        retentionSec={0}
        onCancel={vi.fn()}
        onPickerState={onPickerState}
        onSend={vi.fn(async () => true)}
      />,
    );
    const input = container.querySelector<HTMLInputElement>("input[type='file']")!;
    fireEvent(input, new Event("cancel", { bubbles: true }));
    expect(onPickerState).toHaveBeenLastCalledWith(false);
    unmount();
    expect(onPickerState).toHaveBeenLastCalledWith(false);
  });

  it("reports size and room-policy rejection without sending", () => {
    const onSend = vi.fn(async () => true);
    const { container } = render(
      <AttachmentDialog
        room={{ ...room, allow_images: false }}
        retentionSec={0}
        onCancel={vi.fn()}
        onPickerState={vi.fn()}
        onSend={onSend}
      />,
    );
    const input = container.querySelector<HTMLInputElement>("input[type='file']")!;
    const oversized = new File([new Uint8Array(MEDIA_LIMIT_BYTES.IMAGE + 1)], "large.png", { type: "image/png" });
    fireEvent.change(input, { target: { files: [oversized] } });
    expect(screen.getByRole("status")).toHaveTextContent(/exceeds the image limit/u);

    const disallowed = new File(["image"], "blocked.png", { type: "image/png" });
    fireEvent.change(input, { target: { files: [disallowed] } });
    expect(screen.getByRole("status")).toHaveTextContent("This room does not allow image attachments.");
    expect(onSend).not.toHaveBeenCalled();
  });

  it("closes on Escape and starts focus in the dialog", async () => {
    const onCancel = vi.fn();
    render(
      <AttachmentDialog
        room={room}
        retentionSec={0}
        onCancel={onCancel}
        onPickerState={vi.fn()}
        onSend={vi.fn(async () => true)}
      />,
    );
    await waitFor(() => expect(screen.getByRole("button", { name: /CHOOSE FILE/u })).toHaveFocus());
    fireEvent.keyDown(document, { key: "Escape" });
    expect(onCancel).toHaveBeenCalledOnce();
  });
});

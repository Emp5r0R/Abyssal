import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { RoomRecord } from "../domain/types";
import { ChatView } from "./ChatView";

const direct: RoomRecord = {
  id: "dm_direct",
  name: "Peer",
  conversation_type: "direct",
  peer_username: "Peer",
  self_destruct_timer_sec: 5,
  overall_expiry_sec: 0,
  allow_images: true,
  allow_videos: true,
  allow_files: true,
  enforce_text_absolute_expiry: false,
  image_read_timer_sec: 5,
  image_overall_expiry_sec: 0,
  enforce_image_absolute_expiry: false,
  video_read_timer_sec: 5,
  video_overall_expiry_sec: 0,
  enforce_video_absolute_expiry: false,
  file_read_timer_sec: 5,
  file_overall_expiry_sec: 0,
  enforce_file_absolute_expiry: false,
};

describe("direct message retention", () => {
  it("sends each direct message with selected retention", async () => {
    const send = vi.fn().mockResolvedValue(true);
    render(
      <ChatView
        room={direct}
        username="Self"
        connected
        safetyNumber={null}
        messages={[]}
        users={[]}
        upload={{ active: false, name: "", loaded: 0, total: 0 }}
        onBack={vi.fn()}
        onSend={send}
        onReply={vi.fn()}
        replyTarget={null}
        onOpenAttachment={vi.fn()}
        onViewAttachment={vi.fn()}
        onExportAttachment={vi.fn()}
        onSendGif={vi.fn().mockResolvedValue(true)}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "NEVER" }));
    fireEvent.change(screen.getByLabelText("Message"), { target: { value: "kept in session" } });
    fireEvent.click(screen.getByRole("button", { name: "Send message" }));

    await waitFor(() => expect(send).toHaveBeenCalledWith("kept in session", undefined, 0));
  });
});

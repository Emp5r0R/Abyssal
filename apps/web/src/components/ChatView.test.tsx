import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ChatMessage, RoomRecord } from "../domain/types";
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

  it("shows that verification is recommended while keeping out-of-band confirmation optional", async () => {
    const verify = vi.fn(() => true);
    render(
      <ChatView
        room={direct}
        username="Self"
        connected
        safetyNumber="1234 5678 9012"
        directTrust={{ verified: false, verificationToken: "abyssal:verify:v1:test-token" }}
        messages={[]}
        users={[]}
        upload={{ active: false, name: "", loaded: 0, total: 0 }}
        onBack={vi.fn()}
        onSend={vi.fn().mockResolvedValue(true)}
        onReply={vi.fn()}
        replyTarget={null}
        onOpenAttachment={vi.fn()}
        onViewAttachment={vi.fn()}
        onExportAttachment={vi.fn()}
        onSendGif={vi.fn().mockResolvedValue(true)}
        onVerifyToken={verify}
      />,
    );

    const verifyButton = screen.getAllByRole("button", { name: "Verify peer identity (recommended)" }).find((button) => !(button as HTMLButtonElement).disabled);
    expect(verifyButton).toHaveTextContent("VERIFICATION RECOMMENDED");
    verifyButton!.focus();
    fireEvent.click(verifyButton!);
    expect(screen.getByRole("heading", { name: "Verify peer identity" })).toBeInTheDocument();
    expect(screen.getByText(/trusted channel/i)).toBeInTheDocument();
    expect(screen.getByText(/recommended but optional/i)).toBeInTheDocument();
    const qrImageButton = screen.getByRole("button", { name: /OPEN QR IMAGE/u });
    const scanButton = screen.getByRole("button", { name: /SCAN PEER QR/u });
    const cancelAction = screen.getByRole("button", { name: "CANCEL" });
    await waitFor(() => expect(scanButton).toHaveFocus());
    qrImageButton.focus();
    expect(qrImageButton).toHaveFocus();
    scanButton.focus();
    fireEvent.keyDown(scanButton, { key: "Tab", shiftKey: true });
    expect(cancelAction).toHaveFocus();
    fireEvent.keyDown(document, { key: "Escape" });
    await waitFor(() => expect(verifyButton).toHaveFocus());
    fireEvent.click(verifyButton!);
    fireEvent.change(screen.getByLabelText("Peer verification token"), {
      target: { value: "abyssal:verify:v1:test-token" },
    });
    fireEvent.click(screen.getByRole("button", { name: "VERIFY TOKEN" }));
    await waitFor(() => expect(verify).toHaveBeenCalledWith("abyssal:verify:v1:test-token"));
  });
});

describe("sender-client origin badges", () => {
  afterEach(cleanup);

  const baseMessage = (overrides: Partial<ChatMessage>): ChatMessage => ({
    id: "message-one",
    chatId: direct.id,
    sender: "Peer",
    content: "hello",
    kind: "text",
    createdAtMs: 1_000,
    receivedAtMs: 1_000,
    selfDestructSec: 0,
    absoluteExpirySec: 0,
    mine: false,
    ...overrides,
  });

  it("disables attachment view and export controls while disconnected", () => {
    render(
      <ChatView
        room={direct}
        username="Self"
        connected={false}
        safetyNumber={null}
        messages={[baseMessage({
          kind: "attachment",
          content: "private.txt",
          attachment: {
            id: "123e4567-e89b-42d3-a456-426614174000",
            encryptionVersion: 2,
            encryptionKey: new Uint8Array(32).fill(9),
            name: "private.txt",
            mediaType: "FILE",
            mimeType: "text/plain",
            sizeBytes: 3,
            oneTime: false,
            deleteAfterDownload: false,
          },
        })]}
        users={[]}
        upload={{ active: false, name: "", loaded: 0, total: 0 }}
        onBack={vi.fn()}
        onSend={vi.fn()}
        onReply={vi.fn()}
        replyTarget={null}
        onOpenAttachment={vi.fn()}
        onViewAttachment={vi.fn()}
        onExportAttachment={vi.fn()}
        onSendGif={vi.fn()}
      />,
    );

    expect(screen.getByRole("button", { name: "View attachment (offline)" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Save attachment (offline)" })).toBeDisabled();
  });

  it("warns on each message sent from the web client", () => {
    render(
      <ChatView
        room={direct}
        username="Self"
        connected
        safetyNumber={null}
        messages={[baseMessage({ senderClient: "web" })]}
        users={[]}
        upload={{ active: false, name: "", loaded: 0, total: 0 }}
        onBack={vi.fn()}
        onSend={vi.fn()}
        onReply={vi.fn()}
        replyTarget={null}
        onOpenAttachment={vi.fn()}
        onViewAttachment={vi.fn()}
        onExportAttachment={vi.fn()}
        onSendGif={vi.fn()}
      />,
    );

    expect(screen.getByRole("img", { name: /sent from the web client/i })).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /screenshot/i })).toBeInTheDocument();
  });

  it("marks messages sent from the hardened Android app without the warning styling", () => {
    render(
      <ChatView
        room={direct}
        username="Self"
        connected
        safetyNumber={null}
        messages={[baseMessage({ senderClient: "android", senderDisplayName: "PrivateProfile" })]}
        users={[]}
        upload={{ active: false, name: "", loaded: 0, total: 0 }}
        onBack={vi.fn()}
        onSend={vi.fn()}
        onReply={vi.fn()}
        replyTarget={null}
        onOpenAttachment={vi.fn()}
        onViewAttachment={vi.fn()}
        onExportAttachment={vi.fn()}
        onSendGif={vi.fn()}
      />,
    );

    expect(screen.getByRole("img", { name: /sent from the android app/i })).toBeInTheDocument();
    const author = screen.getByRole("button", { name: "PrivateProfile (Peer)" });
    fireEvent.click(author);
    expect(screen.getByLabelText("Message")).toHaveValue("@Peer ");
    expect(screen.queryByRole("img", { name: /web client/i })).toBeNull();
  });

  it("never decorates own locally composed messages with an origin badge", () => {
    render(
      <ChatView
        room={direct}
        username="Self"
        connected
        safetyNumber={null}
        messages={[baseMessage({ mine: true, sender: "Self", senderClient: "web" })]}
        users={[]}
        upload={{ active: false, name: "", loaded: 0, total: 0 }}
        onBack={vi.fn()}
        onSend={vi.fn()}
        onReply={vi.fn()}
        replyTarget={null}
        onOpenAttachment={vi.fn()}
        onViewAttachment={vi.fn()}
        onExportAttachment={vi.fn()}
        onSendGif={vi.fn()}
      />,
    );

    expect(screen.queryByRole("img", { name: /sent from/i })).toBeNull();
  });

  it("conceals the chat label, sender, and complete message surface by default", () => {
    render(
      <ChatView
        room={direct}
        username="Self"
        connected
        safetyNumber={null}
        messages={[baseMessage({ content: "concealed body" })]}
        users={[]}
        upload={{ active: false, name: "", loaded: 0, total: 0 }}
        onBack={vi.fn()}
        onSend={vi.fn()}
        onReply={vi.fn()}
        replyTarget={null}
        onOpenAttachment={vi.fn()}
        onViewAttachment={vi.fn()}
        onExportAttachment={vi.fn()}
        onSendGif={vi.fn()}
      />,
    );

    expect(screen.getByRole("heading", { name: direct.name }).querySelector("[data-privacy-blur='true']")).not.toBeNull();
    expect(screen.getByRole("button", { name: "Peer" })).toHaveClass("privacy-blur");
    const body = screen.getByText("concealed body").closest(".message-bubble");
    expect(body).toHaveClass("privacy-blur");
    expect(body).toHaveAttribute("tabindex", "0");
  });
});

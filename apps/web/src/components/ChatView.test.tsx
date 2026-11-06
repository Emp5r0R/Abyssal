import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ChatMessage, RoomRecord } from "../domain/types";
import { ChatView } from "./ChatView";
import { PrivacyBlurProvider } from "./PrivacyBlur";

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

    fireEvent.click(screen.getByRole("button", { name: "Never" }));
    expect(screen.getByRole("button", { name: "Never" })).toHaveAttribute("aria-pressed", "true");
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
    expect(verifyButton).toHaveTextContent("Not verified");
    verifyButton!.focus();
    fireEvent.click(verifyButton!);
    expect(screen.getByRole("heading", { name: "Verify peer identity" })).toBeInTheDocument();
    expect(screen.getByText(/trusted channel/i)).toBeInTheDocument();
    expect(screen.getByText(/recommended but optional/i)).toBeInTheDocument();
    expect(screen.getByText("abyssal:verify:v1:test-token")).toBeInTheDocument();
    const copyButton = screen.getByRole("button", { name: "Copy verification code" });
    const qrImageButton = screen.getByRole("button", { name: /Open QR image/u });
    expect(screen.getByRole("button", { name: /Scan peer QR/u })).toBeEnabled();
    const cancelAction = screen.getByRole("button", { name: "Cancel" });
    await waitFor(() => expect(copyButton).toHaveFocus());
    qrImageButton.focus();
    expect(qrImageButton).toHaveFocus();
    copyButton.focus();
    fireEvent.keyDown(copyButton, { key: "Tab", shiftKey: true });
    expect(cancelAction).toHaveFocus();
    fireEvent.keyDown(document, { key: "Escape" });
    await waitFor(() => expect(verifyButton).toHaveFocus());
    fireEvent.click(verifyButton!);
    fireEvent.change(screen.getByLabelText("Peer verification code"), {
      target: { value: "abyssal:verify:v1:test-token" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Verify code" }));
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

  it("conceals the chat label, sender, and complete message surface when blur is on", () => {
    render(
      <PrivacyBlurProvider enabled><ChatView
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
      /></PrivacyBlurProvider>,
    );

    expect(screen.getByRole("heading", { name: direct.name }).querySelector("[data-privacy-blur='true']")).not.toBeNull();
    expect(screen.getByRole("button", { name: "Peer" })).toHaveClass("privacy-blur");
    const body = screen.getByText("concealed body").closest(".message-bubble");
    expect(body).toHaveClass("privacy-blur");
    expect(body).toHaveAttribute("tabindex", "0");
  });
});

describe("message actions", () => {
  afterEach(cleanup);
  const base = { chatId: "dm_direct", kind: "text" as const, createdAtMs: 1, receivedAtMs: 1, selfDestructSec: 0, absoluteExpirySec: 0 };
  const theirs: ChatMessage = { ...base, id: "m1", sender: "Peer", content: "hello", mine: false, reactions: { "👍": ["peer"] } };
  const mine: ChatMessage = { ...base, id: "m2", sender: "Self", content: "typo", mine: true };

  function renderWithActions(onAction = vi.fn().mockResolvedValue(true)) {
    render(
      <ChatView
        room={direct}
        username="Self"
        connected
        safetyNumber={null}
        messages={[theirs, mine]}
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
        onAction={onAction}
      />,
    );
    return onAction;
  }

  it("shows reaction counts and toggles your own reaction", () => {
    const onAction = renderWithActions();
    fireEvent.click(screen.getByRole("button", { name: "👍 1" }));
    expect(onAction).toHaveBeenCalledWith({ kind: "reaction", targetId: "m1", emoji: "👍", active: true });

    fireEvent.click(screen.getAllByRole("button", { name: "React" })[0]);
    fireEvent.click(screen.getByRole("menuitemcheckbox", { name: "❤️" }));
    expect(onAction).toHaveBeenCalledWith({ kind: "reaction", targetId: "m1", emoji: "❤️", active: true });
  });

  it("filters the conversation while searching", () => {
    renderWithActions();
    fireEvent.click(screen.getByRole("button", { name: "Search this conversation" }));
    fireEvent.change(screen.getByLabelText("Search this conversation"), { target: { value: "TYPO" } });
    expect(screen.getByRole("status")).toHaveTextContent("1 found");
    expect(screen.queryByText("hello")).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Search this conversation"), { target: { value: "nothing" } });
    expect(screen.getByText("No matches")).toBeInTheDocument();
    fireEvent.keyDown(screen.getByLabelText("Search this conversation"), { key: "Escape" });
    expect(screen.getByText("hello")).toBeInTheDocument();
  });

  it("offers edit and delete only on your own messages", async () => {
    const onAction = renderWithActions();
    expect(screen.getAllByRole("button", { name: "Edit message" })).toHaveLength(1);
    expect(screen.getAllByRole("button", { name: "Delete for everyone" })).toHaveLength(1);

    fireEvent.click(screen.getByRole("button", { name: "Edit message" }));
    expect(screen.getByText("Editing your message")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Message"), { target: { value: "fixed" } });
    fireEvent.click(screen.getByRole("button", { name: "Save edit" }));
    await waitFor(() => expect(onAction).toHaveBeenCalledWith({ kind: "edit", targetId: "m2", content: "fixed" }));
    await waitFor(() => expect(screen.queryByText("Editing your message")).not.toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: "Delete for everyone" }));
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    expect(onAction).toHaveBeenCalledWith({ kind: "delete", targetId: "m2" });
  });
});

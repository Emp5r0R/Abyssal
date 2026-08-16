import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ChatMessage, RoomRecord } from "../domain/types";
import { AppShell } from "./AppShell";

const room: RoomRecord = {
  id: "forum_ops",
  name: "Operations",
  owner_username: "Alice",
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

function message(chatId: string, content: string): ChatMessage {
  return {
    id: `${chatId}_message`,
    chatId,
    sender: "Bob",
    content,
    kind: "text",
    createdAtMs: 1_000,
    receivedAtMs: 1_000,
    selfDestructSec: 0,
    absoluteExpirySec: 0,
    mine: false,
  };
}

function renderShell(overrides: Partial<React.ComponentProps<typeof AppShell>> = {}) {
  const props: React.ComponentProps<typeof AppShell> = {
    username: "Alice",
    nodeId: "node-one",
    connection: "connected",
    rooms: [room],
    directs: [{ id: "dm_random", peer_username: "Bob" }],
    messages: {},
    presence: [
      { username: "Alice", connected: true, identity_public_b64: "AA", identity_prekey_id: "test-prekey", directory_digest: "A".repeat(43), directory_node_id: "node-one", directory_revision: 1 },
      { username: "Bob", connected: true, identity_public_b64: "AA", identity_prekey_id: "test-prekey", directory_digest: "A".repeat(43), directory_node_id: "node-one", directory_revision: 1 },
      { username: "Carol", connected: false, identity_public_b64: "AA", identity_prekey_id: "test-prekey", directory_digest: "A".repeat(43), directory_node_id: "node-one", directory_revision: 1 },
    ],
    activeRoomId: null,
    maxRooms: 2,
    remainingSessionSec: 100,
    sessionTimeoutSec: 900,
    onOpenRoom: vi.fn(),
    onOpenDirect: vi.fn(),
    onCreateRoom: vi.fn(),
    onDeleteRoom: vi.fn(),
    onLock: vi.fn(),
    onLogout: vi.fn(),
    onWipe: vi.fn(),
    ...overrides,
  };
  render(<AppShell {...props} />);
  return props;
}

afterEach(cleanup);

describe("AppShell direct-message navigation", () => {
  it("opens an existing canonical direct conversation", () => {
    const props = renderShell();
    const directNavigation = screen.getByRole("navigation", { name: "Direct messages" });
    fireEvent.click(within(directNavigation).getByRole("button", { name: /Bob/i }));
    expect(props.onOpenRoom).toHaveBeenCalledWith("dm_random");
  });

  it("starts a new DM from the peer list", () => {
    const props = renderShell();
    const directNavigation = screen.getByRole("navigation", { name: "Direct messages" });
    fireEvent.click(within(directNavigation).getByRole("button", { name: /Carol/i }));
    expect(props.onOpenDirect).toHaveBeenCalledWith("Carol");
  });

  it("does not allow messaging the current account", () => {
    renderShell();
    expect(screen.getByTitle("Current account")).toBeDisabled();
  });

  it("exposes the full directory checkpoint for out-of-band comparison", () => {
    renderShell();
    expect(screen.getByTitle(`Directory checkpoint ${"A".repeat(43)}`)).toBeInTheDocument();
  });

  it("requires explicit confirmation before wiping relay RAM", () => {
    const props = renderShell();
    fireEvent.click(screen.getByRole("button", { name: "Wipe relay" }));
    expect(screen.getByText("Wipe relay memory?")).toBeInTheDocument();
    expect(props.onWipe).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "WIPE NOW" }));
    expect(props.onWipe).toHaveBeenCalledOnce();
  });

  it("keeps room navigation and destructive actions as separate controls", () => {
    const props = renderShell();
    expect(document.querySelector("button button")).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Open room Operations" }));
    expect(props.onOpenRoom).toHaveBeenCalledWith(room.id);

    fireEvent.click(screen.getByRole("button", { name: "Delete room" }));
    expect(props.onDeleteRoom).toHaveBeenCalledWith(room.id);
  });

  it("never renders room or direct message plaintext on the dashboard", () => {
    renderShell({
      messages: {
        [room.id]: [message(room.id, "ROOM SECRET PREVIEW")],
        dm_random: [message("dm_random", "DIRECT SECRET PREVIEW")],
      },
    });

    expect(screen.queryByText(/ROOM SECRET PREVIEW/u)).not.toBeInTheDocument();
    expect(screen.queryByText(/DIRECT SECRET PREVIEW/u)).not.toBeInTheDocument();
    expect(screen.getByText("OWNER Alice")).toBeInTheDocument();
  });
});

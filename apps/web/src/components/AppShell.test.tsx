import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ChatMessage, RoomRecord } from "../domain/types";
import type { PublicRoomSummary } from "../transport/mlsWire";
import { AppShell } from "./AppShell";
import { PrivacyBlurProvider } from "./PrivacyBlur";

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

function renderShell(overrides: Partial<React.ComponentProps<typeof AppShell>> = {}, blur = false) {
  const props: React.ComponentProps<typeof AppShell> = {
    username: "Alice",
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
    canLock: true,
    onOpenRoom: vi.fn(),
    onOpenDirect: vi.fn(),
    onCreateRoom: vi.fn(),
    onDeleteRoom: vi.fn(),
    onLock: vi.fn(),
    onOpenSettings: vi.fn(),
    onLogout: vi.fn(),
    ...overrides,
  };
  render(<PrivacyBlurProvider enabled={blur}><AppShell {...props} /></PrivacyBlurProvider>);
  return props;
}

const publicRoom = (roomId: string): PublicRoomSummary => ({
  room_id: roomId,
  group_id_b64: "A".repeat(43),
  owner_username: "Carol",
  policy: {
    self_destruct_timer_sec: "5", overall_expiry_sec: "60", allow_images: true, allow_videos: false,
    allow_files: true, enforce_text_absolute_expiry: false, image_read_timer_sec: "5", image_overall_expiry_sec: "60",
    enforce_image_absolute_expiry: false, video_read_timer_sec: "5", video_overall_expiry_sec: "60",
    enforce_video_absolute_expiry: false, file_read_timer_sec: "5", file_overall_expiry_sec: "60",
    enforce_file_absolute_expiry: false,
  },
});

afterEach(cleanup);

describe("AppShell navigation and home", () => {
  it("shows the private own profile and keeps the full account ID available", () => {
    renderShell({ username: "acct_1234567890abcdef1234567890abcdef", displayName: "PrivateProfile" });
    const account = document.querySelector<HTMLElement>(".account-card")!;
    expect(within(account).getByText("PrivateProfile")).toBeInTheDocument();
    expect(account).toHaveAttribute("title", "acct_1234567890abcdef1234567890abcdef");
  });

  it("opens an existing canonical direct conversation", () => {
    const props = renderShell();
    const directNavigation = screen.getByRole("navigation", { name: "Direct messages" });
    fireEvent.click(within(directNavigation).getByRole("button", { name: /Bob/u }));
    expect(props.onOpenRoom).toHaveBeenCalledWith("dm_random");
  });

  it("starts a new DM from the people list", () => {
    const props = renderShell();
    const people = screen.getByRole("navigation", { name: "People" });
    fireEvent.click(within(people).getByRole("button", { name: "Message Carol" }));
    expect(props.onOpenDirect).toHaveBeenCalledWith("Carol");
  });

  it("closes the mobile sidebar when navigating home", () => {
    const props = renderShell();
    fireEvent.click(screen.getByRole("button", { name: "Open menu" }));
    const sidebar = document.querySelector(".sidebar")!;
    expect(sidebar).toHaveClass("is-open");
    fireEvent.click(within(sidebar as HTMLElement).getByRole("button", { name: "Home" }));
    expect(sidebar).not.toHaveClass("is-open");
    expect(props.onOpenRoom).toHaveBeenCalledWith(null);
  });

  it("opens settings and offers lock only when the cover is ready", () => {
    const props = renderShell();
    fireEvent.click(screen.getByRole("button", { name: "Settings" }));
    expect(props.onOpenSettings).toHaveBeenCalledOnce();
    fireEvent.click(screen.getByRole("button", { name: "Lock now" }));
    expect(props.onLock).toHaveBeenCalledOnce();
    cleanup();
    renderShell({ canLock: false });
    expect(screen.queryByRole("button", { name: "Lock now" })).not.toBeInTheDocument();
  });

  it("offers search and a quick lock in the mobile top bar", () => {
    const onSearch = vi.fn();
    const props = renderShell({ onSearch });
    const finders = screen.getAllByRole("button", { name: "Find a conversation" });
    expect(finders).toHaveLength(2);
    finders.forEach((button) => fireEvent.click(button));
    expect(onSearch).toHaveBeenCalledTimes(2);
    fireEvent.click(screen.getByRole("button", { name: "Lock" }));
    expect(props.onLock).toHaveBeenCalledOnce();
    cleanup();
    renderShell({ canLock: false });
    expect(screen.queryByRole("button", { name: "Find a conversation" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Lock" })).not.toBeInTheDocument();
  });

  it("lets members copy a room ID from the dashboard", async () => {
    const writeText = vi.fn(async () => undefined);
    vi.stubGlobal("navigator", { ...navigator, clipboard: { writeText } });
    renderShell();
    fireEvent.click(screen.getByRole("button", { name: "Copy room ID" }));
    expect(await screen.findByRole("button", { name: "Copied" })).toBeInTheDocument();
    expect(writeText).toHaveBeenCalledWith("forum_ops");
    vi.unstubAllGlobals();
  });

  it("reports a failed room join request", () => {
    renderShell({ onJoinRoom: vi.fn(() => false) });
    fireEvent.change(screen.getByLabelText("Room ID"), { target: { value: "forum_ops" } });
    fireEvent.click(screen.getByRole("button", { name: "Join by ID" }));
    expect(screen.getByRole("status")).toHaveTextContent(/could not be sent/u);
  });

  it("lists only unjoined public rooms, joins by the exact room ID, and says admission is automatic", () => {
    const onJoinRoom = vi.fn(() => true);
    renderShell({
      onJoinRoom,
      publicRooms: [publicRoom(room.id), publicRoom("forum_public_abc")],
    });

    expect(screen.queryByRole("button", { name: "Join public room forum_ops" })).not.toBeInTheDocument();
    const join = screen.getByRole("button", { name: "Join public room forum_public_abc" });
    fireEvent.click(join);
    expect(onJoinRoom).toHaveBeenCalledWith("forum_public_abc");
    expect(screen.getByRole("status")).toHaveTextContent(/automatically/u);
    expect(join).toBeDisabled();
    expect(join).toHaveTextContent("Joining…");
  });

  it("guides empty dashboards according to relay connectivity", () => {
    renderShell({ rooms: [], directs: [] });
    expect(screen.getByText("Create a room, or join a public one below.")).toBeInTheDocument();
    expect(screen.getByText("Pick someone under People in the sidebar to start one.")).toBeInTheDocument();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
    cleanup();
    renderShell({ rooms: [], connection: "disconnected" });
    expect(screen.getByText("Rooms can be created once the relay is connected.")).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent(/relay is unreachable/u);
    expect(screen.getByRole("button", { name: /New room/u })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Create room" })).toBeDisabled();
  });

  it("does not offer a conversation with the current account", () => {
    renderShell();
    const people = screen.getByRole("navigation", { name: "People" });
    expect(within(people).queryByRole("button", { name: /Alice/u })).not.toBeInTheDocument();
  });

  it("lists online people before offline ones when starting a conversation", () => {
    renderShell({
      directs: [],
      presence: [
        { username: "Alice", connected: true, identity_public_b64: "AA", identity_prekey_id: "p", directory_digest: "A".repeat(43), directory_node_id: "node-one", directory_revision: 1 },
        { username: "Aaron", connected: false, identity_public_b64: "AA", identity_prekey_id: "p", directory_digest: "A".repeat(43), directory_node_id: "node-one", directory_revision: 1 },
        { username: "Zed", connected: true, identity_public_b64: "AA", identity_prekey_id: "p", directory_digest: "A".repeat(43), directory_node_id: "node-one", directory_revision: 1 },
      ],
    });
    const names = [...document.querySelectorAll(".start-direct")].map((button) => button.textContent);
    expect(names).toEqual(["Zed", "Aaron"]);
  });

  it("explains that private rooms need the owner's approval", () => {
    const onJoinRoom = vi.fn(() => true);
    renderShell({ onJoinRoom });
    expect(screen.getByText(/Ask the owner for the room ID/u)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Room ID"), { target: { value: " forum_private " } });
    fireEvent.click(screen.getByRole("button", { name: "Join by ID" }));
    expect(onJoinRoom).toHaveBeenCalledWith("forum_private");
    expect(screen.getByRole("status")).toHaveTextContent(/owner must approve/u);
  });

  it("asks for confirmation before deleting a room and keeps navigation separate", () => {
    const props = renderShell();
    expect(document.querySelector("button button")).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Open room Operations" }));
    expect(props.onOpenRoom).toHaveBeenCalledWith(room.id);

    fireEvent.click(screen.getByRole("button", { name: "Delete room" }));
    expect(screen.getByRole("heading", { name: "Delete this room?" })).toBeInTheDocument();
    expect(props.onDeleteRoom).not.toHaveBeenCalled();
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Delete room" }));
    expect(props.onDeleteRoom).toHaveBeenCalledWith(room.id);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("exposes a member leave action without merging it into room navigation", () => {
    const onLeaveRoom = vi.fn(() => true);
    renderShell({ username: "Bob", onLeaveRoom });
    fireEvent.click(screen.getByRole("button", { name: "Leave room" }));
    expect(onLeaveRoom).toHaveBeenCalledWith(room.id);
  });

  it("shows owner join and leave requests by room name without exposing identity material", () => {
    const props = renderShell({
      pendingRoomJoins: [{ roomId: room.id, requestId: "join-request", username: "Carol" }],
      pendingRoomLeaves: [{ roomId: room.id, requestId: "leave-request", username: "Bob" }],
      onAcceptRoomJoin: vi.fn(async () => true),
      onRejectRoomJoin: vi.fn(() => true),
      onAcceptRoomLeave: vi.fn(async () => true),
      onRejectRoomLeave: vi.fn(() => true),
    });
    const joinRequest = screen.getByLabelText("Join request");
    expect(joinRequest).toHaveTextContent("Carol");
    expect(joinRequest).toHaveTextContent("wants to join Operations");
    fireEvent.click(within(joinRequest).getByRole("button", { name: "Accept" }));
    expect(props.onAcceptRoomJoin).toHaveBeenCalledWith("join-request");
    fireEvent.click(within(joinRequest).getByRole("button", { name: "Decline" }));
    expect(props.onRejectRoomJoin).toHaveBeenCalledWith("join-request");

    const leaveRequest = screen.getByLabelText("Leave request");
    expect(leaveRequest).toHaveTextContent("Bob");
    expect(leaveRequest).not.toHaveTextContent("stable_identity");
    fireEvent.click(within(leaveRequest).getByRole("button", { name: "Remove" }));
    expect(props.onAcceptRoomLeave).toHaveBeenCalledWith("leave-request");
  });

  it("does not render owner controls for the member's own pending leave", () => {
    renderShell({
      username: "Bob",
      pendingRoomLeaves: [{ roomId: room.id, requestId: "leave-request", username: "Bob" }],
    });
    expect(screen.getByLabelText("Your leave request")).toHaveTextContent("Leaving Operations");
    expect(screen.queryByRole("button", { name: "Remove" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Keep" })).not.toBeInTheDocument();
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
    expect(screen.getByText("You own this room")).toBeInTheDocument();
  });

  it("shows names plainly by default and conceals them when blur is turned on", () => {
    renderShell();
    expect(document.querySelectorAll("[data-privacy-blur='true']")).toHaveLength(0);
    cleanup();

    renderShell({ username: "Bob" }, true);
    const concealed = [...document.querySelectorAll<HTMLElement>("[data-privacy-blur='true']")]
      .map((element) => element.textContent);
    expect(concealed).toContain("Operations");
    expect(concealed).toContain("Owner Alice");
  });

  it("labels peers by their latest display name while keeping the account ID as the accessible name", () => {
    renderShell({ messages: { dm_random: [{ ...message("dm_random", "hi"), senderDisplayName: "SilverComet" }] } });
    const directNavigation = screen.getByRole("navigation", { name: "Direct messages" });
    const button = within(directNavigation).getByRole("button", { name: /^Bob/u });
    expect(button).toHaveTextContent("SilverComet");
  });
});

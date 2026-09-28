import {
  Activity,
  DoorOpen,
  Hash,
  House,
  LockKeyhole,
  MessageCirclePlus,
  Plus,
  ShieldAlert,
  ShieldCheck,
  UserRound,
  X,
} from "lucide-react";
import type { ChatMessage, ConnectionState, DirectRecord, PresenceUser, RoomRecord } from "../domain/types";
import { connectionLabel } from "./connectionCopy";
import { PrivacyBlur } from "./PrivacyBlur";
import { Brand, IconButton } from "./Ui";

export interface SidebarProps {
  username: string;
  displayName?: string;
  nodeId: string;
  connection: ConnectionState;
  rooms: RoomRecord[];
  directs: DirectRecord[];
  messages: Record<string, ChatMessage[]>;
  presence: PresenceUser[];
  activeRoomId: string | null;
  maxRooms: number;
  remainingSessionSec: number;
  sessionTimeoutSec: number;
  open: boolean;
  onClose: () => void;
  onNavigate: (chatId: string | null) => void;
  onOpenDirect: (username: string) => void;
  onCreateRoom: () => void;
  onLock: () => void;
  onLogout: () => void;
  onRequestWipe: () => void;
}

/** Primary navigation: identity, rooms, conversations, people, and session controls. */
export function Sidebar({
  username,
  displayName,
  nodeId,
  connection,
  rooms,
  directs,
  messages,
  presence,
  activeRoomId,
  maxRooms,
  remainingSessionSec,
  sessionTimeoutSec,
  open,
  onClose,
  onNavigate,
  onOpenDirect,
  onCreateRoom,
  onLock,
  onLogout,
  onRequestWipe,
}: SidebarProps) {
  const ownedRooms = rooms.filter((room) => room.owner_username === username).length;
  const peers = presence.filter((user) => user.username !== username);
  // Online people first so reachable peers are visible without scrolling.
  const newPeers = peers
    .filter((user) => !directs.some((direct) => direct.peer_username === user.username))
    .sort((left, right) => Number(right.connected) - Number(left.connected) || left.username.localeCompare(right.username));
  const directoryCheckpoint = presence[0]?.directory_digest;
  const navigate = (chatId: string | null) => { onNavigate(chatId); onClose(); };
  const unreadCount = (chatId: string) =>
    (messages[chatId] ?? []).filter((message) => !message.mine && message.readAtMs === undefined).length;

  return (
    <aside className={`sidebar ${open ? "is-open" : ""}`}>
      <div className="sidebar-head">
        <Brand compact />
        <IconButton className="mobile-only" label="Close menu" onClick={onClose}><X size={19} /></IconButton>
      </div>

      <button className="identity-row" type="button" onClick={() => navigate(null)} title="Home">
        <div className="identity-avatar"><UserRound size={19} /></div>
        <div>
          <PrivacyBlur><strong>{displayName ?? username}</strong></PrivacyBlur>
          {displayName ? <PrivacyBlur><small>{username}</small></PrivacyBlur> : null}
          <span className={`identity-status state-${connection}`}><i />{connectionLabel(connection)}</span>
        </div>
        <span className="identity-node" title={nodeId}>{shortNode(nodeId)}</span>
      </button>

      <div className="sidebar-scroll">
        <button
          type="button"
          className={`sidebar-home ${activeRoomId === null ? "is-active" : ""}`}
          onClick={() => navigate(null)}
        >
          <House size={17} /><span>Home</span>
        </button>

        <div className="sidebar-section-title">
          <span>Rooms</span>
          <span className="sidebar-count" title="Rooms you own">{ownedRooms}/{maxRooms}</span>
          <IconButton
            label="Create room"
            disabled={ownedRooms >= maxRooms || connection !== "connected"}
            onClick={() => { onCreateRoom(); onClose(); }}
          ><Plus size={17} /></IconButton>
        </div>
        <nav className="room-nav" aria-label="Rooms">
          {rooms.length === 0 ? <div className="sidebar-empty">No rooms yet</div> : rooms.map((room) => {
            const unread = unreadCount(room.id);
            return (
              <button
                type="button"
                key={room.id}
                className={activeRoomId === room.id ? "is-active" : ""}
                onClick={() => navigate(room.id)}
              >
                <Hash size={16} />
                <PrivacyBlur>{room.name}</PrivacyBlur>
                {unread > 0 ? <strong aria-label={`${unread} unread`}>{Math.min(unread, 99)}</strong> : null}
              </button>
            );
          })}
        </nav>

        <div className="sidebar-section-title">
          <span>Direct messages</span>
          <span className="sidebar-count">{directs.length}</span>
        </div>
        <nav className="direct-nav" aria-label="Direct messages">
          {directs.map((direct) => {
            const unread = unreadCount(direct.id);
            const online = presence.find((user) => user.username === direct.peer_username)?.connected === true;
            return (
              <button
                type="button"
                key={direct.id}
                className={activeRoomId === direct.id ? "is-active" : ""}
                onClick={() => navigate(direct.id)}
              >
                <span className={`direct-status ${online ? "is-online" : ""}`} aria-label={online ? "Online" : "Offline"} />
                <PrivacyBlur>{direct.peer_username}</PrivacyBlur>
                {unread > 0 ? <strong aria-label={`${unread} unread`}>{Math.min(unread, 99)}</strong> : null}
              </button>
            );
          })}
          {newPeers.length > 0 ? <div className="sidebar-subtitle">Start a conversation</div> : null}
          {newPeers.map((user) => (
            <button
              type="button"
              key={user.username}
              className="start-direct"
              title="Start a direct conversation"
              onClick={() => { onOpenDirect(user.username); onClose(); }}
            >
              <span className={`direct-status ${user.connected ? "is-online" : ""}`} />
              <PrivacyBlur>{user.username}</PrivacyBlur>
              <MessageCirclePlus size={15} aria-hidden="true" />
            </button>
          ))}
          {peers.length === 0 ? <div className="sidebar-empty">No one else is on this node yet</div> : null}
        </nav>
      </div>

      <div className="sidebar-session">
        <div><Activity size={14} /><span>Session expires in</span><strong>{formatDuration(remainingSessionSec)}</strong></div>
        <progress className="session-meter" max={sessionTimeoutSec} value={remainingSessionSec} aria-label="Session time remaining" />
        {directoryCheckpoint ? (
          <div className="directory-checkpoint" title={`Directory checkpoint ${directoryCheckpoint}`}>
            <ShieldCheck size={14} /><span>Directory</span><strong>{shortCheckpoint(directoryCheckpoint)}</strong>
          </div>
        ) : null}
      </div>

      <div className="sidebar-actions">
        <IconButton label="Privacy cover" onClick={onLock}><LockKeyhole size={18} /></IconButton>
        <IconButton label="Wipe relay" className="is-danger" onClick={onRequestWipe}><ShieldAlert size={18} /></IconButton>
        <IconButton label="Log out" onClick={onLogout}><DoorOpen size={18} /></IconButton>
      </div>
    </aside>
  );
}

function shortNode(nodeId: string): string {
  const withoutPrefix = nodeId.replace(/^abyssal-node-v1:/u, "");
  return withoutPrefix.length > 10 ? `${withoutPrefix.slice(0, 8)}…` : withoutPrefix;
}

function formatDuration(seconds: number): string {
  const minutes = Math.floor(seconds / 60);
  const rest = seconds % 60;
  return `${String(minutes).padStart(2, "0")}:${String(rest).padStart(2, "0")}`;
}

function shortCheckpoint(value: string): string {
  return `${value.slice(0, 8)}...${value.slice(-4)}`;
}

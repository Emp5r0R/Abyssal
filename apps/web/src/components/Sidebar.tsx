import { Hash, House, LockKeyhole, LogOut, MessageCirclePlus, Plus, Settings, X } from "lucide-react";
import type { ChatMessage, ConnectionState, DirectRecord, PresenceUser, RoomRecord } from "../domain/types";
import { accountInitials, roomLabel, shortAccountId } from "../domain/displayLabels";
import { connectionLabel } from "./connectionCopy";
import { PrivacyBlur } from "./PrivacyBlur";
import { Brand, IconButton } from "./Ui";

export interface SidebarProps {
  username: string;
  displayName?: string;
  connection: ConnectionState;
  rooms: RoomRecord[];
  directs: DirectRecord[];
  messages: Record<string, ChatMessage[]>;
  presence: PresenceUser[];
  displayNames: ReadonlyMap<string, string>;
  activeRoomId: string | null;
  maxRooms: number;
  remainingSessionSec: number;
  canLock: boolean;
  open: boolean;
  onClose: () => void;
  onNavigate: (chatId: string | null) => void;
  onOpenDirect: (username: string) => void;
  onCreateRoom: () => void;
  onLock: () => void;
  onOpenSettings: () => void;
  onLogout: () => void;
}

/** Primary navigation: rooms, conversations, people, and the signed-in account. */
export function Sidebar({
  username,
  displayName,
  connection,
  rooms,
  directs,
  messages,
  presence,
  displayNames,
  activeRoomId,
  maxRooms,
  remainingSessionSec,
  canLock,
  open,
  onClose,
  onNavigate,
  onOpenDirect,
  onCreateRoom,
  onLock,
  onOpenSettings,
  onLogout,
}: SidebarProps) {
  const ownedRooms = rooms.filter((room) => room.owner_username === username).length;
  const peers = presence.filter((user) => user.username !== username);
  // Online people first so reachable peers are visible without scrolling.
  const newPeers = peers
    .filter((user) => !directs.some((direct) => direct.peer_username === user.username))
    .sort((left, right) => Number(right.connected) - Number(left.connected) || left.username.localeCompare(right.username));
  const navigate = (chatId: string | null) => { onNavigate(chatId); onClose(); };
  const unreadCount = (chatId: string) =>
    (messages[chatId] ?? []).filter((message) => !message.mine && message.readAtMs === undefined).length;
  const peerName = (peer: string) => displayNames.get(peer.toLowerCase());
  const createDisabled = ownedRooms >= maxRooms || connection !== "connected";

  return (
    <aside className={`sidebar ${open ? "is-open" : ""}`} aria-label="Navigation">
      <div className="sidebar-head">
        <Brand compact />
        <span className={`status-dot-label state-${connection}`} title={connectionLabel(connection)}>
          <i aria-hidden="true" />{connectionLabel(connection)}
        </span>
        <IconButton className="mobile-only" label="Close menu" onClick={onClose}><X size={18} /></IconButton>
      </div>

      <div className="sidebar-scroll">
        <button
          type="button"
          className={`nav-item ${activeRoomId === null ? "is-active" : ""}`}
          aria-current={activeRoomId === null ? "page" : undefined}
          onClick={() => navigate(null)}
        >
          <House size={17} aria-hidden="true" /><span className="nav-label">Home</span>
        </button>

        <div className="nav-section">
          <div className="nav-section-title">
            <h2>Rooms</h2>
            <span className="nav-count" title="Rooms you own">{ownedRooms}/{maxRooms}</span>
            <IconButton
              className="is-small"
              label="Create room"
              disabled={createDisabled}
              onClick={() => { onCreateRoom(); onClose(); }}
            ><Plus size={16} /></IconButton>
          </div>
          <nav aria-label="Rooms">
            {rooms.length === 0 ? <p className="nav-empty">No rooms yet</p> : rooms.map((room) => (
              <NavItem
                key={room.id}
                active={activeRoomId === room.id}
                unread={unreadCount(room.id)}
                onClick={() => navigate(room.id)}
                icon={<Hash size={16} aria-hidden="true" />}
                label={<PrivacyBlur>{roomLabel(room)}</PrivacyBlur>}
              />
            ))}
          </nav>
        </div>

        <div className="nav-section">
          <div className="nav-section-title">
            <h2>Direct messages</h2>
            <span className="nav-count">{directs.length}</span>
          </div>
          <nav aria-label="Direct messages">
            {directs.length === 0 ? <p className="nav-empty">No conversations yet</p> : directs.map((direct) => {
              const online = presence.find((user) => user.username === direct.peer_username)?.connected === true;
              const name = peerName(direct.peer_username);
              return (
                <NavItem
                  key={direct.id}
                  active={activeRoomId === direct.id}
                  unread={unreadCount(direct.id)}
                  onClick={() => navigate(direct.id)}
                  title={direct.peer_username}
                  icon={<span className={`presence-dot ${online ? "is-online" : ""}`} role="img" aria-label={online ? "Online" : "Offline"} />}
                  label={<PrivacyBlur>{name ?? shortAccountId(direct.peer_username)}</PrivacyBlur>}
                  accessibleName={direct.peer_username}
                />
              );
            })}
          </nav>
        </div>

        <div className="nav-section">
          <div className="nav-section-title">
            <h2>People</h2>
            <span className="nav-count" title="Online now">{peers.filter((user) => user.connected).length} online</span>
          </div>
          <nav aria-label="People">
            {peers.length === 0 ? <p className="nav-empty">No one else is on this node yet</p> : null}
            {peers.length > 0 && newPeers.length === 0 ? <p className="nav-empty">You have a conversation with everyone</p> : null}
            {newPeers.map((user) => (
              <button
                type="button"
                key={user.username}
                className="nav-item start-direct"
                title={`Message ${user.username}`}
                aria-label={`Message ${user.username}`}
                onClick={() => { onOpenDirect(user.username); onClose(); }}
              >
                <span className={`presence-dot ${user.connected ? "is-online" : ""}`} aria-hidden="true" />
                <span className="nav-label"><PrivacyBlur>{peerName(user.username) ?? shortAccountId(user.username)}</PrivacyBlur></span>
                <MessageCirclePlus className="nav-trailing" size={15} aria-hidden="true" />
              </button>
            ))}
          </nav>
        </div>
      </div>

      <footer className="sidebar-account">
        <div className="account-card" title={username}>
          <span className="avatar" aria-hidden="true">{accountInitials(displayName ?? username)}</span>
          <span className="account-text">
            <PrivacyBlur className="account-name">{displayName ?? shortAccountId(username)}</PrivacyBlur>
            <span className="account-meta" title="You are signed out after this much inactivity">Idle timeout {formatDuration(remainingSessionSec)}</span>
          </span>
        </div>
        <div className="account-actions">
          {canLock ? <IconButton label="Lock now" onClick={onLock}><LockKeyhole size={17} /></IconButton> : null}
          <IconButton label="Settings" onClick={() => { onOpenSettings(); onClose(); }}><Settings size={17} /></IconButton>
          <IconButton label="Sign out" onClick={onLogout}><LogOut size={17} /></IconButton>
        </div>
      </footer>
    </aside>
  );
}

function NavItem({ active, unread, onClick, icon, label, title, accessibleName }: {
  active: boolean;
  unread: number;
  onClick: () => void;
  icon: React.ReactNode;
  label: React.ReactNode;
  title?: string;
  accessibleName?: string;
}) {
  return (
    <button
      type="button"
      className={`nav-item ${active ? "is-active" : ""}`}
      aria-current={active ? "page" : undefined}
      aria-label={accessibleName ? `${accessibleName}${unread > 0 ? `, ${unread} unread` : ""}` : undefined}
      title={title}
      onClick={onClick}
    >
      {icon}
      <span className="nav-label">{label}</span>
      {unread > 0 ? <span className="unread-badge" aria-label={`${unread} unread`}>{Math.min(unread, 99)}</span> : null}
    </button>
  );
}

function formatDuration(seconds: number): string {
  const safe = Math.max(0, Math.floor(seconds));
  const minutes = Math.floor(safe / 60);
  return `${minutes}:${String(safe % 60).padStart(2, "0")}`;
}

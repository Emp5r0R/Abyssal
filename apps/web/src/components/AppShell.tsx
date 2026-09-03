import {
  Activity,
  DoorOpen,
  Hash,
  LockKeyhole,
  Menu,
  MessageCircle,
  Plus,
  Radio,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  UserRound,
  UsersRound,
  X,
} from "lucide-react";
import { useState } from "react";
import type { ChatMessage, ConnectionState, DirectRecord, PresenceUser, RoomRecord } from "../domain/types";
import { Brand, Dialog, Field, IconButton } from "./Ui";
import { PrivacyBlur } from "./PrivacyBlur";

interface AppShellProps {
  username: string;
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
  onOpenRoom: (chatId: string | null) => void;
  onOpenDirect: (username: string) => void;
  onCreateRoom: () => void;
  onDeleteRoom: (chatId: string) => void;
  pendingRoomJoins?: Array<{ requestId: string; roomId: string; username: string }>;
  pendingRoomLeaves?: Array<{ requestId: string; roomId: string; username: string }>;
  onJoinRoom?: (roomId: string) => boolean;
  onAcceptRoomJoin?: (requestId: string) => Promise<boolean>;
  onRejectRoomJoin?: (requestId: string) => boolean;
  onLeaveRoom?: (roomId: string) => boolean;
  onAcceptRoomLeave?: (requestId: string) => Promise<boolean>;
  onRejectRoomLeave?: (requestId: string) => boolean;
  onLock: () => void;
  onLogout: () => void;
  onWipe: () => void;
  children?: React.ReactNode;
}

export function AppShell({
  username,
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
  onOpenRoom,
  onOpenDirect,
  onCreateRoom,
  onDeleteRoom,
  pendingRoomJoins = [],
  pendingRoomLeaves = [],
  onJoinRoom = () => false,
  onAcceptRoomJoin = async () => false,
  onRejectRoomJoin = () => false,
  onLeaveRoom = () => false,
  onAcceptRoomLeave = async () => false,
  onRejectRoomLeave = () => false,
  onLock,
  onLogout,
  onWipe,
  children,
}: AppShellProps) {
  const [mobileMenu, setMobileMenu] = useState(false);
  const [confirmWipe, setConfirmWipe] = useState(false);
  const ownedRooms = rooms.filter((room) => room.owner_username === username).length;
  const activeUsers = presence.filter((user) => user.connected);
  const directoryCheckpoint = presence[0]?.directory_digest;

  return (
    <main className={`app-shell ${activeRoomId ? "has-active-room" : ""}`}>
      <header className="mobile-topbar">
        <Brand compact />
        <IconButton label="Open rooms" onClick={() => setMobileMenu(true)}><Menu size={21} /></IconButton>
      </header>

      <aside className={`sidebar ${mobileMenu ? "is-open" : ""}`}>
        <div className="sidebar-head">
          <Brand compact />
          <IconButton className="mobile-only" label="Close rooms" onClick={() => setMobileMenu(false)}><X size={19} /></IconButton>
        </div>

        <button className="identity-row" type="button" onClick={() => onOpenRoom(null)}>
          <div className="identity-avatar"><UserRound size={19} /></div>
          <div><PrivacyBlur><strong>{username}</strong></PrivacyBlur><span>{shortNode(nodeId)}</span></div>
          <span className={`connection-dot state-${connection}`} title={connection} />
        </button>

        <div className="sidebar-section-title">
          <span>ROOMS</span>
          <span>{ownedRooms}/{maxRooms}</span>
          <IconButton label="Create room" disabled={ownedRooms >= maxRooms || connection !== "connected"} onClick={onCreateRoom}><Plus size={18} /></IconButton>
        </div>

        <nav className="room-nav" aria-label="Rooms">
          {rooms.length === 0 ? <div className="sidebar-empty">No rooms</div> : rooms.map((room) => {
            const unread = (messages[room.id] ?? []).filter((message) => !message.mine && message.readAtMs === undefined).length;
            return (
              <button
                type="button"
                key={room.id}
                className={activeRoomId === room.id ? "is-active" : ""}
                onClick={() => { onOpenRoom(room.id); setMobileMenu(false); }}
              >
                <Hash size={17} />
                <PrivacyBlur>{room.name}</PrivacyBlur>
                {unread > 0 ? <strong>{Math.min(unread, 99)}</strong> : null}
              </button>
            );
          })}
        </nav>

        <div className="sidebar-section-title direct-title">
          <span>DIRECT</span>
          <span>{directs.length}</span>
        </div>

        <nav className="direct-nav" aria-label="Direct messages">
          {directs.map((direct) => {
            const unread = (messages[direct.id] ?? []).filter((message) => !message.mine && message.readAtMs === undefined).length;
            const online = presence.find((user) => user.username === direct.peer_username)?.connected === true;
            return (
              <button
                type="button"
                key={direct.id}
                className={activeRoomId === direct.id ? "is-active" : ""}
                onClick={() => { onOpenRoom(direct.id); setMobileMenu(false); }}
              >
                <span className={`direct-status ${online ? "is-online" : ""}`} />
                <PrivacyBlur>{direct.peer_username}</PrivacyBlur>
                {unread > 0 ? <strong>{Math.min(unread, 99)}</strong> : null}
              </button>
            );
          })}
          {presence
            .filter((user) => user.username !== username && !directs.some((direct) => direct.peer_username === user.username))
            .map((user) => (
              <button
                type="button"
                key={user.username}
                className="start-direct"
                onClick={() => { onOpenDirect(user.username); setMobileMenu(false); }}
              >
                <MessageCircle size={15} />
                <PrivacyBlur>{user.username}</PrivacyBlur>
                <small>{user.connected ? "ONLINE" : "OFFLINE"}</small>
              </button>
            ))}
          {presence.filter((user) => user.username !== username).length === 0 ? (
            <div className="sidebar-empty">No peers</div>
          ) : null}
        </nav>

        <div className="sidebar-session">
          <div><Activity size={15} /><span>SESSION</span><strong>{formatDuration(remainingSessionSec)}</strong></div>
          <progress className="session-meter" max={sessionTimeoutSec} value={remainingSessionSec} aria-label="Session time remaining" />
          {directoryCheckpoint ? (
            <div className="directory-checkpoint" title={`Directory checkpoint ${directoryCheckpoint}`}>
              <ShieldCheck size={14} /><span>DIRECTORY</span><strong>{shortCheckpoint(directoryCheckpoint)}</strong>
            </div>
          ) : null}
        </div>

        <div className="sidebar-actions">
          <IconButton label="Privacy cover" onClick={onLock}><LockKeyhole size={19} /></IconButton>
          <IconButton label="Wipe relay" onClick={() => setConfirmWipe(true)}><ShieldAlert size={19} /></IconButton>
          <IconButton label="Log out" onClick={onLogout}><DoorOpen size={19} /></IconButton>
        </div>
      </aside>

      <section className="workspace">
        {children ?? (
          <Dashboard
            username={username}
            rooms={rooms}
            directs={directs}
            maxRooms={maxRooms}
            connection={connection}
            onOpenRoom={onOpenRoom}
            onCreateRoom={onCreateRoom}
            onDeleteRoom={onDeleteRoom}
            pendingRoomJoins={pendingRoomJoins}
            pendingRoomLeaves={pendingRoomLeaves}
            onJoinRoom={onJoinRoom}
            onAcceptRoomJoin={onAcceptRoomJoin}
            onRejectRoomJoin={onRejectRoomJoin}
            onLeaveRoom={onLeaveRoom}
            onAcceptRoomLeave={onAcceptRoomLeave}
            onRejectRoomLeave={onRejectRoomLeave}
          />
        )}
      </section>

      <aside className="presence-rail">
        <header><UsersRound size={17} /><span>CONNECTED</span><strong>{activeUsers.length}</strong></header>
        <div className="presence-list">
          {presence.map((user) => (
            <button
              type="button"
              key={user.username}
              className={user.connected ? "is-online" : ""}
              disabled={user.username === username}
              onClick={() => onOpenDirect(user.username)}
              title={user.username === username ? "Current account" : "Open direct conversation"}
            >
              <span className="presence-avatar"><PrivacyBlur>{initials(user.username)}</PrivacyBlur></span>
              <div><PrivacyBlur><strong>{user.username}</strong></PrivacyBlur><span>{user.connected ? "ONLINE" : "OFFLINE"}</span></div>
              {user.username === username ? <i /> : <MessageCircle size={14} />}
            </button>
          ))}
        </div>
        <footer><Radio size={14} /><span>LIVE PRESENCE</span></footer>
      </aside>

      {confirmWipe ? (
        <Dialog
          title="Wipe relay memory?"
          description="Accounts, sessions, rooms, pending frames, and attachments disappear immediately."
          actions={
            <>
              <button className="secondary-button" type="button" onClick={() => setConfirmWipe(false)}>CANCEL</button>
              <button className="danger-button" type="button" onClick={() => { setConfirmWipe(false); onWipe(); }}>WIPE NOW</button>
            </>
          }
        >
          <div className="destructive-summary"><ShieldAlert size={26} /><span>Relay restart and new invite capsules are required after wipe.</span></div>
        </Dialog>
      ) : null}
    </main>
  );
}

function Dashboard({
  username,
  rooms,
  directs,
  maxRooms,
  connection,
  onOpenRoom,
  onCreateRoom,
  onDeleteRoom,
  pendingRoomJoins,
  pendingRoomLeaves,
  onJoinRoom,
  onAcceptRoomJoin,
  onRejectRoomJoin,
  onLeaveRoom,
  onAcceptRoomLeave,
  onRejectRoomLeave,
}: {
  username: string;
  rooms: RoomRecord[];
  directs: DirectRecord[];
  maxRooms: number;
  connection: ConnectionState;
  onOpenRoom: (id: string) => void;
  onCreateRoom: () => void;
  onDeleteRoom: (id: string) => void;
  pendingRoomJoins: Array<{ requestId: string; roomId: string; username: string }>;
  pendingRoomLeaves: Array<{ requestId: string; roomId: string; username: string }>;
  onJoinRoom: (roomId: string) => boolean;
  onAcceptRoomJoin: (requestId: string) => Promise<boolean>;
  onRejectRoomJoin: (requestId: string) => boolean;
  onLeaveRoom: (roomId: string) => boolean;
  onAcceptRoomLeave: (requestId: string) => Promise<boolean>;
  onRejectRoomLeave: (requestId: string) => boolean;
}) {
  const owned = rooms.filter((room) => room.owner_username === username).length;
  const [joinId, setJoinId] = useState("");
  const ownerLeaveRequests = pendingRoomLeaves.filter((request) =>
    rooms.some((room) => room.id === request.roomId && room.owner_username === username && request.username !== username),
  );
  const ownLeaveRequests = pendingRoomLeaves.filter((request) => request.username === username);
  return (
    <section className="dashboard">
      <header className="dashboard-header">
        <div><span className="eyebrow"><Radio size={14} /> RELAY CATALOG</span><h1>Rooms</h1></div>
        <button className="primary-button" type="button" disabled={owned >= maxRooms || connection !== "connected"} onClick={onCreateRoom}><Plus size={17} /> CREATE ROOM</button>
      </header>

      <div className="dashboard-metrics">
        <div><span>AVAILABLE</span><strong>{rooms.length}</strong></div>
        <div><span>OWNED</span><strong>{owned}/{maxRooms}</strong></div>
        <div><span>RELAY</span><strong className={`text-${connection}`}>{connection.toUpperCase()}</strong></div>
      </div>

      <form className="room-join-form" onSubmit={(event) => { event.preventDefault(); if (onJoinRoom(joinId.trim())) setJoinId(""); }}>
        <Field label="Join room ID" value={joinId} maxLength={128} placeholder="forum_..." onChange={(event) => setJoinId(event.target.value)} />
        <button className="secondary-button" type="submit" disabled={connection !== "connected" || !joinId.trim()}>JOIN</button>
      </form>

      {pendingRoomJoins.length > 0 ? <div className="pending-room-joins" aria-label="Pending room joins">
        {pendingRoomJoins.map((request) => <div key={request.requestId}>
          <span><PrivacyBlur><strong>{request.username}</strong></PrivacyBlur><small>{request.roomId}</small></span>
          <button className="secondary-button" type="button" onClick={() => void onAcceptRoomJoin(request.requestId)}>ACCEPT</button>
          <button className="danger-button" type="button" onClick={() => onRejectRoomJoin(request.requestId)}>REJECT</button>
        </div>)}
      </div> : null}

      {ownerLeaveRequests.length > 0 ? <div className="pending-room-joins" aria-label="Pending room leaves">
        {ownerLeaveRequests.map((request) => <div key={request.requestId}>
          <span><PrivacyBlur><strong>{request.username}</strong></PrivacyBlur><small>{request.roomId}</small></span>
          <button className="danger-button" type="button" onClick={() => void onAcceptRoomLeave(request.requestId)}>REMOVE</button>
          <button className="secondary-button" type="button" onClick={() => onRejectRoomLeave(request.requestId)}>KEEP</button>
        </div>)}
      </div> : null}
      {ownLeaveRequests.length > 0 ? <div className="pending-room-joins" aria-label="Leave requests pending">
        {ownLeaveRequests.map((request) => <div key={request.requestId}>
          <span><strong>LEAVE REQUEST PENDING</strong><small>{request.roomId}</small></span>
        </div>)}
      </div> : null}

      <div className="dashboard-section-heading">
        <div><MessageCircle size={16} /><span>DIRECT MESSAGES</span></div>
        <strong>{directs.length}</strong>
      </div>

      <div className="direct-dashboard" role="list" aria-label="Direct messages">
        {directs.length === 0 ? (
          <div className="direct-empty">Select a peer from the Direct list to begin.</div>
        ) : directs.map((direct) => (
            <button type="button" key={direct.id} onClick={() => onOpenRoom(direct.id)} role="listitem">
              <span className="presence-avatar"><PrivacyBlur>{initials(direct.peer_username)}</PrivacyBlur></span>
              <span><PrivacyBlur><strong>{direct.peer_username}</strong></PrivacyBlur><small>DIRECT</small></span>
              <MessageCircle size={16} />
            </button>
          ))}
      </div>

      <div className="room-table" role="list">
        {rooms.length === 0 ? (
          <div className="empty-dashboard">
            <Hash size={30} />
            <strong>NO ROOMS</strong>
            <span>Create first room when relay is connected.</span>
          </div>
        ) : rooms.map((room) => {
          const owner = room.owner_username === username;
          return (
            <div className="room-row" key={room.id} role="listitem">
              <button className="room-row-open" type="button" onClick={() => onOpenRoom(room.id)} aria-label={`Open room ${room.name}`}>
                <span className="room-row-icon"><Hash size={20} /></span>
                <span className="room-row-main">
                  <PrivacyBlur><strong>{room.name}</strong></PrivacyBlur>
                  <PrivacyBlur>{room.owner_username ? `OWNER ${room.owner_username}` : "NODE ROOM"}</PrivacyBlur>
                </span>
                <span className="room-policy">{room.self_destruct_timer_sec === 0 ? "NEVER" : `${room.self_destruct_timer_sec}s`}</span>
                <span className="room-media">{[room.allow_images && "IMG", room.allow_videos && "VID", room.allow_files && "FILE"].filter(Boolean).join(" · ") || "TEXT"}</span>
              </button>
              {owner ? (
                <IconButton label="Delete room" onClick={() => onDeleteRoom(room.id)}><Trash2 size={17} /></IconButton>
              ) : (
                <span className="room-row-actions">
                  <PrivacyBlur className="room-owner">{room.owner_username || "NODE"}</PrivacyBlur>
                  <IconButton label="Leave room" onClick={() => onLeaveRoom(room.id)}><DoorOpen size={17} /></IconButton>
                </span>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
}

function shortNode(nodeId: string): string {
  return nodeId.length > 24 ? `${nodeId.slice(0, 21)}...` : nodeId;
}

function initials(username: string): string {
  return username.slice(0, 2).toUpperCase();
}

function formatDuration(seconds: number): string {
  const minutes = Math.floor(seconds / 60);
  const rest = seconds % 60;
  return `${String(minutes).padStart(2, "0")}:${String(rest).padStart(2, "0")}`;
}

function shortCheckpoint(value: string): string {
  return `${value.slice(0, 8)}...${value.slice(-4)}`;
}

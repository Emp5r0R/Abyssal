import { DoorOpen, Globe, Hash, KeyRound, MessageCircle, Plus, Trash2, WifiOff } from "lucide-react";
import { useState } from "react";
import type { ConnectionState, DirectRecord, PresenceUser, RoomRecord } from "../domain/types";
import type { PublicRoomSummary } from "../transport/mlsWire";
import { connectionLabel, connectionNotice } from "./connectionCopy";
import { PrivacyBlur } from "./PrivacyBlur";
import { Field, IconButton } from "./Ui";

type RoomRequest = { requestId: string; roomId: string; username: string };

export interface HomeDashboardProps {
  username: string;
  displayName?: string;
  rooms: RoomRecord[];
  publicRooms: PublicRoomSummary[];
  directs: DirectRecord[];
  presence: PresenceUser[];
  maxRooms: number;
  connection: ConnectionState;
  onOpenRoom: (id: string) => void;
  onCreateRoom: () => void;
  onDeleteRoom: (id: string) => void;
  pendingRoomJoins: RoomRequest[];
  pendingRoomLeaves: RoomRequest[];
  onJoinRoom: (roomId: string) => boolean;
  onAcceptRoomJoin: (requestId: string) => Promise<boolean>;
  onRejectRoomJoin: (requestId: string) => boolean;
  onLeaveRoom: (roomId: string) => boolean;
  onAcceptRoomLeave: (requestId: string) => Promise<boolean>;
  onRejectRoomLeave: (requestId: string) => boolean;
}

/** Landing view: connection state, pending owner decisions, rooms, discovery, and conversations. */
export function HomeDashboard({
  username,
  displayName,
  rooms,
  publicRooms,
  directs,
  presence,
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
}: HomeDashboardProps) {
  const owned = rooms.filter((room) => room.owner_username === username).length;
  const connected = connection === "connected";
  const notice = connectionNotice(connection);
  const onlinePeers = presence.filter((user) => user.connected && user.username !== username).length;
  const ownerLeaveRequests = pendingRoomLeaves.filter((request) =>
    rooms.some((room) => room.id === request.roomId && room.owner_username === username && request.username !== username),
  );
  const ownLeaveRequests = pendingRoomLeaves.filter((request) => request.username === username);

  return (
    <section className="dashboard">
      <header className="dashboard-header">
        <div>
          <span className={`status-chip state-${connection}`}><i />{connectionLabel(connection)}</span>
          <h1>Home</h1>
          <p className="dashboard-subtitle">
            Signed in as <PrivacyBlur><strong>{displayName ?? username}</strong></PrivacyBlur>
            {" · "}{onlinePeers === 1 ? "1 person online" : `${onlinePeers} people online`}
          </p>
        </div>
        <button
          className="primary-button"
          type="button"
          disabled={owned >= maxRooms || !connected}
          title={owned >= maxRooms ? `You own the maximum of ${maxRooms} rooms` : undefined}
          onClick={onCreateRoom}
        ><Plus size={17} /> NEW ROOM</button>
      </header>

      {notice ? <div className={`dashboard-banner state-${connection}`} role="status"><WifiOff size={16} /><span>{notice}</span></div> : null}

      <div className="dashboard-body">
        <RoomRequests
          pendingRoomJoins={pendingRoomJoins}
          ownerLeaveRequests={ownerLeaveRequests}
          ownLeaveRequests={ownLeaveRequests}
          onAcceptRoomJoin={onAcceptRoomJoin}
          onRejectRoomJoin={onRejectRoomJoin}
          onAcceptRoomLeave={onAcceptRoomLeave}
          onRejectRoomLeave={onRejectRoomLeave}
        />

        <section className="dashboard-card" aria-labelledby="home-rooms-title">
          <header className="dashboard-card-header">
            <h2 id="home-rooms-title"><Hash size={16} />Your rooms</h2>
            <span>{owned} of {maxRooms} owned</span>
          </header>
          <div className="room-table" role="list">
            {rooms.length === 0 ? (
              <div className="empty-dashboard">
                <strong>No rooms yet</strong>
                <span>{connected ? "Create a room or join one by ID." : "Rooms can be created once the relay is connected."}</span>
              </div>
            ) : rooms.map((room) => (
              <RoomRow key={room.id} room={room} owner={room.owner_username === username} onOpenRoom={onOpenRoom} onDeleteRoom={onDeleteRoom} onLeaveRoom={onLeaveRoom} />
            ))}
          </div>
        </section>

        <JoinRooms rooms={rooms} publicRooms={publicRooms} connected={connected} onJoinRoom={onJoinRoom} />

        <section className="dashboard-card" aria-labelledby="home-directs-title">
          <header className="dashboard-card-header">
            <h2 id="home-directs-title"><MessageCircle size={16} />Direct messages</h2>
            <span>{directs.length}</span>
          </header>
          <div className="direct-dashboard" role="list" aria-label="Direct conversations">
            {directs.length === 0 ? (
              <p className="catalog-empty">Select a peer under DIRECT MESSAGES in the sidebar to start a conversation.</p>
            ) : directs.map((direct) => {
              const online = presence.find((user) => user.username === direct.peer_username)?.connected === true;
              return (
                <button type="button" key={direct.id} onClick={() => onOpenRoom(direct.id)} role="listitem">
                  <span className="presence-avatar"><PrivacyBlur>{initials(direct.peer_username)}</PrivacyBlur></span>
                  <span><PrivacyBlur><strong>{direct.peer_username}</strong></PrivacyBlur><small>{online ? "Online" : "Offline"}</small></span>
                  <MessageCircle size={16} />
                </button>
              );
            })}
          </div>
        </section>
      </div>
    </section>
  );
}

function RoomRow({ room, owner, onOpenRoom, onDeleteRoom, onLeaveRoom }: {
  room: RoomRecord;
  owner: boolean;
  onOpenRoom: (id: string) => void;
  onDeleteRoom: (id: string) => void;
  onLeaveRoom: (id: string) => boolean;
}) {
  const media = [room.allow_images && "Images", room.allow_videos && "Videos", room.allow_files && "Files"].filter(Boolean).join(" · ") || "Text only";
  return (
    <div className="room-row" role="listitem">
      <button className="room-row-open" type="button" onClick={() => onOpenRoom(room.id)} aria-label={`Open room ${room.name}`}>
        <span className="room-row-icon"><Hash size={18} /></span>
        <span className="room-row-main">
          <PrivacyBlur><strong>{room.name}</strong></PrivacyBlur>
          <PrivacyBlur>{owner ? "OWNER You" : room.owner_username ? `OWNER ${room.owner_username}` : "NODE ROOM"}</PrivacyBlur>
        </span>
        <span className="room-policy" title="Messages disappear this long after they are read">
          {room.self_destruct_timer_sec === 0 ? "No timer" : `${formatTimer(room.self_destruct_timer_sec)} after read`}
        </span>
        <span className="room-media">{media}</span>
      </button>
      {owner ? (
        <IconButton label="Delete room" onClick={() => onDeleteRoom(room.id)}><Trash2 size={17} /></IconButton>
      ) : (
        <IconButton label="Leave room" onClick={() => onLeaveRoom(room.id)}><DoorOpen size={17} /></IconButton>
      )}
    </div>
  );
}

function JoinRooms({ rooms, publicRooms, connected, onJoinRoom }: {
  rooms: RoomRecord[];
  publicRooms: PublicRoomSummary[];
  connected: boolean;
  onJoinRoom: (roomId: string) => boolean;
}) {
  const [joinId, setJoinId] = useState("");
  const [actionNotice, setActionNotice] = useState<string | null>(null);
  const joinedRoomIds = new Set(rooms.map((room) => room.id));
  const discoverable = publicRooms.filter((room) => !joinedRoomIds.has(room.room_id));
  const requestJoin = (roomId: string) => {
    if (onJoinRoom(roomId)) {
      setJoinId("");
      setActionNotice("Join request sent. The room owner must approve it.");
    } else {
      setActionNotice("Room join request could not be sent.");
    }
  };
  return (
    <section className="dashboard-card" aria-labelledby="home-join-title">
      <header className="dashboard-card-header">
        <h2 id="home-join-title"><Globe size={16} />Join a room</h2>
        <span>{discoverable.length} public</span>
      </header>
      <form className="room-join-form" onSubmit={(event) => { event.preventDefault(); requestJoin(joinId.trim()); }}>
        <Field
          label="Join room ID"
          value={joinId}
          maxLength={128}
          placeholder="forum_…"
          hint="Private rooms are hidden. Ask the owner for the exact room ID."
          onChange={(event) => { setActionNotice(null); setJoinId(event.target.value); }}
        />
        <button className="secondary-button" type="submit" disabled={!connected || !joinId.trim()}><KeyRound size={15} /> JOIN</button>
      </form>
      {actionNotice ? <p className="form-feedback" role="status" aria-live="polite">{actionNotice}</p> : null}
      <div className="public-room-catalog">
        <h3 id="public-room-catalog-title">Public rooms</h3>
        {publicRooms.length === 0 ? (
          <p className="catalog-empty">No public rooms on this node yet.</p>
        ) : discoverable.length === 0 ? (
          <p className="catalog-empty">You have joined every public room.</p>
        ) : (
          <div className="public-room-list" role="list" aria-labelledby="public-room-catalog-title">
            {discoverable.map((room) => (
              <div className="public-room-row" key={room.room_id} role="listitem">
                <div className="public-room-summary">
                  <PrivacyBlur><strong>{room.room_id}</strong></PrivacyBlur>
                  <PrivacyBlur><small>OWNER {room.owner_username}</small></PrivacyBlur>
                </div>
                <button
                  className="secondary-button"
                  type="button"
                  disabled={!connected}
                  aria-label={`Join public room ${room.room_id}`}
                  onClick={() => requestJoin(room.room_id)}
                >JOIN</button>
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}

function RoomRequests({
  pendingRoomJoins,
  ownerLeaveRequests,
  ownLeaveRequests,
  onAcceptRoomJoin,
  onRejectRoomJoin,
  onAcceptRoomLeave,
  onRejectRoomLeave,
}: {
  pendingRoomJoins: RoomRequest[];
  ownerLeaveRequests: RoomRequest[];
  ownLeaveRequests: RoomRequest[];
  onAcceptRoomJoin: (requestId: string) => Promise<boolean>;
  onRejectRoomJoin: (requestId: string) => boolean;
  onAcceptRoomLeave: (requestId: string) => Promise<boolean>;
  onRejectRoomLeave: (requestId: string) => boolean;
}) {
  if (pendingRoomJoins.length + ownerLeaveRequests.length + ownLeaveRequests.length === 0) return null;
  return (
    <section className="dashboard-card is-attention" aria-labelledby="home-requests-title">
      <header className="dashboard-card-header"><h2 id="home-requests-title">Requests</h2></header>
      {pendingRoomJoins.length > 0 ? <div className="pending-room-joins" aria-label="Pending room joins">
        {pendingRoomJoins.map((request) => <div key={request.requestId}>
          <span><PrivacyBlur><strong>{request.username}</strong></PrivacyBlur><small>wants to join {request.roomId}</small></span>
          <button className="secondary-button" type="button" onClick={() => void onAcceptRoomJoin(request.requestId)}>ACCEPT</button>
          <button className="danger-button" type="button" onClick={() => onRejectRoomJoin(request.requestId)}>REJECT</button>
        </div>)}
      </div> : null}
      {ownerLeaveRequests.length > 0 ? <div className="pending-room-joins" aria-label="Pending room leaves">
        {ownerLeaveRequests.map((request) => <div key={request.requestId}>
          <span><PrivacyBlur><strong>{request.username}</strong></PrivacyBlur><small>wants to leave {request.roomId}</small></span>
          <button className="danger-button" type="button" onClick={() => void onAcceptRoomLeave(request.requestId)}>REMOVE</button>
          <button className="secondary-button" type="button" onClick={() => onRejectRoomLeave(request.requestId)}>KEEP</button>
        </div>)}
      </div> : null}
      {ownLeaveRequests.length > 0 ? <div className="pending-room-joins" aria-label="Leave requests pending">
        {ownLeaveRequests.map((request) => <div key={request.requestId}>
          <span><strong>LEAVE REQUEST PENDING</strong><small>{request.roomId}</small></span>
        </div>)}
      </div> : null}
    </section>
  );
}

function initials(username: string): string {
  return username.replace(/^acct_/u, "").slice(0, 2).toUpperCase();
}

function formatTimer(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86_400) return `${Math.round(seconds / 3600)}h`;
  return `${Math.round(seconds / 86_400)}d`;
}

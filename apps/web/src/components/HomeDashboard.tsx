import { DoorOpen, Globe, Hash, LockKeyhole, MessageCircle, Plus, Trash2, Users, WifiOff } from "lucide-react";
import { useState } from "react";
import { accountInitials, roomLabel, shortAccountId, shortRoomId } from "../domain/displayLabels";
import type { ConnectionState, DirectRecord, PresenceUser, RoomRecord } from "../domain/types";
import type { PublicRoomSummary } from "../transport/mlsWire";
import { connectionNotice } from "./connectionCopy";
import { PrivacyBlur } from "./PrivacyBlur";
import { Dialog, Field, IconButton } from "./Ui";

type RoomRequest = { requestId: string; roomId: string; username: string };

export interface HomeDashboardProps {
  username: string;
  displayName?: string;
  rooms: RoomRecord[];
  publicRooms: PublicRoomSummary[];
  directs: DirectRecord[];
  presence: PresenceUser[];
  displayNames: ReadonlyMap<string, string>;
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

export const PUBLIC_JOIN_NOTICE = "Joining. Public rooms let you in automatically as soon as the owner is online.";
export const PRIVATE_JOIN_NOTICE = "Join request sent. The room owner must approve it.";
export const JOIN_FAILED_NOTICE = "The join request could not be sent. Check the room ID and your connection.";

/** Landing view: connection state, pending owner decisions, rooms, discovery, and conversations. */
export function HomeDashboard({
  username,
  displayName,
  rooms,
  publicRooms,
  directs,
  presence,
  displayNames,
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
  const [confirmDelete, setConfirmDelete] = useState<RoomRecord | null>(null);
  const owned = rooms.filter((room) => room.owner_username === username).length;
  const connected = connection === "connected";
  const notice = connectionNotice(connection);
  const onlinePeers = presence.filter((user) => user.connected && user.username !== username).length;
  const roomName = (roomId: string) => {
    const room = rooms.find((candidate) => candidate.id === roomId);
    return room ? roomLabel(room) : `Room ${shortRoomId(roomId)}`;
  };
  const ownerJoinRequests = pendingRoomJoins.filter((request) =>
    rooms.some((room) => room.id === request.roomId && room.owner_username === username));
  const ownerLeaveRequests = pendingRoomLeaves.filter((request) =>
    rooms.some((room) => room.id === request.roomId && room.owner_username === username && request.username !== username),
  );
  const ownLeaveRequests = pendingRoomLeaves.filter((request) => request.username === username);
  const atRoomLimit = owned >= maxRooms;

  return (
    <section className="page">
      <header className="page-header">
        <div className="page-title">
          <h1>Home</h1>
          <p>
            Signed in as <PrivacyBlur><strong>{displayName ?? shortAccountId(username)}</strong></PrivacyBlur>
            <span aria-hidden="true"> · </span>
            {onlinePeers === 1 ? "1 person online" : `${onlinePeers} people online`}
          </p>
        </div>
        <button
          className="primary-button"
          type="button"
          disabled={atRoomLimit || !connected}
          title={atRoomLimit ? `You already own ${maxRooms} rooms, the limit on this node` : undefined}
          onClick={onCreateRoom}
        ><Plus size={17} aria-hidden="true" />New room</button>
      </header>

      {notice ? <div className={`banner state-${connection}`} role="status"><WifiOff size={16} aria-hidden="true" /><span>{notice}</span></div> : null}

      <div className="page-body">
        <RoomRequests
          ownerJoinRequests={ownerJoinRequests}
          ownerLeaveRequests={ownerLeaveRequests}
          ownLeaveRequests={ownLeaveRequests}
          displayNames={displayNames}
          roomName={roomName}
          onAcceptRoomJoin={onAcceptRoomJoin}
          onRejectRoomJoin={onRejectRoomJoin}
          onAcceptRoomLeave={onAcceptRoomLeave}
          onRejectRoomLeave={onRejectRoomLeave}
        />

        <section className="card" aria-labelledby="home-rooms-title">
          <header className="card-header">
            <h2 id="home-rooms-title"><Hash size={16} aria-hidden="true" />Your rooms</h2>
            <span className="card-meta">{owned} of {maxRooms} owned</span>
          </header>
          {rooms.length === 0 ? (
            <div className="empty-state">
              <strong>No rooms yet</strong>
              <span>{connected ? "Create a room, or join a public one below." : "Rooms can be created once the relay is connected."}</span>
            </div>
          ) : (
            <ul className="list" aria-label="Your rooms">
              {rooms.map((room) => (
                <RoomRow
                  key={room.id}
                  room={room}
                  owner={room.owner_username === username}
                  ownerName={room.owner_username ? displayNames.get(room.owner_username.toLowerCase()) : undefined}
                  onOpenRoom={onOpenRoom}
                  onDeleteRoom={() => setConfirmDelete(room)}
                  onLeaveRoom={onLeaveRoom}
                />
              ))}
            </ul>
          )}
        </section>

        <JoinRooms rooms={rooms} publicRooms={publicRooms} connected={connected} displayNames={displayNames} onJoinRoom={onJoinRoom} />

        <section className="card" aria-labelledby="home-directs-title">
          <header className="card-header">
            <h2 id="home-directs-title"><MessageCircle size={16} aria-hidden="true" />Direct messages</h2>
            <span className="card-meta">{directs.length}</span>
          </header>
          {directs.length === 0 ? (
            <div className="empty-state">
              <strong>No conversations yet</strong>
              <span>Pick someone under People in the sidebar to start one.</span>
            </div>
          ) : (
            <ul className="list" aria-label="Direct conversations">
              {directs.map((direct) => {
                const online = presence.find((user) => user.username === direct.peer_username)?.connected === true;
                const name = displayNames.get(direct.peer_username.toLowerCase());
                return (
                  <li key={direct.id}>
                    <button className="list-row" type="button" title={direct.peer_username} onClick={() => onOpenRoom(direct.id)}>
                      <span className="avatar" aria-hidden="true">{accountInitials(name ?? direct.peer_username)}</span>
                      <span className="list-row-text">
                        <PrivacyBlur className="list-row-title">{name ?? shortAccountId(direct.peer_username)}</PrivacyBlur>
                        <span className="list-row-meta">
                          <span className={`presence-dot ${online ? "is-online" : ""}`} aria-hidden="true" />
                          {online ? "Online" : "Offline"}
                        </span>
                      </span>
                      <MessageCircle className="list-row-trailing" size={16} aria-hidden="true" />
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </section>
      </div>

      {confirmDelete ? (
        <Dialog
          title="Delete this room?"
          description="Everyone loses the room and its messages. This cannot be undone."
          onClose={() => setConfirmDelete(null)}
          actions={
            <>
              <button className="secondary-button" type="button" onClick={() => setConfirmDelete(null)}>Cancel</button>
              <button className="danger-button" type="button" onClick={() => { onDeleteRoom(confirmDelete.id); setConfirmDelete(null); }}>Delete room</button>
            </>
          }
        >
          <p className="dialog-emphasis"><PrivacyBlur>{roomLabel(confirmDelete)}</PrivacyBlur></p>
        </Dialog>
      ) : null}
    </section>
  );
}

function RoomRow({ room, owner, ownerName, onOpenRoom, onDeleteRoom, onLeaveRoom }: {
  room: RoomRecord;
  owner: boolean;
  ownerName?: string;
  onOpenRoom: (id: string) => void;
  onDeleteRoom: () => void;
  onLeaveRoom: (id: string) => boolean;
}) {
  const label = roomLabel(room);
  const media = [room.allow_images && "images", room.allow_videos && "videos", room.allow_files && "files"].filter(Boolean);
  const ownerText = owner ? "You own this room" : `Owner ${ownerName ?? (room.owner_username ? shortAccountId(room.owner_username) : "unknown")}`;
  return (
    <li className="room-row">
      <button className="list-row" type="button" onClick={() => onOpenRoom(room.id)} aria-label={`Open room ${label}`}>
        <span className={`room-icon ${room.visibility === "public" ? "is-public" : ""}`} aria-hidden="true">
          {room.visibility === "public" ? <Globe size={17} /> : <Hash size={17} />}
        </span>
        <span className="list-row-text">
          <PrivacyBlur className="list-row-title">{label}</PrivacyBlur>
          <span className="list-row-meta">
            <PrivacyBlur>{ownerText}</PrivacyBlur>
            <span aria-hidden="true">·</span>
            <span>{room.visibility === "public" ? "Public" : "Private"}</span>
          </span>
        </span>
        <span className="room-policy">
          <span>{room.self_destruct_timer_sec === 0 ? "Messages stay until the session ends" : `Messages vanish ${formatTimer(room.self_destruct_timer_sec)} after reading`}</span>
          <span>{media.length === 0 ? "Text only" : `Text, ${media.join(", ")}`}</span>
        </span>
      </button>
      {owner ? (
        <IconButton label="Delete room" onClick={onDeleteRoom}><Trash2 size={17} /></IconButton>
      ) : (
        <IconButton label="Leave room" onClick={() => onLeaveRoom(room.id)}><DoorOpen size={17} /></IconButton>
      )}
    </li>
  );
}

function JoinRooms({ rooms, publicRooms, connected, displayNames, onJoinRoom }: {
  rooms: RoomRecord[];
  publicRooms: PublicRoomSummary[];
  connected: boolean;
  displayNames: ReadonlyMap<string, string>;
  onJoinRoom: (roomId: string) => boolean;
}) {
  const [joinId, setJoinId] = useState("");
  const [actionNotice, setActionNotice] = useState<string | null>(null);
  const [requested, setRequested] = useState<ReadonlySet<string>>(() => new Set());
  const joinedRoomIds = new Set(rooms.map((room) => room.id));
  const discoverable = publicRooms.filter((room) => !joinedRoomIds.has(room.room_id));
  const requestJoin = (roomId: string) => {
    if (!onJoinRoom(roomId)) {
      setActionNotice(JOIN_FAILED_NOTICE);
      return;
    }
    setJoinId("");
    setRequested((current) => new Set(current).add(roomId));
    setActionNotice(publicRooms.some((room) => room.room_id === roomId) ? PUBLIC_JOIN_NOTICE : PRIVATE_JOIN_NOTICE);
  };
  return (
    <section className="card" aria-labelledby="home-join-title">
      <header className="card-header">
        <h2 id="home-join-title"><Globe size={16} aria-hidden="true" />Join a room</h2>
        <span className="card-meta">{discoverable.length} public</span>
      </header>
      {publicRooms.length === 0 ? (
        <p className="card-note">No public rooms on this node yet.</p>
      ) : discoverable.length === 0 ? (
        <p className="card-note">You are in every public room.</p>
      ) : (
        <ul className="list" aria-label="Public rooms">
          {discoverable.map((room) => {
            const pending = requested.has(room.room_id);
            const owner = displayNames.get(room.owner_username.toLowerCase()) ?? shortAccountId(room.owner_username);
            return (
              <li className="public-room-row" key={room.room_id}>
                <span className="room-icon is-public" aria-hidden="true"><Users size={17} /></span>
                <span className="list-row-text" title={room.room_id}>
                  <span className="list-row-title">Room {shortRoomId(room.room_id)}</span>
                  <span className="list-row-meta"><PrivacyBlur>Owner {owner}</PrivacyBlur></span>
                </span>
                <button
                  className="secondary-button"
                  type="button"
                  disabled={!connected || pending}
                  aria-label={`Join public room ${room.room_id}`}
                  onClick={() => requestJoin(room.room_id)}
                >{pending ? "Joining…" : "Join"}</button>
              </li>
            );
          })}
        </ul>
      )}
      <form className="inline-form" onSubmit={(event) => { event.preventDefault(); requestJoin(joinId.trim()); }}>
        <Field
          label="Room ID"
          value={joinId}
          maxLength={128}
          autoComplete="off"
          spellCheck={false}
          placeholder="forum_…"
          hint="Private rooms are not listed. Ask the owner for the room ID."
          onChange={(event) => { setActionNotice(null); setJoinId(event.target.value); }}
        />
        <button className="secondary-button" type="submit" disabled={!connected || !joinId.trim()}><LockKeyhole size={15} aria-hidden="true" />Join by ID</button>
      </form>
      {actionNotice ? <p className="form-feedback" role="status" aria-live="polite">{actionNotice}</p> : null}
    </section>
  );
}

function RoomRequests({
  ownerJoinRequests,
  ownerLeaveRequests,
  ownLeaveRequests,
  displayNames,
  roomName,
  onAcceptRoomJoin,
  onRejectRoomJoin,
  onAcceptRoomLeave,
  onRejectRoomLeave,
}: {
  ownerJoinRequests: RoomRequest[];
  ownerLeaveRequests: RoomRequest[];
  ownLeaveRequests: RoomRequest[];
  displayNames: ReadonlyMap<string, string>;
  roomName: (roomId: string) => string;
  onAcceptRoomJoin: (requestId: string) => Promise<boolean>;
  onRejectRoomJoin: (requestId: string) => boolean;
  onAcceptRoomLeave: (requestId: string) => Promise<boolean>;
  onRejectRoomLeave: (requestId: string) => boolean;
}) {
  if (ownerJoinRequests.length + ownerLeaveRequests.length + ownLeaveRequests.length === 0) return null;
  const person = (username: string) => displayNames.get(username.toLowerCase()) ?? shortAccountId(username);
  return (
    <section className="card is-attention" aria-labelledby="home-requests-title">
      <header className="card-header"><h2 id="home-requests-title">Needs your attention</h2></header>
      <ul className="list">
        {ownerJoinRequests.map((request) => (
          <li className="request-row" key={request.requestId} aria-label="Join request">
            <span className="list-row-text" title={request.username}>
              <PrivacyBlur className="list-row-title">{person(request.username)}</PrivacyBlur>
              <span className="list-row-meta"><span>wants to join <PrivacyBlur>{roomName(request.roomId)}</PrivacyBlur></span></span>
            </span>
            <span className="request-actions">
              <button className="secondary-button" type="button" onClick={() => onRejectRoomJoin(request.requestId)}>Decline</button>
              <button className="primary-button" type="button" onClick={() => void onAcceptRoomJoin(request.requestId)}>Accept</button>
            </span>
          </li>
        ))}
        {ownerLeaveRequests.map((request) => (
          <li className="request-row" key={request.requestId} aria-label="Leave request">
            <span className="list-row-text" title={request.username}>
              <PrivacyBlur className="list-row-title">{person(request.username)}</PrivacyBlur>
              <span className="list-row-meta"><span>wants to leave <PrivacyBlur>{roomName(request.roomId)}</PrivacyBlur></span></span>
            </span>
            <span className="request-actions">
              <button className="secondary-button" type="button" onClick={() => onRejectRoomLeave(request.requestId)}>Keep</button>
              <button className="danger-button" type="button" onClick={() => void onAcceptRoomLeave(request.requestId)}>Remove</button>
            </span>
          </li>
        ))}
        {ownLeaveRequests.map((request) => (
          <li className="request-row" key={request.requestId} aria-label="Your leave request">
            <span className="list-row-text">
              <span className="list-row-title">Leaving <PrivacyBlur>{roomName(request.roomId)}</PrivacyBlur></span>
              <span className="list-row-meta">Waiting for the room owner to confirm.</span>
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}

function formatTimer(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
  if (seconds < 86_400) return `${Math.round(seconds / 3600)} h`;
  return `${Math.round(seconds / 86_400)} d`;
}

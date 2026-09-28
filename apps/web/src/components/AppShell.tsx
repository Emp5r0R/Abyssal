import { Menu, ShieldAlert } from "lucide-react";
import { useState } from "react";
import type { ChatMessage, ConnectionState, DirectRecord, PresenceUser, RoomRecord } from "../domain/types";
import type { PublicRoomSummary } from "../transport/mlsWire";
import { connectionLabel } from "./connectionCopy";
import { HomeDashboard } from "./HomeDashboard";
import { Sidebar } from "./Sidebar";
import { Brand, Dialog, IconButton } from "./Ui";

interface AppShellProps {
  username: string;
  displayName?: string;
  nodeId: string;
  connection: ConnectionState;
  rooms: RoomRecord[];
  publicRooms?: PublicRoomSummary[];
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
  displayName,
  nodeId,
  connection,
  rooms,
  publicRooms = [],
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

  return (
    <main className={`app-shell ${activeRoomId ? "has-active-room" : ""}`}>
      <header className="mobile-topbar">
        <IconButton label="Open menu" onClick={() => setMobileMenu(true)}><Menu size={21} /></IconButton>
        <Brand compact />
        <span className={`status-chip state-${connection}`}><i />{connectionLabel(connection)}</span>
      </header>

      <Sidebar
        username={username}
        displayName={displayName}
        nodeId={nodeId}
        connection={connection}
        rooms={rooms}
        directs={directs}
        messages={messages}
        presence={presence}
        activeRoomId={activeRoomId}
        maxRooms={maxRooms}
        remainingSessionSec={remainingSessionSec}
        sessionTimeoutSec={sessionTimeoutSec}
        open={mobileMenu}
        onClose={() => setMobileMenu(false)}
        onNavigate={onOpenRoom}
        onOpenDirect={onOpenDirect}
        onCreateRoom={onCreateRoom}
        onLock={onLock}
        onLogout={onLogout}
        onRequestWipe={() => setConfirmWipe(true)}
      />
      {mobileMenu ? <button className="sidebar-scrim" type="button" aria-label="Close menu" onClick={() => setMobileMenu(false)} /> : null}

      <section className="workspace">
        {children ?? (
          <HomeDashboard
            username={username}
            displayName={displayName}
            rooms={rooms}
            publicRooms={publicRooms}
            directs={directs}
            presence={presence}
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

      {confirmWipe ? (
        <Dialog
          title="Wipe relay memory?"
          description="Accounts, sessions, rooms, pending frames, and attachments disappear immediately."
          onClose={() => setConfirmWipe(false)}
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

import { LockKeyhole, Menu, Search } from "lucide-react";
import { useMemo, useState } from "react";
import { displayNamesBySender } from "../domain/displayLabels";
import type { ChatMessage, ConnectionState, DirectRecord, PresenceUser, RoomRecord } from "../domain/types";
import type { PublicRoomSummary } from "../transport/mlsWire";
import { connectionLabel } from "./connectionCopy";
import { HomeDashboard } from "./HomeDashboard";
import { Sidebar } from "./Sidebar";
import { Brand, IconButton } from "./Ui";

type RoomRequest = { requestId: string; roomId: string; username: string };

interface AppShellProps {
  username: string;
  displayName?: string;
  connection: ConnectionState;
  rooms: RoomRecord[];
  publicRooms?: PublicRoomSummary[];
  directs: DirectRecord[];
  messages: Record<string, ChatMessage[]>;
  presence: PresenceUser[];
  activeRoomId: string | null;
  maxRooms: number;
  remainingSessionSec: number;
  canLock: boolean;
  onOpenRoom: (chatId: string | null) => void;
  onOpenDirect: (username: string) => void;
  onCreateRoom: () => void;
  onDeleteRoom: (chatId: string) => void;
  pendingRoomJoins?: RoomRequest[];
  pendingRoomLeaves?: RoomRequest[];
  onJoinRoom?: (roomId: string) => boolean;
  onAcceptRoomJoin?: (requestId: string) => Promise<boolean>;
  onRejectRoomJoin?: (requestId: string) => boolean;
  onLeaveRoom?: (roomId: string) => boolean;
  onAcceptRoomLeave?: (requestId: string) => Promise<boolean>;
  onRejectRoomLeave?: (requestId: string) => boolean;
  onLock: () => void;
  onOpenSettings: () => void;
  onLogout: () => void;
  /** Opens the conversation finder; on phones this replaces the Ctrl+K shortcut. */
  onSearch?: () => void;
  children?: React.ReactNode;
}

/** Two-pane workspace: navigation on the left, the open conversation or Home on the right. */
export function AppShell({
  username,
  displayName,
  connection,
  rooms,
  publicRooms = [],
  directs,
  messages,
  presence,
  activeRoomId,
  maxRooms,
  remainingSessionSec,
  canLock,
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
  onOpenSettings,
  onLogout,
  onSearch,
  children,
}: AppShellProps) {
  const [mobileMenu, setMobileMenu] = useState(false);
  const displayNames = useMemo(() => displayNamesBySender(messages), [messages]);

  return (
    <main className={`app-shell ${activeRoomId ? "has-active-room" : ""}`}>
      <header className="mobile-topbar">
        <IconButton label="Open menu" onClick={() => setMobileMenu(true)}><Menu size={20} /></IconButton>
        <Brand compact />
        <span className={`status-dot-label state-${connection}`}><i aria-hidden="true" />{connectionLabel(connection)}</span>
        {onSearch ? <IconButton label="Find a conversation" onClick={onSearch}><Search size={20} /></IconButton> : null}
        {canLock ? <IconButton label="Lock" title="Lock now" onClick={onLock}><LockKeyhole size={19} /></IconButton> : null}
      </header>

      <Sidebar
        username={username}
        displayName={displayName}
        connection={connection}
        rooms={rooms}
        directs={directs}
        messages={messages}
        presence={presence}
        displayNames={displayNames}
        activeRoomId={activeRoomId}
        maxRooms={maxRooms}
        remainingSessionSec={remainingSessionSec}
        canLock={canLock}
        open={mobileMenu}
        onClose={() => setMobileMenu(false)}
        onNavigate={onOpenRoom}
        onOpenDirect={onOpenDirect}
        onCreateRoom={onCreateRoom}
        onLock={onLock}
        onOpenSettings={onOpenSettings}
        onLogout={onLogout}
        onSearch={onSearch ? () => { setMobileMenu(false); onSearch(); } : undefined}
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
            displayNames={displayNames}
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
    </main>
  );
}

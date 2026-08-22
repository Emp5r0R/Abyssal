import { useCallback, useEffect, useRef, useState } from "react";
import { flushSync } from "react-dom";
import { AppShell } from "./components/AppShell";
import { AttachmentDialog } from "./components/AttachmentDialog";
import { ChatView } from "./components/ChatView";
import { CreateRoomDialog } from "./components/CreateRoomDialog";
import { Entrance } from "./components/Entrance";
import { MediaViewer } from "./components/MediaViewer";
import { CalculatorCover, PinSetup } from "./components/Privacy";
import type { ReactionAsset } from "./domain/reactions";
import type { ChatMessage } from "./domain/types";
import { useAbyssalSession } from "./hooks/useAbyssalSession";
import { PrivacyPinGate } from "./security/privacyPin";

export default function App() {
  const abyssal = useAbyssalSession();
  const clearPrivateView = abyssal.clearPrivateView;
  const [pinGate, setPinGate] = useState<PrivacyPinGate | null>(null);
  const [locked, setLocked] = useState(false);
  const [showCreateRoom, setShowCreateRoom] = useState(false);
  const [showAttachment, setShowAttachment] = useState(false);
  const [attachmentRetentionSec, setAttachmentRetentionSec] = useState(5);
  const [replyTarget, setReplyTarget] = useState<ChatMessage | null>(null);
  const externalPickerRef = useRef(false);
  const pinGateRef = useRef<PrivacyPinGate | null>(null);

  const destroyPinGate = useCallback(() => {
    pinGateRef.current?.destroy();
    pinGateRef.current = null;
    setPinGate(null);
  }, []);

  const clearTransientUi = useCallback(() => {
    externalPickerRef.current = false;
    setReplyTarget(null);
    setShowAttachment(false);
    setShowCreateRoom(false);
    clearPrivateView();
  }, [clearPrivateView]);

  const lockWorkspace = useCallback(() => {
    clearTransientUi();
    setLocked(true);
  }, [clearTransientUi]);

  useEffect(() => {
    const visibility = () => {
      if (!abyssal.session || document.visibilityState !== "hidden" || externalPickerRef.current) return;
      if (abyssal.retainWhenHiddenRef.current && pinGateRef.current) lockWorkspace();
      else void abyssal.logout();
    };
    const focus = () => window.setTimeout(() => { externalPickerRef.current = false; }, 500);
    document.addEventListener("visibilitychange", visibility);
    window.addEventListener("focus", focus);
    return () => {
      document.removeEventListener("visibilitychange", visibility);
      window.removeEventListener("focus", focus);
    };
  }, [abyssal, lockWorkspace]);

  useEffect(() => {
    const pageHide = () => {
      flushSync(() => {
        clearTransientUi();
        setLocked(false);
        destroyPinGate();
      });
    };
    window.addEventListener("pagehide", pageHide);
    return () => window.removeEventListener("pagehide", pageHide);
  }, [clearTransientUi, destroyPinGate]);

  useEffect(() => {
    if (!abyssal.session) {
      pinGateRef.current?.destroy();
      pinGateRef.current = null;
    }
  }, [abyssal.session]);

  const resetLocal = async () => {
    setLocked(false);
    clearTransientUi();
    destroyPinGate();
    setReplyTarget(null);
    await abyssal.logout();
  };

  if (!abyssal.session) {
    return <Entrance onLogin={abyssal.login} />;
  }

  if (!pinGate || pinGate.destroyed) {
    return (
      <div className="secure-root" onPointerDownCapture={abyssal.touchActivity} onKeyDownCapture={abyssal.touchActivity}>
        <SecureWorkspace abyssal={abyssal} replyTarget={replyTarget} setReplyTarget={setReplyTarget} onLock={lockWorkspace} setAttachmentRetentionSec={setAttachmentRetentionSec} setShowAttachment={setShowAttachment} setShowCreateRoom={setShowCreateRoom} resetLocal={resetLocal} />
        <PinSetup onComplete={async (pin, duress) => {
          const nextGate = await PrivacyPinGate.create(pin, duress);
          pinGateRef.current?.destroy();
          pinGateRef.current = nextGate;
          setPinGate(nextGate);
        }} />
      </div>
    );
  }

  if (locked) {
    return (
      <CalculatorCover
        pinGate={pinGate}
        onUnlock={() => { abyssal.touchActivity(); setLocked(false); }}
        onDuress={() => {
          abyssal.wipeRelay();
          clearTransientUi();
          destroyPinGate();
          abyssal.clearMemory();
          setLocked(false);
        }}
      />
    );
  }

  return (
    <div className="secure-root" onPointerDownCapture={abyssal.touchActivity} onKeyDownCapture={abyssal.touchActivity}>
      <SecureWorkspace abyssal={abyssal} replyTarget={replyTarget} setReplyTarget={setReplyTarget} onLock={lockWorkspace} setAttachmentRetentionSec={setAttachmentRetentionSec} setShowAttachment={setShowAttachment} setShowCreateRoom={setShowCreateRoom} resetLocal={resetLocal} />

      {showCreateRoom ? <CreateRoomDialog onCancel={() => setShowCreateRoom(false)} onCreate={abyssal.createRoom} /> : null}
      {showAttachment && abyssal.activeRoom ? (
        <AttachmentDialog
          room={abyssal.activeRoom}
          retentionSec={attachmentRetentionSec}
          onCancel={() => { externalPickerRef.current = false; setShowAttachment(false); }}
          onPickerState={(active) => { externalPickerRef.current = active; }}
          onSend={(file, options) => abyssal.sendAttachment({
            file,
            options: { ...options, readSec: attachmentRetentionSec },
            replyToId: replyTarget?.id,
          })}
        />
      ) : null}
      {abyssal.media ? <MediaViewer media={abyssal.media} onClose={abyssal.clearMedia} /> : null}
      {abyssal.notice ? <button type="button" className="notice" onClick={abyssal.clearNotice}>{abyssal.notice}</button> : null}
    </div>
  );
}

type AbyssalController = ReturnType<typeof useAbyssalSession>;

function SecureWorkspace({
  abyssal,
  replyTarget,
  setReplyTarget,
  onLock,
  setAttachmentRetentionSec,
  setShowAttachment,
  setShowCreateRoom,
  resetLocal,
}: {
  abyssal: AbyssalController;
  replyTarget: ChatMessage | null;
  setReplyTarget: (message: ChatMessage | null) => void;
  onLock: () => void;
  setAttachmentRetentionSec: (seconds: number) => void;
  setShowAttachment: (show: boolean) => void;
  setShowCreateRoom: (show: boolean) => void;
  resetLocal: () => Promise<void>;
}) {
  const session = abyssal.session;
  if (!session) return null;

  const sendGif = async (reaction: ReactionAsset, replyToId?: string, retentionSec?: number): Promise<boolean> => {
    try {
      const response = await fetch(reaction.path, { cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer" });
      if (!response.ok) return false;
      const blob = await response.blob();
      return await abyssal.sendAttachment({
        file: new File([blob], reaction.filename, { type: reaction.mimeType }),
        options: { oneTime: false, deleteAfterDownload: false, ttlSec: 0, readSec: retentionSec },
        replyToId,
        reactionShortcode: reaction.shortcode,
      });
    } catch {
      // Same vague failure surface as other attachment operations.
      return false;
    }
  };

  const openRoom = (chatId: string | null) => {
    setReplyTarget(null);
    setShowAttachment(false);
    abyssal.openRoom(chatId);
  };

  return (
    <AppShell
      username={session.username}
      nodeId={session.nodeId}
      connection={abyssal.connection}
      rooms={abyssal.rooms}
      directs={abyssal.directs}
      messages={abyssal.messages}
      presence={abyssal.presence}
      activeRoomId={abyssal.activeRoomId}
      maxRooms={session.maxRoomsPerUser}
      remainingSessionSec={abyssal.remainingSessionSec}
      sessionTimeoutSec={session.sessionInactivitySec}
      onOpenRoom={openRoom}
      onOpenDirect={(username) => { setReplyTarget(null); setShowAttachment(false); abyssal.openDirect(username); }}
      onCreateRoom={() => setShowCreateRoom(true)}
      onDeleteRoom={abyssal.deleteRoom}
      pendingRoomJoins={(abyssal.pendingMlsJoins ?? []).map((join) => ({ requestId: join.requestId, roomId: join.roomId, username: join.username }))}
      pendingRoomLeaves={(abyssal.pendingMlsLeaves ?? []).map((leave) => ({ requestId: leave.requestId, roomId: leave.roomId, username: leave.username }))}
      onJoinRoom={abyssal.joinRoom}
      onAcceptRoomJoin={abyssal.acceptRoomJoin}
      onRejectRoomJoin={abyssal.rejectRoomJoin}
      onLeaveRoom={abyssal.leaveRoom}
      onAcceptRoomLeave={abyssal.acceptRoomLeave}
      onRejectRoomLeave={abyssal.rejectRoomLeave}
      onLock={onLock}
      onLogout={() => void resetLocal()}
      onWipe={() => { abyssal.wipeRelay(); void resetLocal(); }}
    >
      {abyssal.activeRoom ? (
        <ChatView
          room={abyssal.activeRoom}
          username={session.username}
          connected={abyssal.connection === "connected"}
          safetyNumber={abyssal.safetyNumber}
          directTrust={abyssal.directTrust}
          messages={abyssal.messages[abyssal.activeRoom.id] ?? []}
          users={abyssal.presence}
          upload={abyssal.upload}
          onBack={() => openRoom(null)}
          onSend={abyssal.sendText}
          onReply={setReplyTarget}
          replyTarget={replyTarget}
          onOpenAttachment={(retentionSec) => { setAttachmentRetentionSec(retentionSec); setShowAttachment(true); }}
          onViewAttachment={abyssal.viewAttachment}
          onExportAttachment={abyssal.exportAttachment}
          onSendGif={sendGif}
          onVerifySafetyNumber={abyssal.verifyDirectSafetyNumber}
        />
      ) : undefined}
    </AppShell>
  );
}

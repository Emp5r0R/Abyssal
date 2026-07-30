import { useEffect, useRef, useState } from "react";
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

export default function App() {
  const abyssal = useAbyssalSession();
  const [coverPin, setCoverPin] = useState("");
  const [duressPin, setDuressPin] = useState("");
  const [locked, setLocked] = useState(false);
  const [showCreateRoom, setShowCreateRoom] = useState(false);
  const [showAttachment, setShowAttachment] = useState(false);
  const [replyTarget, setReplyTarget] = useState<ChatMessage | null>(null);
  const externalPickerRef = useRef(false);

  useEffect(() => {
    const visibility = () => {
      if (!abyssal.session || document.visibilityState !== "hidden" || externalPickerRef.current) return;
      if (abyssal.retainWhenHiddenRef.current && coverPin) setLocked(true);
      else void abyssal.logout();
    };
    const focus = () => window.setTimeout(() => { externalPickerRef.current = false; }, 500);
    document.addEventListener("visibilitychange", visibility);
    window.addEventListener("focus", focus);
    return () => {
      document.removeEventListener("visibilitychange", visibility);
      window.removeEventListener("focus", focus);
    };
  }, [abyssal, coverPin]);

  const resetLocal = async () => {
    setLocked(false);
    setCoverPin("");
    setDuressPin("");
    setReplyTarget(null);
    await abyssal.logout();
  };

  if (!abyssal.session) {
    return <Entrance onLogin={abyssal.login} />;
  }

  if (!coverPin) {
    return (
      <div className="secure-root" onPointerDownCapture={abyssal.touchActivity} onKeyDownCapture={abyssal.touchActivity}>
        <SecureWorkspace abyssal={abyssal} replyTarget={replyTarget} setReplyTarget={setReplyTarget} setLocked={setLocked} setShowAttachment={setShowAttachment} setShowCreateRoom={setShowCreateRoom} resetLocal={resetLocal} />
        <PinSetup onComplete={(pin, duress) => { setCoverPin(pin); setDuressPin(duress); }} />
      </div>
    );
  }

  if (locked) {
    return (
      <CalculatorCover
        pin={coverPin}
        duressPin={duressPin}
        onUnlock={() => { abyssal.touchActivity(); setLocked(false); }}
        onDuress={() => { abyssal.wipeRelay(); abyssal.clearMemory(); setCoverPin(""); setDuressPin(""); setLocked(false); }}
      />
    );
  }

  return (
    <div className="secure-root" onPointerDownCapture={abyssal.touchActivity} onKeyDownCapture={abyssal.touchActivity}>
      <SecureWorkspace abyssal={abyssal} replyTarget={replyTarget} setReplyTarget={setReplyTarget} setLocked={setLocked} setShowAttachment={setShowAttachment} setShowCreateRoom={setShowCreateRoom} resetLocal={resetLocal} />

      {showCreateRoom ? <CreateRoomDialog onCancel={() => setShowCreateRoom(false)} onCreate={abyssal.createRoom} /> : null}
      {showAttachment && abyssal.activeRoom ? (
        <AttachmentDialog
          room={abyssal.activeRoom}
          onCancel={() => { externalPickerRef.current = false; setShowAttachment(false); }}
          onPickerState={(active) => { externalPickerRef.current = active; }}
          onSend={(file, options) => abyssal.sendAttachment({ file, options, replyToId: replyTarget?.id })}
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
  setLocked,
  setShowAttachment,
  setShowCreateRoom,
  resetLocal,
}: {
  abyssal: AbyssalController;
  replyTarget: ChatMessage | null;
  setReplyTarget: (message: ChatMessage | null) => void;
  setLocked: (locked: boolean) => void;
  setShowAttachment: (show: boolean) => void;
  setShowCreateRoom: (show: boolean) => void;
  resetLocal: () => Promise<void>;
}) {
  const session = abyssal.session;
  if (!session) return null;

  const sendGif = async (reaction: ReactionAsset, replyToId?: string): Promise<boolean> => {
    try {
      const response = await fetch(reaction.path, { cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer" });
      if (!response.ok) return false;
      const blob = await response.blob();
      return await abyssal.sendAttachment({
        file: new File([blob], reaction.filename, { type: reaction.mimeType }),
        options: { oneTime: false, deleteAfterDownload: false, ttlSec: 0 },
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
      onLock={() => setLocked(true)}
      onLogout={() => void resetLocal()}
      onWipe={() => { abyssal.wipeRelay(); abyssal.clearMemory(); }}
    >
      {abyssal.activeRoom ? (
        <ChatView
          room={abyssal.activeRoom}
          username={session.username}
          connected={abyssal.connection === "connected"}
          safetyNumber={abyssal.safetyNumber}
          messages={abyssal.messages[abyssal.activeRoom.id] ?? []}
          users={abyssal.presence}
          upload={abyssal.upload}
          onBack={() => openRoom(null)}
          onSend={abyssal.sendText}
          onReply={setReplyTarget}
          replyTarget={replyTarget}
          onOpenAttachment={() => setShowAttachment(true)}
          onViewAttachment={abyssal.viewAttachment}
          onExportAttachment={abyssal.exportAttachment}
          onSendGif={sendGif}
        />
      ) : undefined}
    </AppShell>
  );
}

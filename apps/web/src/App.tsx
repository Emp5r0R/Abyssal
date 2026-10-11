import { useCallback, useEffect, useRef, useState } from "react";
import { X } from "lucide-react";
import { flushSync } from "react-dom";
import { AppShell } from "./components/AppShell";
import { AttachmentDialog } from "./components/AttachmentDialog";
import { ChatView } from "./components/ChatView";
import { CreateRoomDialog } from "./components/CreateRoomDialog";
import { Entrance } from "./components/Entrance";
import { MediaViewer } from "./components/MediaViewer";
import { PrivacyBlurProvider } from "./components/PrivacyBlur";
import { SecurityVerificationGate } from "./components/SecurityVerificationGate";
import { SettingsDialog } from "./components/SettingsDialog";
import { CalculatorCover, PinSetup } from "./components/Privacy";
import { withCoverEnabled } from "./domain/workspacePreferences";
import type { ReactionAsset } from "./domain/reactions";
import type { ChatMessage } from "./domain/types";
import { useAbyssalSession } from "./hooks/useAbyssalSession";
import { usePrivacyCover } from "./hooks/usePrivacyCover";
import {
  verifyOriginAttestation,
  verifyOriginPreflight,
  type OriginAttestationStatus,
} from "./security/originAttestation";

export default function App() {
  const abyssal = useAbyssalSession();
  const cover = usePrivacyCover();
  const clearPrivateView = abyssal.clearPrivateView;
  const { destroyPinGate, lock, respondToHiddenTab } = cover;
  const [showCreateRoom, setShowCreateRoom] = useState(false);
  const [showAttachment, setShowAttachment] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [attachmentRetentionSec, setAttachmentRetentionSec] = useState(5);
  const [replyTarget, setReplyTarget] = useState<ChatMessage | null>(null);
  const [originStatus, setOriginStatus] = useState<OriginAttestationStatus>("CHECKING");
  const externalPickerRef = useRef(false);
  const attestationGenerationRef = useRef(0);

  const checkOrigin = useCallback(() => {
    const generation = ++attestationGenerationRef.current;
    setOriginStatus("CHECKING");
    void verifyOriginAttestation().then((result) => {
      if (attestationGenerationRef.current === generation) setOriginStatus(result.status);
    });
  }, []);

  const preflightOrigin = useCallback(async () => {
    const result = await verifyOriginPreflight();
    if (result.status !== "OK") setOriginStatus(result.status);
    return result.status === "OK";
  }, []);

  useEffect(() => {
    const generation = ++attestationGenerationRef.current;
    void verifyOriginAttestation().then((result) => {
      if (attestationGenerationRef.current === generation) setOriginStatus(result.status);
    });
    return () => { attestationGenerationRef.current += 1; };
  }, []);

  const clearTransientUi = useCallback(() => {
    externalPickerRef.current = false;
    setReplyTarget(null);
    setShowAttachment(false);
    setShowCreateRoom(false);
    setShowSettings(false);
    clearPrivateView();
  }, [clearPrivateView]);

  const lockWorkspace = useCallback(() => {
    clearTransientUi();
    lock();
  }, [clearTransientUi, lock]);

  useEffect(() => {
    const visibility = () => {
      if (!abyssal.session || document.visibilityState !== "hidden" || externalPickerRef.current) return;
      const response = respondToHiddenTab();
      if (response === "lock") lockWorkspace();
      else if (response === "sign-out") void abyssal.logout();
    };
    const focus = () => window.setTimeout(() => { externalPickerRef.current = false; }, 500);
    document.addEventListener("visibilitychange", visibility);
    window.addEventListener("focus", focus);
    return () => {
      document.removeEventListener("visibilitychange", visibility);
      window.removeEventListener("focus", focus);
    };
  }, [abyssal, lockWorkspace, respondToHiddenTab]);

  useEffect(() => {
    const pageHide = () => {
      flushSync(() => {
        clearTransientUi();
        destroyPinGate();
      });
    };
    window.addEventListener("pagehide", pageHide);
    return () => window.removeEventListener("pagehide", pageHide);
  }, [clearTransientUi, destroyPinGate]);

  useEffect(() => {
    if (!abyssal.session) destroyPinGate();
  }, [abyssal.session, destroyPinGate]);

  const resetLocal = async () => {
    clearTransientUi();
    destroyPinGate();
    await abyssal.logout();
  };

  if (originStatus !== "OK") {
    return <SecurityVerificationGate status={originStatus} onRetry={checkOrigin} />;
  }

  if (abyssal.securityWarning) {
    return (
      <SecurityVerificationGate
        status={abyssal.securityWarning}
        onRetry={() => window.location.reload()}
        onEndSession={() => { void abyssal.logout(); }}
      />
    );
  }

  if (!abyssal.session) {
    return (
      <Entrance
        onLogin={abyssal.login}
        onPreflight={preflightOrigin}
        notice={abyssal.entryNotice}
        coverEnabled={cover.preferences.coverEnabled}
        onCoverEnabledChange={(enabled) => cover.updatePreferences(withCoverEnabled(cover.preferences, enabled))}
      />
    );
  }

  if (cover.locked && cover.pinGate) {
    return (
      <CalculatorCover
        pinGate={cover.pinGate}
        onUnlock={() => { abyssal.touchActivity(); cover.unlock(); }}
        onDuress={() => {
          abyssal.wipeRelay();
          clearTransientUi();
          destroyPinGate();
          abyssal.clearMemory();
        }}
      />
    );
  }

  const dialogsAllowed = !cover.needsPinSetup;

  return (
    <PrivacyBlurProvider enabled={cover.preferences.blurEnabled}>
      <div className="secure-root" onPointerDownCapture={abyssal.touchActivity} onKeyDownCapture={abyssal.touchActivity}>
        <SecureWorkspace
          abyssal={abyssal}
          replyTarget={replyTarget}
          setReplyTarget={setReplyTarget}
          canLock={cover.coverReady}
          onLock={lockWorkspace}
          onOpenSettings={() => setShowSettings(true)}
          setAttachmentRetentionSec={setAttachmentRetentionSec}
          setShowAttachment={setShowAttachment}
          setShowCreateRoom={setShowCreateRoom}
          resetLocal={resetLocal}
        />

        {cover.needsPinSetup ? <PinSetup onComplete={cover.installPin} onSkip={cover.skipPinSetup} /> : null}
        {dialogsAllowed && showSettings ? (
          <SettingsDialog
            preferences={cover.preferences}
            username={abyssal.session.username}
            nodeId={abyssal.session.nodeId}
            directoryCheckpoint={abyssal.presence[0]?.directory_digest}
            onChange={cover.updatePreferences}
            onWipe={() => { abyssal.wipeRelay(); void resetLocal(); }}
            onClose={() => setShowSettings(false)}
          />
        ) : null}
        {dialogsAllowed && showCreateRoom ? <CreateRoomDialog onCancel={() => setShowCreateRoom(false)} onCreate={abyssal.createRoom} /> : null}
        {dialogsAllowed && showAttachment && abyssal.activeRoom ? (
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
        {dialogsAllowed && abyssal.media ? <MediaViewer media={abyssal.media} onClose={abyssal.clearMedia} /> : null}
        {dialogsAllowed && abyssal.notice ? (
          <div className="toast" role="status" aria-live="polite">
            <span>{abyssal.notice}</span>
            <button
              className="toast-dismiss"
              type="button"
              aria-label="Dismiss notice"
              title="Dismiss notice"
              onClick={abyssal.clearNotice}
            >
              <X size={16} />
            </button>
          </div>
        ) : null}
      </div>
    </PrivacyBlurProvider>
  );
}

type AbyssalController = ReturnType<typeof useAbyssalSession>;

function SecureWorkspace({
  abyssal,
  replyTarget,
  setReplyTarget,
  canLock,
  onLock,
  onOpenSettings,
  setAttachmentRetentionSec,
  setShowAttachment,
  setShowCreateRoom,
  resetLocal,
}: {
  abyssal: AbyssalController;
  replyTarget: ChatMessage | null;
  setReplyTarget: (message: ChatMessage | null) => void;
  canLock: boolean;
  onLock: () => void;
  onOpenSettings: () => void;
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
      displayName={session.displayName}
      connection={abyssal.connection}
      rooms={abyssal.rooms}
      publicRooms={abyssal.publicRooms}
      directs={abyssal.directs}
      messages={abyssal.messages}
      presence={abyssal.presence}
      activeRoomId={abyssal.activeRoomId}
      maxRooms={session.maxRoomsPerUser}
      remainingSessionSec={abyssal.remainingSessionSec}
      canLock={canLock}
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
      onOpenSettings={onOpenSettings}
      onLogout={() => void resetLocal()}
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
          onVerifyToken={abyssal.verifyDirectVerificationToken}
        />
      ) : undefined}
    </AppShell>
  );
}

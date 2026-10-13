import { useCallback, useEffect, useMemo, useRef, useState } from "react";
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
import { QuickSwitcher } from "./components/QuickSwitcher";
import { SettingsDialog } from "./components/SettingsDialog";
import { ShortcutsDialog } from "./components/ShortcutsDialog";
import { useVerifiedAssets } from "./components/verifiedAssetContext";
import { CalculatorCover, PinSetup } from "./components/Privacy";
import { conversationEntries, displayNamesBySender, roomLabel, shortAccountId } from "./domain/displayLabels";
import type { NotificationLevel } from "./domain/notificationPolicy";
import { adjacentConversation } from "./domain/keyboardShortcuts";
import { withBlurEnabled, withCoverEnabled, withNotificationLevel } from "./domain/workspacePreferences";
import type { ReactionAsset } from "./domain/reactions";
import type { ChatMessage } from "./domain/types";
import { useAbyssalSession } from "./hooks/useAbyssalSession";
import { useKeyboardShortcuts } from "./hooks/useKeyboardShortcuts";
import { useMessageNotifications } from "./hooks/useMessageNotifications";
import { createBrowserNotifier } from "./platform/notifier";
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
  const [showShortcuts, setShowShortcuts] = useState(false);
  const [showSwitcher, setShowSwitcher] = useState(false);
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
    setShowShortcuts(false);
    setShowSwitcher(false);
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

  const navigateTo = useCallback((chatId: string | null) => {
    setReplyTarget(null);
    setShowAttachment(false);
    abyssal.openRoom(chatId);
  }, [abyssal]);

  const displayNames = useMemo(() => displayNamesBySender(abyssal.messages), [abyssal.messages]);
  const conversations = useMemo(
    () => conversationEntries(abyssal.rooms, abyssal.directs, displayNames),
    [abyssal.directs, abyssal.rooms, displayNames],
  );
  const workspaceOpen = originStatus === "OK" && !abyssal.securityWarning && Boolean(abyssal.session) &&
    !(cover.locked && cover.pinGate) && !cover.needsPinSetup;
  const step = (direction: 1 | -1) => {
    const next = adjacentConversation(conversations.map((entry) => entry.id), abyssal.activeRoomId, direction);
    if (next) navigateTo(next);
  };
  useKeyboardShortcuts({
    "quick-switcher": () => setShowSwitcher(true),
    "previous-conversation": () => step(-1),
    "next-conversation": () => step(1),
    "go-home": () => navigateTo(null),
    "focus-composer": () => document.querySelector<HTMLTextAreaElement>("textarea[data-composer='true']")?.focus(),
    "create-room": () => setShowCreateRoom(true),
    "open-settings": () => setShowSettings(true),
    lock: cover.coverReady ? lockWorkspace : undefined,
    "toggle-blur": () => cover.updatePreferences(withBlurEnabled(cover.preferences, !cover.preferences.blurEnabled)),
    "show-shortcuts": () => setShowShortcuts(true),
  }, workspaceOpen);

  const [notifier] = useState(createBrowserNotifier);
  const [notificationPermission, setNotificationPermission] = useState(notifier.permission);
  const { updatePreferencesWith } = cover;
  const changeNotificationLevel = useCallback(async (level: NotificationLevel) => {
    const allowed = level === "off" || await notifier.requestPermission();
    setNotificationPermission(notifier.permission());
    if (allowed) updatePreferencesWith((current) => withNotificationLevel(current, level));
  }, [notifier, updatePreferencesWith]);
  useMessageNotifications({
    notifier,
    enabled: Boolean(abyssal.session),
    level: notificationPermission === "granted" ? cover.preferences.notificationLevel : "off",
    locked: cover.locked,
    activeChatId: abyssal.activeRoomId,
    messages: abyssal.messages,
    labelsFor: (message) => {
      const room = abyssal.rooms.find((candidate) => candidate.id === message.chatId);
      return {
        sender: displayNames.get(message.sender.toLowerCase()) ?? shortAccountId(message.sender),
        conversation: room ? roomLabel(room) : null,
      };
    },
    onOpen: navigateTo,
  });

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
          onSearch={() => setShowSwitcher(true)}
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
            notificationPermission={notificationPermission}
            onNotificationLevelChange={(level) => { void changeNotificationLevel(level); }}
            onShowShortcuts={() => { setShowSettings(false); setShowShortcuts(true); }}
            onWipe={() => { abyssal.wipeRelay(); void resetLocal(); }}
            onClose={() => setShowSettings(false)}
          />
        ) : null}
        {dialogsAllowed && showShortcuts ? <ShortcutsDialog onClose={() => setShowShortcuts(false)} /> : null}
        {dialogsAllowed && showSwitcher ? (
          <QuickSwitcher conversations={conversations} onOpen={navigateTo} onClose={() => setShowSwitcher(false)} />
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
  onSearch,
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
  onSearch: () => void;
  setAttachmentRetentionSec: (seconds: number) => void;
  setShowAttachment: (show: boolean) => void;
  setShowCreateRoom: (show: boolean) => void;
  resetLocal: () => Promise<void>;
}) {
  const verifiedAssets = useVerifiedAssets();
  const session = abyssal.session;
  if (!session) return null;

  const sendGif = async (reaction: ReactionAsset, replyToId?: string, retentionSec?: number): Promise<boolean> => {
    try {
      const blob = await verifiedAssets.load(reaction);
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
      onSearch={onSearch}
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

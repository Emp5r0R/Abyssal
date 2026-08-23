import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { flushSync } from "react-dom";
import {
  absoluteRetention,
  classifyMedia,
  isExpired,
  MEDIA_LIMIT_BYTES,
  mediaAllowed,
  readRetention,
} from "../domain/messagePolicy";
import { mentionsUsername, replyTargetsCurrentUser } from "../domain/messageAttention";
import { LOCAL_SENDER_CLIENT, parseSenderClient } from "../domain/senderClient";
import {
  appendBoundedMessage,
  wipeEvictedMessage,
  wipeMessageAttachmentKey as wipeMessageAttachment,
} from "../domain/messageMemoryPolicy";
import { reactionByShortcode } from "../domain/reactions";
import type {
  AccountSession,
  AttachmentOptions,
  ChatMessage,
  ConnectionState,
  DirectoryStamp,
  DecryptedMedia,
  DirectRecord,
  IncomingFrame,
  MediaType,
  PresenceUser,
  RoomRecord,
  UploadProgress,
} from "../domain/types";
import {
  base64ToBytes,
  bytesToBase64,
  conversationSafetyNumber,
  ATTACHMENT_CIPHER_VERSION,
  finishOpaqueLogin,
  finishOpaqueRegistration,
  FatalCipherError,
  identityContext,
  IDENTITY_PUBLIC_KEY_BYTES,
  InMemoryPayloadCipher,
  payloadToFrame,
  PROTOCOL_VERSION,
  startOpaque,
  type EncryptedPayload,
  type EncryptedAttachment,
  wipeBytes,
  wipeOpaqueStart,
} from "../security/crypto";
import { attachmentDownloadBlob, attachmentDownloadName } from "../security/attachmentExport";
import {
  MlsRoomManager,
  type PendingMlsJoinSummary,
  type PendingMlsLeaveSummary,
  type PreparedMlsApplication,
  type PreparedMlsSnapshot,
} from "../security/mls";
import {
  DirectTrustStore,
  type DirectTrustContext,
  type DirectTrustStatus,
} from "../security/directTrust";
import { normalizeNodeUrl } from "../security/nodeUrl";
import {
  decryptAndCompleteAttachment,
  downloadEncryptedAttachment,
  deleteUploadedAttachment,
  finishOpaqueAccount,
  RelaySocket,
  releaseAttachmentDownloadClaim,
  revokeSession,
  startOpaqueAccount,
  uploadEncryptedAttachment,
  type EncryptedSendOutcome,
  type AttachmentPlaintextPolicy,
  type DownloadedEncryptedAttachment,
  type PrekeyLease,
  PrekeyLeaseError,
} from "../transport/nodeClient";
import { roomFromMlsWire } from "../transport/mlsWire";

const ACTIVITY_SIGNAL_INTERVAL_MS = 20_000;
const MAX_MESSAGE_AGE_MS = 24 * 60 * 60 * 1000;
const MAX_ROOM_ID_BYTES = 128;
const MAX_ROOM_NAME_LENGTH = 36;
const MAX_ROOM_CATALOG = 1024;
const MAX_DIRECT_CATALOG = 128;
const MAX_PRESENCE_USERS = 128;
const MAX_PINNED_IDENTITIES = 1024;
const MAX_DIRECTORY_HISTORY = 32;
const MAX_DIRECTORY_REVISION = 65_536;
const MAX_OWN_MESSAGE_IDS = 10_000;
const MAX_TIMER_SECONDS = 86_400;
const USERNAME_PATTERN = /^[A-Za-z0-9_-]{1,80}$/u;
const ROOM_ID_PATTERN = /^forum_[A-Za-z0-9_-]{1,122}$/u;
const ROOM_KEYS = new Set([
  "id", "name", "owner_username", "self_destruct_timer_sec", "overall_expiry_sec",
  "allow_images", "allow_videos", "allow_files", "enforce_text_absolute_expiry",
  "image_read_timer_sec", "image_overall_expiry_sec", "enforce_image_absolute_expiry",
  "video_read_timer_sec", "video_overall_expiry_sec", "enforce_video_absolute_expiry",
  "file_read_timer_sec", "file_overall_expiry_sec", "enforce_file_absolute_expiry",
  "conversation_type", "peer_username",
]);
const PRESENCE_KEYS = new Set([
  "username", "connected", "identity_public_b64", "identity_prekey_id", "directory_digest",
  "directory_node_id", "directory_revision",
]);
const DIRECT_KEYS = new Set(["id", "peer_username"]);
// Browser downloads can outlive the click event, especially for large files.
// Keep the explicit-download Blob URL alive briefly enough to avoid truncation,
// then release it so an export cannot pin plaintext indefinitely.
const DOWNLOAD_URL_CLEANUP_DELAY_MS = 60_000;

interface LoginInput {
  nodeUrl: string;
  code: string;
  password: string;
  retainWhenHidden: boolean;
}

interface AttachmentInput {
  file: File;
  options: AttachmentOptions;
  replyToId?: string;
  reactionShortcode?: string;
}

interface UploadState extends UploadProgress {
  active: boolean;
  name: string;
}

interface AttachmentOperation {
  controller: AbortController;
  generation: number;
  connectionGeneration: number;
  wipe: () => void;
}

const EMPTY_UPLOAD: UploadState = { active: false, name: "", loaded: 0, total: 0 };

class AsyncCryptoGate {
  #tail: Promise<void> = Promise.resolve();

  run<T>(operation: () => T | Promise<T>): Promise<T> {
    const ready = this.#tail.catch(() => undefined);
    let release!: () => void;
    this.#tail = new Promise<void>((resolve) => { release = resolve; });
    return ready.then(operation).finally(() => release());
  }
}

function attachmentPlaintextPolicy(
  attachment: NonNullable<ChatMessage["attachment"]>,
): AttachmentPlaintextPolicy {
  return {
    expectedBytes: attachment.sizeBytes,
    maxBytes: MEDIA_LIMIT_BYTES[attachment.mediaType],
  };
}

export function useAbyssalSession() {
  const [session, setSession] = useState<AccountSession | null>(null);
  const [connection, setConnection] = useState<ConnectionState>("disconnected");
  const [rooms, setRooms] = useState<RoomRecord[]>([]);
  const [directs, setDirects] = useState<DirectRecord[]>([]);
  const [presence, setPresence] = useState<PresenceUser[]>([]);
  const [messages, setMessages] = useState<Record<string, ChatMessage[]>>({});
  const [activeRoomId, setActiveRoomId] = useState<string | null>(null);
  const [remainingSessionSec, setRemainingSessionSec] = useState(0);
  const [upload, setUpload] = useState<UploadState>(EMPTY_UPLOAD);
  const [media, setMedia] = useState<DecryptedMedia | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [securityWarning, setSecurityWarning] = useState<"ATTESTATION_REJECTED" | null>(null);
  const [pendingMlsJoins, setPendingMlsJoins] = useState<PendingMlsJoinSummary[]>([]);
  const [pendingMlsLeaves, setPendingMlsLeaves] = useState<PendingMlsLeaveSummary[]>([]);
  const [directTrust, setDirectTrust] = useState<DirectTrustStatus>({
    active: false,
    peerUsername: null,
    safetyNumber: null,
    verified: false,
  });
  const socketRef = useRef<RelaySocket | null>(null);
  const loginAbortRef = useRef<AbortController | null>(null);
  const cipherRef = useRef(new InMemoryPayloadCipher());
  const mlsRef = useRef<MlsRoomManager | null>(null);
  const lastActivityRef = useRef(0);
  const lastActivitySignalRef = useRef(0);
  const retainWhenHiddenRef = useRef(false);
  const sessionRef = useRef<AccountSession | null>(null);
  const roomsRef = useRef<RoomRecord[]>([]);
  const directsRef = useRef<DirectRecord[]>([]);
  const presenceRef = useRef<PresenceUser[]>([]);
  const messagesRef = useRef<Record<string, ChatMessage[]>>({});
  const mediaRef = useRef<DecryptedMedia | null>(null);
  const activeRoomRef = useRef<string | null>(null);
  const requestedDirectRef = useRef<string | null>(null);
  const ownMessageIdsRef = useRef(new Set<string>());
  const receivedFrameIdsRef = useRef(new Map<string, string>());
  const identityPinsRef = useRef(new Map<string, string>());
  const directoryHistoryRef = useRef(new Map<string, DirectoryStamp>());
  const directoryStampRef = useRef<DirectoryStamp | null>(null);
  const directoryNodeRef = useRef<string | null>(null);
  const directoryRevisionRef = useRef(0);
  const mlsSnapshotsRef = useRef(new Map<string, PreparedMlsSnapshot>());
  const frameQueueRef = useRef<Promise<void>>(Promise.resolve());
  const sendReadReceiptRef = useRef<(chatId: string, messageId: string) => void>(() => undefined);
  const sendMlsSnapshotRef = useRef<(snapshot: PreparedMlsSnapshot) => Promise<EncryptedSendOutcome>>(async () => "NOT_SENT");
  const sessionGenerationRef = useRef(0);
  const connectionGenerationRef = useRef(0);
  const directTrustRef = useRef(new DirectTrustStore());
  const cryptoGateRef = useRef(new AsyncCryptoGate());
  const attachmentOperationsRef = useRef(new Set<AttachmentOperation>());
  const exportUrlsRef = useRef(new Map<string, number | null>());

  useEffect(() => {
    sessionRef.current = session;
  }, [session]);

  useEffect(() => {
    roomsRef.current = rooms;
  }, [rooms]);

  useEffect(() => {
    directsRef.current = directs;
  }, [directs]);

  useEffect(() => {
    presenceRef.current = presence;
  }, [presence]);

  useEffect(() => {
    messagesRef.current = messages;
  }, [messages]);

  useEffect(() => {
    activeRoomRef.current = activeRoomId;
  }, [activeRoomId]);

  const updateMessages = useCallback((update: (current: Record<string, ChatMessage[]>) => Record<string, ChatMessage[]>) => {
    const next = update(messagesRef.current);
    messagesRef.current = next;
    setMessages(next);
  }, []);

  const cancelAttachmentOperations = useCallback(() => {
    const operations = [...attachmentOperationsRef.current];
    attachmentOperationsRef.current.clear();
    operations.forEach((operation) => {
      operation.controller.abort();
      operation.wipe();
    });
  }, []);

  const revokeExportUrl = useCallback((url: string) => {
    const timer = exportUrlsRef.current.get(url);
    if (timer === undefined) return;
    exportUrlsRef.current.delete(url);
    if (timer !== null) window.clearTimeout(timer);
    URL.revokeObjectURL(url);
  }, []);

  const clearExportUrls = useCallback(() => {
    [...exportUrlsRef.current.keys()].forEach(revokeExportUrl);
  }, [revokeExportUrl]);

  const startAttachmentOperation = useCallback((wipe: () => void): AttachmentOperation => {
    const operation = {
      controller: new AbortController(),
      generation: sessionGenerationRef.current,
      connectionGeneration: connectionGenerationRef.current,
      wipe,
    };
    attachmentOperationsRef.current.add(operation);
    return operation;
  }, []);

  const finishAttachmentOperation = useCallback((operation: AttachmentOperation) => {
    attachmentOperationsRef.current.delete(operation);
    operation.wipe();
  }, []);

  const attachmentOperationActive = useCallback((operation: AttachmentOperation, token: string): boolean => (
    !operation.controller.signal.aborted &&
    operation.generation === sessionGenerationRef.current &&
    operation.connectionGeneration === connectionGenerationRef.current &&
    sessionRef.current?.token === token
  ), []);

  const clearDirectTrust = useCallback(() => {
    directTrustRef.current.clear();
    setDirectTrust(directTrustRef.current.status(null));
  }, []);

  const activeDirectTrustContext = useCallback((chatId = activeRoomRef.current): DirectTrustContext | null => {
    const currentSession = sessionRef.current;
    if (!currentSession || !chatId || chatId !== activeRoomRef.current || connection !== "connected") return null;
    const direct = directsRef.current.find((candidate) => candidate.id === chatId);
    if (!direct) return null;
    const peer = presenceRef.current.find(
      (user) => user.username.toLowerCase() === direct.peer_username.toLowerCase(),
    );
    if (!peer) return null;
    let peerIdentity: Uint8Array<ArrayBufferLike> | null = null;
    try {
      peerIdentity = base64ToBytes(peer.identity_public_b64);
      const safetyNumber = conversationSafetyNumber(currentSession.identityPublicKey, peerIdentity);
      return {
        chatId: direct.id,
        peerUsername: direct.peer_username,
        safetyNumber,
        sessionGeneration: sessionGenerationRef.current,
        connectionGeneration: connectionGenerationRef.current,
        localIdentity: currentSession.identityPublicKey.slice(),
        peerIdentity,
      };
    } catch {
      peerIdentity?.fill(0);
      return null;
    }
  }, [connection]);

  const refreshDirectTrust = useCallback(() => {
    const context = activeDirectTrustContext();
    directTrustRef.current.invalidateIfIdentityChanged(context);
    setDirectTrust(directTrustRef.current.status(context));
    context?.localIdentity.fill(0);
    context?.peerIdentity.fill(0);
  }, [activeDirectTrustContext]);

  const directOperationAllowed = useCallback((chatId: string): boolean => {
    const context = activeDirectTrustContext(chatId);
    directTrustRef.current.invalidateIfIdentityChanged(context);
    const allowed = directTrustRef.current.isVerified(context);
    context?.localIdentity.fill(0);
    context?.peerIdentity.fill(0);
    const isDirect = directsRef.current.some((direct) => direct.id === chatId);
    const isRoom = roomsRef.current.some((room) => room.id === chatId);
    return isDirect ? allowed : isRoom;
  }, [activeDirectTrustContext]);

  const verifyDirectSafetyNumber = useCallback((displayedSafetyNumber: string): boolean => {
    const context = activeDirectTrustContext();
    if (!context) return false;
    const accepted = directTrustRef.current.markVerified(context, displayedSafetyNumber);
    context.localIdentity.fill(0);
    context.peerIdentity.fill(0);
    refreshDirectTrust();
    return accepted;
  }, [activeDirectTrustContext, refreshDirectTrust]);

  const clearMedia = useCallback(() => {
    const current = mediaRef.current;
    mediaRef.current = null;
    if (current) URL.revokeObjectURL(current.objectUrl);
    setMedia(null);
  }, []);

  useEffect(() => {
    const directTrustStore = directTrustRef.current;
    return () => {
      cancelAttachmentOperations();
      clearExportUrls();
      directTrustStore.clear();
      const current = mediaRef.current;
      mediaRef.current = null;
      if (current) URL.revokeObjectURL(current.objectUrl);
    };
  }, [cancelAttachmentOperations, clearExportUrls]);

  const clearMemory = useCallback(() => {
    sessionGenerationRef.current += 1;
    cancelAttachmentOperations();
    clearExportUrls();
    loginAbortRef.current?.abort();
    loginAbortRef.current = null;
    const currentSession = sessionRef.current;
    sessionRef.current = null;
    socketRef.current?.close();
    socketRef.current = null;
    mlsRef.current?.close();
    mlsRef.current = null;
    cipherRef.current.clear();
    clearMedia();
    if (currentSession) wipeBytes(currentSession.identityPublicKey);
    const currentMessages = messagesRef.current;
    messagesRef.current = {};
    wipeMessageMap(currentMessages);
    setSession(null);
    setConnection("disconnected");
    setRooms([]);
    setDirects([]);
    setPresence([]);
    setMessages({});
    setActiveRoomId(null);
    setRemainingSessionSec(0);
    setUpload(EMPTY_UPLOAD);
    setNotice(null);
    setSecurityWarning(null);
    setPendingMlsJoins([]);
    setPendingMlsLeaves([]);
    ownMessageIdsRef.current.clear();
    receivedFrameIdsRef.current.clear();
    identityPinsRef.current.clear();
    directoryHistoryRef.current.clear();
    directoryStampRef.current = null;
    directoryNodeRef.current = null;
    directoryRevisionRef.current = 0;
    mlsSnapshotsRef.current.clear();
    clearDirectTrust();
    connectionGenerationRef.current += 1;
    frameQueueRef.current = Promise.resolve();
    roomsRef.current = [];
    directsRef.current = [];
    presenceRef.current = [];
    activeRoomRef.current = null;
    requestedDirectRef.current = null;
    retainWhenHiddenRef.current = false;
    lastActivityRef.current = 0;
    lastActivitySignalRef.current = 0;
  }, [cancelAttachmentOperations, clearDirectTrust, clearExportUrls, clearMedia]);

  const clearPrivateView = useCallback(() => {
    clearMedia();
    activeRoomRef.current = null;
    setActiveRoomId(null);
    setNotice(null);
  }, [clearMedia]);

  const logout = useCallback(async () => {
    const current = sessionRef.current;
    clearMemory();
    if (current) await revokeSession(current);
  }, [clearMemory]);

  const failClosed = useCallback((candidate: AccountSession | null = sessionRef.current) => {
    clearMemory();
    if (candidate) void revokeSession(candidate);
  }, [clearMemory]);

  const touchActivity = useCallback(() => {
    if (!sessionRef.current) return;
    const now = Date.now();
    lastActivityRef.current = now;
    const timeout = sessionRef.current.sessionInactivitySec;
    setRemainingSessionSec(timeout);
    if (now - lastActivitySignalRef.current >= ACTIVITY_SIGNAL_INTERVAL_MS) {
      lastActivitySignalRef.current = now;
      socketRef.current?.activity();
    }
  }, []);

  const rememberDirectoryStamp = useCallback((stamp: DirectoryStamp): boolean => {
    if (sessionRef.current?.nodeId !== stamp.directory_node_id) return false;
    const node = directoryNodeRef.current;
    if (node !== null && node !== stamp.directory_node_id) return false;
    const key = `${stamp.directory_node_id}\u0000${stamp.directory_revision}\u0000${stamp.directory_digest}`;
    if (directoryHistoryRef.current.has(key)) {
      return stamp.directory_revision >= directoryRevisionRef.current;
    }
    const sameRevision = [...directoryHistoryRef.current.values()].find(
      (known) => known.directory_revision === stamp.directory_revision,
    );
    if (sameRevision && (
      sameRevision.directory_node_id !== stamp.directory_node_id ||
      sameRevision.directory_digest !== stamp.directory_digest
    )) return false;
    if (stamp.directory_revision < directoryRevisionRef.current) {
      return false;
    }
    if (directoryHistoryRef.current.size >= MAX_DIRECTORY_HISTORY) {
      const oldest = directoryHistoryRef.current.keys().next().value;
      if (oldest) directoryHistoryRef.current.delete(oldest);
    }
    directoryHistoryRef.current.set(key, { ...stamp });
    directoryNodeRef.current = stamp.directory_node_id;
    directoryRevisionRef.current = Math.max(directoryRevisionRef.current, stamp.directory_revision);
    directoryStampRef.current = { ...stamp };
    return true;
  }, []);

  const knownDirectoryEvidence = useCallback((frame: Extract<IncomingFrame, { type: "message" }>): "accepted" | "unknown-old" | "conflict" => {
    if (typeof frame.directory_node_id !== "string" ||
      !/^[A-Za-z0-9._:-]{1,128}$/u.test(frame.directory_node_id) ||
      typeof frame.directory_revision !== "number" ||
      !Number.isSafeInteger(frame.directory_revision) ||
      frame.directory_revision < 1 || frame.directory_revision > MAX_DIRECTORY_REVISION ||
      typeof frame.directory_digest !== "string" ||
      !canonicalBase64Bytes(frame.directory_digest, 32)) return "conflict";
    const key = `${frame.directory_node_id}\u0000${frame.directory_revision}\u0000${frame.directory_digest}`;
    if (directoryHistoryRef.current.has(key)) return "accepted";
    if (frame.directory_node_id !== directoryNodeRef.current ||
      frame.directory_revision > directoryRevisionRef.current) return "conflict";
    if (frame.directory_revision === directoryRevisionRef.current) return "conflict";
    return "unknown-old";
  }, []);

  const applyFrame = useCallback(async (frame: IncomingFrame) => {
    if (frame.type === "GLOBAL_WIPE" || frame.type === "global_wipe") {
      clearMemory();
      return;
    }
    if (frame.type === "presence") {
      const presenceGeneration = sessionGenerationRef.current;
      const presenceToken = sessionRef.current?.token;
      if (!presenceToken) return;
      if (frame.users.length === 0 || frame.users.length > MAX_PRESENCE_USERS ||
        frame.users.some((user) => !validPresence(user))) {
        clearMemory();
        return;
      }
      const usernames = new Set<string>();
      const next = frame.users.filter((user) => {
        const key = user.username.toLowerCase();
        if (usernames.has(key)) return false;
        usernames.add(key);
        return true;
      });
      if (next.length !== frame.users.length) {
        clearMemory();
        return;
      }
      const newPinCount = [...usernames].reduce(
        (count, username) => count + Number(!identityPinsRef.current.has(username)),
        0,
      );
      if (identityPinsRef.current.size + newPinCount > MAX_PINNED_IDENTITIES) {
        clearMemory();
        return;
      }
      if (new Set(next.map((user) => user.directory_digest)).size > 1) {
        clearMemory();
        return;
      }
      const stamp = presenceDirectoryStamp(next);
      if (!stamp || new Set(next.map((user) => user.directory_node_id)).size !== 1 ||
        new Set(next.map((user) => user.directory_revision)).size !== 1) {
        clearMemory();
        return;
      }
      try {
        const recomputed = await directoryDigestV2(
          stamp.directory_node_id,
          stamp.directory_revision,
          next,
        );
        if (presenceGeneration !== sessionGenerationRef.current ||
          sessionRef.current?.token !== presenceToken) return;
        if (recomputed !== stamp.directory_digest || !rememberDirectoryStamp(stamp)) {
          clearMemory();
          return;
        }
        socketRef.current?.setDirectoryStamp(stamp);
      } catch {
        clearMemory();
        return;
      }
      const identityChanged = next.some((user) => {
        const key = user.username.toLowerCase();
        const pinned = identityPinsRef.current.get(key);
        const fingerprint = stableIdentityFingerprint(user.identity_public_b64);
        if (pinned && pinned !== fingerprint) return true;
        identityPinsRef.current.set(key, fingerprint);
        return false;
      });
      if (identityChanged) {
        clearMemory();
        return;
      }
      presenceRef.current = next;
      setPresence(next);
      return;
    }
    if (frame.type === "mls_rooms") {
      try {
        const next = mlsRef.current?.recoverCatalog(frame.rooms);
        if (!next) throw new Error("Room unavailable");
        roomsRef.current = next;
        setRooms(next);
      } catch { clearMemory(); }
      return;
    }
    if (frame.type === "mls_room_created") {
      const nextRoom = roomFromMlsWire(frame.room);
      roomsRef.current = [...roomsRef.current.filter((room) => room.id !== nextRoom.id), nextRoom];
      setRooms(roomsRef.current);
      return;
    }
    if (frame.type === "mls_room_discovered") {
      try {
        const request = mlsRef.current?.beginJoin(frame);
        if (!request || !socketRef.current?.sendMlsControl(request)) throw new Error("Room unavailable");
      } catch { setNotice("Action unavailable."); }
      return;
    }
    if (frame.type === "mls_join_requested") {
      try { mlsRef.current?.rememberJoin(frame); setPendingMlsJoins(mlsRef.current?.pendingJoins() ?? []); }
      catch { clearMemory(); }
      return;
    }
    if (frame.type === "mls_join_rejected") {
      try {
        const manager = mlsRef.current;
        if (!manager) throw new Error("Room unavailable");
        manager.rejectOwnJoin(frame.room_id, frame.request_id);
        roomsRef.current = roomsRef.current.filter((room) => room.id !== frame.room_id);
        setRooms(roomsRef.current);
        setNotice("Action unavailable.");
      } catch { clearMemory(); }
      return;
    }
    if (frame.type === "mls_leave_requested") {
      try {
        mlsRef.current?.rememberLeave(frame);
        setPendingMlsLeaves(mlsRef.current?.pendingLeaves() ?? []);
      } catch { clearMemory(); }
      return;
    }
    if (frame.type === "mls_leave_pending") {
      if (!mlsRef.current?.pendingLeaves().some((leave) => leave.roomId === frame.room_id && leave.requestId === frame.request_id)) {
        clearMemory();
      }
      return;
    }
    if (frame.type === "mls_leave_rejected") {
      try {
        mlsRef.current?.forgetLeave(frame.room_id, frame.request_id);
        setPendingMlsLeaves(mlsRef.current?.pendingLeaves() ?? []);
        setNotice("Action unavailable.");
      } catch { clearMemory(); }
      return;
    }
    if (frame.type === "mls_left" || frame.type === "mls_room_deleted") {
      mlsRef.current?.removeRoom(frame.room_id);
      roomsRef.current = roomsRef.current.filter((room) => room.id !== frame.room_id);
      setRooms(roomsRef.current);
      updateMessages((current) => { const next = { ...current }; wipeMessageList(next[frame.room_id]); delete next[frame.room_id]; return next; });
      if (activeRoomRef.current === frame.room_id) { activeRoomRef.current = null; setActiveRoomId(null); }
      return;
    }
    if (frame.type === "mls_membership") {
      try {
        const snapshot = mlsRef.current?.receiveMembership(frame);
        if (!snapshot) throw new Error("Room unavailable");
        const outcome = await sendMlsSnapshotRef.current(snapshot);
        if (outcome !== "ACCEPTED") throw new Error("Room unavailable");
        mlsSnapshotsRef.current.set(`${frame.room_id}\u0000${frame.message_id}`, { ...snapshot, nativePending: false });
        while (mlsSnapshotsRef.current.size > 256) mlsSnapshotsRef.current.delete(mlsSnapshotsRef.current.keys().next().value!);
        roomsRef.current = roomsRef.current.map((room) => room.id === frame.room_id ? {
          ...room, mlsActive: frame.roster.some((member) => member.username === sessionRef.current?.username),
          mlsEpoch: BigInt(frame.to_epoch), mlsRevision: BigInt(frame.revision), mlsMembers: frame.roster.map((member) => member.username),
        } : room);
        setRooms(roomsRef.current);
      } catch { clearMemory(); }
      return;
    }
    if (frame.type === "mls_application") {
      const generation = sessionGenerationRef.current; const token = sessionRef.current?.token;
      await cryptoGateRef.current.run(async () => {
        if (!token || generation !== sessionGenerationRef.current || sessionRef.current?.token !== token) return;
        const replay = `${frame.room_id}\u0000${frame.message_id}`;
        const prior = mlsSnapshotsRef.current.get(replay);
        if (prior) {
          if (await sendMlsSnapshotRef.current(prior) !== "ACCEPTED") clearMemory();
          return;
        }
        let plaintext: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
        try {
          const decrypted = mlsRef.current?.receiveApplication(frame);
          if (!decrypted) throw new Error("Payload unavailable");
          plaintext = decrypted.plaintext;
          const decoded = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext)) as unknown;
          const room = roomsRef.current.find((candidate) => candidate.id === frame.room_id);
          const message = plainRecord(decoded) && sessionRef.current
            ? parsePayload(frame.room_id, frame.message_id, decoded, room, sessionRef.current.username, frame.sender_username, undefined, ownMessageIdsRef.current)
            : null;
          if (!message || await sendMlsSnapshotRef.current(decrypted.snapshot) !== "ACCEPTED") throw new Error("Payload unavailable");
          mlsSnapshotsRef.current.set(replay, { ...decrypted.snapshot, nativePending: false });
          while (mlsSnapshotsRef.current.size > 256) mlsSnapshotsRef.current.delete(mlsSnapshotsRef.current.keys().next().value!);
          updateMessages((current) => appendBoundedMessage(current, message));
        } catch { clearMemory(); }
        finally { plaintext.fill(0); }
      });
      return;
    }
    if (frame.type.startsWith("mls_")) return;
    if (frame.type === "rooms") {
      if (!validRoomCatalog(frame.rooms)) return;
      roomsRef.current = frame.rooms;
      setRooms(frame.rooms);
      frame.rooms.forEach((room) => socketRef.current?.join(room.id));
      return;
    }
    if (frame.type === "room_created" && validRoom(frame.room)) {
      const roomKey = frame.room.id.toLowerCase();
      const existing = roomsRef.current.find((room) => room.id.toLowerCase() === roomKey);
      if ((existing && existing.id !== frame.room.id) ||
        (!existing && roomsRef.current.length >= MAX_ROOM_CATALOG)) return;
      roomsRef.current = [
        ...roomsRef.current.filter((room) => room.id.toLowerCase() !== roomKey),
        frame.room,
      ];
      setRooms(roomsRef.current);
      socketRef.current?.join(frame.room.id);
      return;
    }
    if (frame.type === "room_deleted") {
      roomsRef.current = roomsRef.current.filter((room) => room.id !== frame.chat_id);
      setRooms(roomsRef.current);
      updateMessages((current) => {
        const next = { ...current };
        wipeMessageList(next[frame.chat_id]);
        delete next[frame.chat_id];
        return next;
      });
      setActiveRoomId((current) => (current === frame.chat_id ? null : current));
      return;
    }
    if (frame.type === "directs") {
      if (!validDirectCatalog(frame.directs)) return;
      const next = frame.directs;
      directsRef.current = next;
      setDirects(next);
      next.forEach((direct) => socketRef.current?.join(direct.id));
      return;
    }
    if (frame.type === "direct_opened" && validDirect(frame.direct)) {
      const direct = frame.direct;
      const directId = direct.id.toLowerCase();
      const peer = direct.peer_username.toLowerCase();
      const idConflict = directsRef.current.find((current) => current.id.toLowerCase() === directId);
      const peerConflict = directsRef.current.find((current) => current.peer_username.toLowerCase() === peer);
      if ((idConflict && (idConflict.id !== direct.id || idConflict.peer_username.toLowerCase() !== peer)) ||
        (peerConflict && peerConflict.id.toLowerCase() !== directId) ||
        (!idConflict && directsRef.current.length >= MAX_DIRECT_CATALOG)) return;
      directsRef.current = [
        ...directsRef.current.filter((current) => current.id.toLowerCase() !== directId),
        direct,
      ];
      setDirects(directsRef.current);
      if (requestedDirectRef.current?.toLowerCase() === direct.peer_username.toLowerCase()) {
        requestedDirectRef.current = null;
        activeRoomRef.current = direct.id;
        setActiveRoomId(direct.id);
      }
      socketRef.current?.join(direct.id);
      return;
    }
    if (frame.type !== "message" || frame.version !== PROTOCOL_VERSION) return;

    const operationGeneration = sessionGenerationRef.current;
    const operationToken = sessionRef.current?.token;
    await cryptoGateRef.current.run(async () => {
      if (
        operationGeneration !== sessionGenerationRef.current ||
        !operationToken ||
        sessionRef.current?.token !== operationToken
      ) return;
      const currentSession = sessionRef.current;
      if (!currentSession) return;
      try {
      const senderKey = frame.sender_username.toLowerCase();
      const conversation = conversationForId(roomsRef.current, directsRef.current, frame.chat_id);
      if (!conversation || (conversation.conversation_type === "direct" &&
        conversation.peer_username?.toLowerCase() !== senderKey)) return;
      if (!presenceRef.current.some((user) => user.username.toLowerCase() === senderKey)) return;
      const directoryEvidence = knownDirectoryEvidence(frame);
      if (directoryEvidence === "conflict") {
        failClosed(currentSession);
        return;
      }
      if (directoryEvidence === "unknown-old") return;
      const pinnedFingerprint = identityPinsRef.current.get(senderKey);
      if (!pinnedFingerprint) return;
      let senderFingerprint = "";
      try {
        senderFingerprint = stableIdentityFingerprint(frame.sender_public_key_b64);
      } catch {
        return;
      }
      if (senderFingerprint !== pinnedFingerprint) return;
      const replayKey = `${frame.chat_id}\u0000${frame.sender_username}\u0000${frame.message_id}`;
      const directoryEvidenceKey = `${frame.directory_node_id}\u0000${frame.directory_revision}\u0000${frame.directory_digest}`;
      const processedDirectoryEvidence = receivedFrameIdsRef.current.get(replayKey);
      if (processedDirectoryEvidence !== undefined) {
        if (processedDirectoryEvidence !== directoryEvidenceKey) {
          failClosed(currentSession);
          return;
        }
        const stateSnapshot = cipherRef.current.stateSnapshot();
        if (!stateSnapshot) {
          clearMemory();
          return;
        }
        let ackOutcome: EncryptedSendOutcome = "NOT_SENT";
        let ackSignature: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
        try {
          ackSignature = cipherRef.current.signAcknowledgement(
            frame.chat_id,
            frame.message_id,
            frame.sender_username,
            frame.prekey_id,
          );
          ackOutcome = await (socketRef.current?.acknowledge(
            frame.chat_id,
            frame.message_id,
            frame.sender_username,
            stateSnapshot,
            ackSignature,
            frame.prekey_id,
          ) ?? Promise.resolve("NOT_SENT"));
        } catch {
          ackOutcome = "NOT_SENT";
        } finally {
          wipeBytes(stateSnapshot.envelope);
          wipeBytes(stateSnapshot.identityPublicKey);
          wipeBytes(stateSnapshot.stateSignature);
          wipeBytes(ackSignature);
        }
        if (
          operationGeneration !== sessionGenerationRef.current ||
          sessionRef.current?.token !== operationToken
        ) return;
        if (ackOutcome !== "ACCEPTED") failClosed(currentSession);
        return;
      }
      if (receivedFrameIdsRef.current.size >= 10_000) {
        const oldest = receivedFrameIdsRef.current.keys().next().value;
        if (oldest) receivedFrameIdsRef.current.delete(oldest);
      }
      let senderPublicKey: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
      let identityPublicKey: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
      let nonce: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
      let ciphertext: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
      let signature: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
      let wrappedKey: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
      let decrypted = "";
      try {
        senderPublicKey = base64ToBytes(frame.sender_public_key_b64);
        identityPublicKey = base64ToBytes(frame.identity_public_b64 ?? frame.sender_public_key_b64);
        nonce = base64ToBytes(frame.nonce_b64);
        ciphertext = base64ToBytes(frame.ciphertext_b64);
        signature = base64ToBytes(frame.signature_b64);
        wrappedKey = base64ToBytes(frame.wrapped_key_b64);
        decrypted = cipherRef.current.decryptText(
          frame.chat_id,
          frame.message_id,
          frame.sender_username,
          senderPublicKey,
          {
            version: frame.version,
            identityPublicKey,
            nonce,
            ciphertext,
          },
          signature,
          wrappedKey,
          frame.prekey_id,
          frame.is_prekey,
          currentSession.username,
        );
        let decryptedPayload: unknown;
        try {
          decryptedPayload = JSON.parse(decrypted) as unknown;
        } catch {
          failClosed(currentSession);
          return;
        }
        if (!directoryStampMatches(frame, decryptedPayload)) {
          failClosed(currentSession);
          return;
        }
        const stateSnapshot = cipherRef.current.stateSnapshot();
        if (!stateSnapshot) throw new Error("Identity unavailable");
        let ackOutcome: EncryptedSendOutcome = "NOT_SENT";
        let ackSignature: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
        try {
          ackSignature = cipherRef.current.signAcknowledgement(
            frame.chat_id,
            frame.message_id,
            frame.sender_username,
            frame.prekey_id,
          );
          ackOutcome = await (socketRef.current?.acknowledge(
            frame.chat_id,
            frame.message_id,
            frame.sender_username,
            stateSnapshot,
            ackSignature,
            frame.prekey_id,
          ) ?? Promise.resolve("NOT_SENT"));
        } catch {
          ackOutcome = "NOT_SENT";
        } finally {
          wipeBytes(stateSnapshot.envelope);
          wipeBytes(stateSnapshot.identityPublicKey);
          wipeBytes(stateSnapshot.stateSignature);
          wipeBytes(ackSignature);
        }
        if (
          operationGeneration !== sessionGenerationRef.current ||
          sessionRef.current?.token !== operationToken
        ) return;
        if (ackOutcome !== "ACCEPTED") {
          failClosed(currentSession);
          return;
        }
      } finally {
        wipeBytes(senderPublicKey);
        wipeBytes(identityPublicKey);
        wipeBytes(nonce);
        wipeBytes(ciphertext);
        wipeBytes(signature);
        wipeBytes(wrappedKey);
      }
      if (
        operationGeneration !== sessionGenerationRef.current ||
        sessionRef.current?.token !== operationToken
      ) return;
      receivedFrameIdsRef.current.set(replayKey, directoryEvidenceKey);
      const payload = JSON.parse(decrypted) as Record<string, unknown>;
      if (payload.kind === "read_receipt") {
        if (payload.id !== frame.message_id) return;
        const targetId = typeof payload.message_id === "string" ? payload.message_id : "";
        if (!ownMessageIdsRef.current.has(targetId)) return;
        const readAtMs = Date.now();
        updateMessages((current) => {
          const list = current[frame.chat_id];
          if (!list) return current;
          let changed = false;
          const next = list.map((message) => {
            if (message.id !== targetId || message.readAtMs !== undefined) return message;
            changed = true;
            return { ...message, readAtMs };
          });
          return changed ? { ...current, [frame.chat_id]: next } : current;
        });
        return;
      }
      const message = parsePayload(
        frame.chat_id,
        frame.message_id,
        payload,
        conversation,
        currentSession.username,
        frame.sender_username,
        frame.sender_public_key_b64,
        ownMessageIdsRef.current,
      );
      if (!message) return;
      if (isExpired(message, Date.now())) {
        wipeEvictedMessage(message);
        return;
      }
      if (message.mine) rememberBoundedId(ownMessageIdsRef.current, message.id, MAX_OWN_MESSAGE_IDS);
      if (activeRoomRef.current === frame.chat_id) {
        message.readAtMs = Date.now();
        sendReadReceiptRef.current(frame.chat_id, message.id);
      }
      updateMessages((current) => appendBoundedMessage(current, message));
      } catch (error) {
        if (
          error instanceof FatalCipherError &&
          operationGeneration === sessionGenerationRef.current &&
          sessionRef.current?.token === operationToken
        ) {
          failClosed(currentSession);
        }
        // Authentication failure or malformed plaintext stays outside UI state.
      }
    });
  }, [clearMemory, failClosed, knownDirectoryEvidence, rememberDirectoryStamp, updateMessages]);

  const login = useCallback(async (input: LoginInput): Promise<AccountSession> => {
    if (sessionRef.current || loginAbortRef.current) throw new Error("Action unavailable");
    const loginAbort = new AbortController();
    loginAbortRef.current = loginAbort;
    const ensureLoginActive = () => {
      if (loginAbort.signal.aborted || loginAbortRef.current !== loginAbort) {
        throw new Error("Action unavailable");
      }
    };
    const revokeDiscardedSession = async (candidate: AccountSession | null): Promise<void> => {
      if (!candidate) return;
      wipeBytes(candidate.identityPublicKey);
      await revokeSession(candidate).catch(() => undefined);
    };
    let nextSession: AccountSession | null = null;
    setNotice(null);
    setSecurityWarning(null);
    try {
      const endpoint = normalizeNodeUrl(input.nodeUrl);
      const opaque = await startOpaque(input.password);
      try {
        ensureLoginActive();
        const start = await startOpaqueAccount(
          endpoint,
          input.code,
          opaque.registrationRequest,
          opaque.credentialRequest,
          loginAbort.signal,
        );
        ensureLoginActive();
        let context: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
        let response: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
        try {
          context = identityContext(start.node_id, input.code);
          response = base64ToBytes(start.response_b64!);
          if (start.mode === "registration") {
            const result = await finishOpaqueRegistration(input.password, opaque, response);
            try {
              const identity = cipherRef.current.createIdentity(result.exportKey, context);
              const challenge = base64ToBytes(start.challenge_b64!);
              let identityProof: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
              try {
                ensureLoginActive();
                identityProof = cipherRef.current.signRegistrationIdentityProof(
                  start.node_id,
                  start.handshake_id!,
                  challenge,
                  result.registrationUpload,
                  identity.publicKey,
                  identity.prekeyId,
                  identity.envelope,
                );
                nextSession = await finishOpaqueAccount(endpoint, {
                  handshakeId: start.handshake_id!,
                  registrationUpload: result.registrationUpload,
                  identityPublicKey: identity.publicKey,
                  identityPrekeyId: identity.prekeyId,
                  identityEnvelope: identity.envelope,
                  identityProof,
                }, loginAbort.signal);
                ensureLoginActive();
              } finally {
                wipeBytes(challenge);
                wipeBytes(identityProof);
                wipeBytes(identity.publicKey);
                wipeBytes(identity.envelope);
              }
            } finally {
              wipeBytes(result.registrationUpload);
              wipeBytes(result.exportKey);
            }
          } else {
            const result = await finishOpaqueLogin(input.password, opaque, response);
            let identityPublic: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
            let identityEnvelope: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
            try {
              identityPublic = base64ToBytes(start.identity_public_b64!);
              identityEnvelope = base64ToBytes(start.identity_envelope_b64!);
              cipherRef.current.recoverIdentity(
                result.exportKey,
                context,
                identityEnvelope,
                identityPublic,
              );
              ensureLoginActive();
              nextSession = await finishOpaqueAccount(endpoint, {
                handshakeId: start.handshake_id!,
                credentialFinalization: result.credentialFinalization,
              }, loginAbort.signal);
              ensureLoginActive();
            } finally {
              wipeBytes(result.credentialFinalization);
              wipeBytes(result.exportKey);
              wipeBytes(identityPublic);
              wipeBytes(identityEnvelope);
            }
          }
        } finally {
          wipeBytes(context);
          wipeBytes(response);
        }
        if (
          !nextSession ||
          nextSession.nodeId !== start.node_id ||
          nextSession.created !== (start.mode === "registration")
        ) {
          throw new Error("Wrong information");
        }
      } finally {
        wipeOpaqueStart(opaque);
      }
    } catch (error) {
      cipherRef.current.clear();
      await revokeDiscardedSession(nextSession);
      if (loginAbortRef.current === loginAbort) loginAbortRef.current = null;
      throw error;
    }
    let candidateRelay: RelaySocket | null = null;
    try {
      ensureLoginActive();
      const currentPublicKey = cipherRef.current.publicKey();
      let identityMatches = false;
      try {
        identityMatches = nextSession !== null &&
          equalBytes(currentPublicKey, nextSession.identityPublicKey) &&
          cipherRef.current.prekeyId() === nextSession.identityPrekeyId;
      } finally {
        wipeBytes(currentPublicKey);
      }
      if (!identityMatches || !nextSession) {
        cipherRef.current.clear();
        if (nextSession) wipeBytes(nextSession.identityPublicKey);
        throw new Error("Wrong information");
      }
      mlsRef.current?.close();
      mlsRef.current = cipherRef.current.createMlsManager(nextSession.username, nextSession.nodeId);
      retainWhenHiddenRef.current = input.retainWhenHidden;
      const relayGeneration = sessionGenerationRef.current;
      lastActivityRef.current = Date.now();
      lastActivitySignalRef.current = Date.now();
      setRemainingSessionSec(nextSession.sessionInactivitySec);
      const candidate = nextSession;
      candidateRelay = new RelaySocket(
        candidate,
        (frame) => {
          if (sessionGenerationRef.current !== relayGeneration || sessionRef.current?.token !== candidate.token) return;
          frameQueueRef.current = frameQueueRef.current
            .then(async () => {
              if (sessionGenerationRef.current !== relayGeneration ||
                sessionRef.current?.token !== candidate.token) return;
              await applyFrame(frame);
            })
            .catch(() => {
              if (sessionGenerationRef.current === relayGeneration &&
                sessionRef.current?.token === candidate.token) failClosed(candidate);
            });
        },
        (state) => {
          if (sessionRef.current && sessionRef.current.token !== candidate.token) return;
          if (state !== "connected") {
            connectionGenerationRef.current += 1;
            clearDirectTrust();
            cancelAttachmentOperations();
            clearMedia();
            clearExportUrls();
          }
          setConnection(state);
        },
        () => {
          if (sessionGenerationRef.current === relayGeneration && sessionRef.current?.token === candidate.token) {
            failClosed(candidate);
          }
        },
        () => {
          if (sessionGenerationRef.current === relayGeneration && sessionRef.current?.token === candidate.token) {
            setSecurityWarning("ATTESTATION_REJECTED");
          }
        },
      );
      // Connect before publishing the session. WebSocket construction can
      // throw synchronously for a malformed endpoint; no partial session/ref
      // should be visible if that happens.
      candidateRelay.connect();
      ensureLoginActive();
      sessionRef.current = candidate;
      setSession(candidate);
      socketRef.current = candidateRelay;
      return candidate;
    } catch (error) {
      const candidate = nextSession;
      const activeRelay = socketRef.current;
      if (activeRelay) {
        activeRelay.close();
        socketRef.current = null;
      }
      if (candidateRelay && candidateRelay !== activeRelay) candidateRelay.close();
      if (candidate && sessionRef.current?.token === candidate.token) {
        sessionRef.current = null;
        setSession((current) => current?.token === candidate.token ? null : current);
      }
      mlsRef.current?.close();
      mlsRef.current = null;
      cipherRef.current.clear();
      retainWhenHiddenRef.current = false;
      lastActivityRef.current = 0;
      lastActivitySignalRef.current = 0;
      setRemainingSessionSec(0);
      setConnection("disconnected");
      await revokeDiscardedSession(candidate);
      throw error;
    } finally {
      if (loginAbortRef.current === loginAbort) loginAbortRef.current = null;
    }
  }, [applyFrame, cancelAttachmentOperations, clearDirectTrust, clearExportUrls, clearMedia, failClosed]);

  useEffect(() => {
    if (connection !== "connected") return;
    directs.forEach((direct) => socketRef.current?.join(direct.id));
  }, [connection, directs]);

  useEffect(() => {
    refreshDirectTrust();
  }, [activeRoomId, connection, presence, refreshDirectTrust, session]);

  useEffect(() => {
    if (!session) return;
    const timer = window.setInterval(() => {
      const now = Date.now();
      const remaining = Math.max(0, Math.ceil((lastActivityRef.current + session.sessionInactivitySec * 1000 - now) / 1000));
      setRemainingSessionSec(remaining);
      if (remaining === 0) void logout();
      updateMessages((current) => pruneExpired(current, now));
    }, 500);
    return () => window.clearInterval(timer);
  }, [logout, session, updateMessages]);

  useEffect(() => {
    const pageHide = () => {
      document.documentElement.classList.add("abyssal-page-hidden");
      const current = sessionRef.current;
      if (current) void revokeSession(current);
      flushSync(clearMemory);
    };
    const pageShow = (event: PageTransitionEvent) => {
      document.documentElement.classList.remove("abyssal-page-hidden");
      if (event.persisted) clearMemory();
    };
    window.addEventListener("pagehide", pageHide);
    window.addEventListener("pageshow", pageShow);
    return () => {
      window.removeEventListener("pagehide", pageHide);
      window.removeEventListener("pageshow", pageShow);
    };
  }, [clearMemory]);

  const markRoomRead = useCallback((chatId: string) => {
    const trusted = directOperationAllowed(chatId);
    const knownChat = roomsRef.current.some((room) => room.id === chatId) ||
      directsRef.current.some((direct) => direct.id === chatId);
    if (!knownChat) return;
    const now = Date.now();
    const receipts: string[] = [];
    updateMessages((current) => {
      const roomMessages = current[chatId];
      if (!roomMessages) return current;
      let changed = false;
      const nextMessages = roomMessages.map((message) => {
        if (message.mine || message.readAtMs !== undefined) return message;
        changed = true;
        receipts.push(message.id);
        return { ...message, readAtMs: now };
      });
      return changed ? { ...current, [chatId]: nextMessages } : current;
    });
    if (trusted) receipts.forEach((messageId) => sendReadReceiptRef.current(chatId, messageId));
  }, [directOperationAllowed, updateMessages]);

  const openRoom = useCallback((chatId: string | null) => {
    clearMedia();
    setNotice(null);
    activeRoomRef.current = chatId;
    setActiveRoomId(chatId);
    if (chatId) {
      socketRef.current?.join(chatId);
      window.setTimeout(() => markRoomRead(chatId), 350);
    }
  }, [clearMedia, markRoomRead]);

  const openDirect = useCallback((peerUsername: string): boolean => {
    clearMedia();
    setNotice(null);
    const existing = directsRef.current.find(
      (direct) => direct.peer_username.toLowerCase() === peerUsername.trim().toLowerCase(),
    );
    if (existing) {
      openRoom(existing.id);
      return true;
    }
    if (connection !== "connected") return false;
    requestedDirectRef.current = peerUsername.trim();
    return socketRef.current?.openDirect(peerUsername.trim()) ?? false;
  }, [clearMedia, connection, openRoom]);

  const recipientKeysFor = useCallback((chatId: string, includeSelf = false) => {
    const currentSession = sessionRef.current;
    if (!currentSession) return [];
    const direct = directsRef.current.find((candidate) => candidate.id === chatId);
    const usernames = direct
      ? new Set([direct.peer_username])
      : new Set(
          presenceRef.current
            .map((user) => user.username)
            .filter((username) => username !== currentSession.username),
        );
    const recipients = presenceRef.current
      .filter((user) => usernames.has(user.username))
      .map((user) => ({
        username: user.username,
        publicKey: base64ToBytes(user.identity_public_b64),
        prekeyId: user.identity_prekey_id,
      }));
    if (includeSelf) {
      recipients.push({
        username: currentSession.username,
        publicKey: currentSession.identityPublicKey.slice(),
        prekeyId: currentSession.identityPrekeyId,
      });
    }
    return recipients;
  }, []);

  const runOutboundTransaction = useCallback(async (
    currentSession: AccountSession,
    generation: number,
    connectionGeneration: number,
    chatId: string,
    messageId: string,
    recipients: Array<{ username: string; publicKey: Uint8Array; prekeyId: string }>,
    createPayload: (directoryStamp: DirectoryStamp) => EncryptedPayload,
  ): Promise<EncryptedSendOutcome> => {
    let encrypted: EncryptedPayload | null = null;
    let staged = false;
    let admissionAttempted = false;
    const acquiredLeases: PrekeyLease[] = [];
    const directoryStamp = directoryStampRef.current ? { ...directoryStampRef.current } : null;
    if (!directoryStamp) return "NOT_SENT";
    let leasesReleaseAttempted = false;
    const active = () => generation === sessionGenerationRef.current &&
      connectionGeneration === connectionGenerationRef.current &&
      sessionRef.current?.token === currentSession.token;
    const releaseAcquiredLeases = () => {
      if (leasesReleaseAttempted || !active()) return;
      leasesReleaseAttempted = true;
      acquiredLeases.forEach((lease) => {
        try {
          socketRef.current?.releasePrekeyLease(lease);
        } catch {
          // Lease cleanup is best effort; the relay owns the final expiry.
        }
      });
    };
    try {
      const outcome = await cryptoGateRef.current.run(async () => {
        if (!active()) return "NOT_SENT" as const;
        try {
          for (const recipient of recipients) {
            if (!cipherRef.current.requiresPrekey(recipient.username)) continue;
            let lease: PrekeyLease;
            try {
              lease = await (socketRef.current?.requestPrekeyLease(
                chatId,
                messageId,
                recipient.username,
              ) ?? Promise.reject(new PrekeyLeaseError("NOT_SENT")));
            } catch (error) {
              // Only this request's lease is unknown. Every earlier response
              // is known unused and must be released before propagating the
              // failure (including AMBIGUOUS/CLOSED outcomes).
              releaseAcquiredLeases();
              throw error;
            }
            if (!active()) {
              wipeBytes(lease.recipientPublicKey);
              return "NOT_SENT" as const;
            }
            acquiredLeases.push(lease);
            wipeBytes(recipient.publicKey);
            recipient.publicKey = lease.recipientPublicKey.slice();
            recipient.prekeyId = lease.prekeyId;
          }
          if (!active()) return "NOT_SENT" as const;
          encrypted = createPayload(directoryStamp);
          staged = true;
          const stagedPayload = encrypted;
          const frame = payloadToFrame(stagedPayload);
          admissionAttempted = true;
          const sent = await (socketRef.current?.sendEncryptedPayload(
            messageId,
            {
              type: "message",
              chat_id: chatId,
              ...frame,
              ...(directoryStamp ? directoryStampFields(directoryStamp) : {}),
            },
          ) ?? Promise.resolve("NOT_SENT" as const));
          if (!active()) {
            if (sent === "ACCEPTED") failClosed(currentSession);
            return sent === "ACCEPTED" ? "AMBIGUOUS" : "NOT_SENT";
          }
          if (sent === "ACCEPTED") {
            try {
              cipherRef.current.commitOutbound(messageId, stagedPayload.stateRevision);
            } catch {
              failClosed(currentSession);
              return "AMBIGUOUS" as const;
            }
            return sent;
          }
          if (sent === "REJECTED" || sent === "NOT_SENT") {
            try {
              cipherRef.current.rollbackOutbound(messageId, stagedPayload.stateRevision);
            } catch {
              releaseAcquiredLeases();
              failClosed(currentSession);
              return "AMBIGUOUS" as const;
            }
            releaseAcquiredLeases();
            return sent;
          }
          failClosed(currentSession);
          return sent;
        } catch (error) {
          if (error instanceof FatalCipherError) {
            // Native encryption failed before admission when this flag is
            // still clear. The lease claims are therefore definitely unused;
            // release them while the authenticated relay is still active,
            // then discard the now-invalid native identity.
            if (!admissionAttempted) releaseAcquiredLeases();
            if (active()) failClosed(currentSession);
            return "AMBIGUOUS" as const;
          }
          if (admissionAttempted) {
            if (active()) failClosed(currentSession);
            return "AMBIGUOUS" as const;
          }
          if (staged && active() && encrypted) {
            try {
              cipherRef.current.rollbackOutbound(messageId, encrypted.stateRevision);
            } catch {
              if (!admissionAttempted) releaseAcquiredLeases();
              failClosed(currentSession);
              return "AMBIGUOUS" as const;
            }
          }
          releaseAcquiredLeases();
          return "NOT_SENT" as const;
        }
      });
      return outcome;
    } finally {
      if (encrypted) wipeEncryptedPayload(encrypted);
      acquiredLeases.forEach((lease) => wipeBytes(lease.recipientPublicKey));
      recipients.forEach((recipient) => wipeBytes(recipient.publicKey));
    }
  }, [failClosed]);

  const runMlsTransaction = useCallback(async (
    currentSession: AccountSession,
    generation: number,
    connectionGeneration: number,
    prepared: PreparedMlsApplication,
  ): Promise<EncryptedSendOutcome> => {
    const active = () => generation === sessionGenerationRef.current &&
      connectionGeneration === connectionGenerationRef.current && sessionRef.current?.token === currentSession.token;
    let outcome: EncryptedSendOutcome = "NOT_SENT";
    try {
      if (!active()) return outcome;
      outcome = await (socketRef.current?.sendMlsTransaction(
        prepared.roomId, prepared.messageId, prepared.revision, prepared.frame,
      ) ?? Promise.resolve("NOT_SENT"));
      if (!active()) outcome = outcome === "ACCEPTED" ? "AMBIGUOUS" : "NOT_SENT";
      mlsRef.current?.finishTransaction(prepared, outcome);
      if (outcome === "AMBIGUOUS") failClosed(currentSession);
      return outcome;
    } catch {
      if (active()) failClosed(currentSession);
      return "AMBIGUOUS";
    }
  }, [failClosed]);

  const runMlsSnapshotTransaction = useCallback(async (prepared: PreparedMlsSnapshot): Promise<EncryptedSendOutcome> => {
    const current = sessionRef.current; const generation = sessionGenerationRef.current;
    const connectionGeneration = connectionGenerationRef.current;
    if (!current || connection !== "connected") return "NOT_SENT";
    const active = () => generation === sessionGenerationRef.current && connectionGeneration === connectionGenerationRef.current &&
      sessionRef.current?.token === current.token;
    try {
      const raw = await (socketRef.current?.sendMlsSnapshot(prepared.roomId, prepared.messageId, prepared.revision, prepared.frame) ?? Promise.resolve("NOT_SENT"));
      const outcome: EncryptedSendOutcome = active() ? raw : raw === "ACCEPTED" ? "AMBIGUOUS" : "NOT_SENT";
      mlsRef.current?.finishSnapshot(prepared, outcome);
      if (outcome === "AMBIGUOUS") failClosed(current);
      return outcome;
    } catch { if (active()) failClosed(current); return "AMBIGUOUS"; }
  }, [connection, failClosed]);

  useEffect(() => { sendMlsSnapshotRef.current = runMlsSnapshotTransaction; }, [runMlsSnapshotTransaction]);

  const sendReadReceipt = useCallback((chatId: string, messageId: string) => {
    const currentSession = sessionRef.current;
    if (!currentSession || connection !== "connected" || !validControlId(messageId)) return;
    const conversation = conversationForId(roomsRef.current, directsRef.current, chatId);
    if (!conversation || conversation.mlsActive !== undefined || !directOperationAllowed(chatId)) return;
    const recipients = recipientKeysFor(chatId);
    if (recipients.length === 0) return;
    const generation = sessionGenerationRef.current;
    const connectionGeneration = connectionGenerationRef.current;
    const receiptId = crypto.randomUUID();
    void runOutboundTransaction(
      currentSession,
      generation,
      connectionGeneration,
      chatId,
      receiptId,
      recipients,
      (directoryStamp) => cipherRef.current.encryptText(
        chatId,
        receiptId,
        currentSession.username,
        JSON.stringify({
          kind: "read_receipt", id: receiptId, message_id: messageId,
          ...(directoryStamp ? directoryStampFields(directoryStamp) : {}),
        }),
        recipients,
      ),
    );
  }, [connection, directOperationAllowed, recipientKeysFor, runOutboundTransaction]);

  useEffect(() => {
    sendReadReceiptRef.current = sendReadReceipt;
  }, [sendReadReceipt]);

  const sendText = useCallback(async (content: string, replyToId?: string, retentionSec?: number): Promise<boolean> => {
    const currentSession = sessionRef.current;
    const chatId = activeRoomId;
    const room = conversationForId(roomsRef.current, directsRef.current, chatId);
    const clean = content.trim();
    if (!currentSession || !chatId || !room || !clean || connection !== "connected") return false;
    if (!directOperationAllowed(chatId)) {
      setNotice("Verify this direct chat's safety number before sending.");
      return false;
    }
    const connectionGeneration = connectionGenerationRef.current;
    if (connectionGeneration !== connectionGenerationRef.current || connection !== "connected") return false;
    const recipients = recipientKeysFor(chatId);
    const isMlsRoom = room.conversation_type !== "direct" && room.mlsActive !== undefined;
    if (!isMlsRoom && recipients.length === 0) return false;
    const generation = sessionGenerationRef.current;
    const now = Date.now();
    const message: ChatMessage = {
      id: crypto.randomUUID(),
      chatId,
      sender: currentSession.username,
      content: clean.slice(0, 8_000),
      kind: "text",
      createdAtMs: now,
      receivedAtMs: now,
      selfDestructSec: room.conversation_type === "direct"
        ? clampDirectRetention(retentionSec)
        : readRetention(room),
      absoluteExpirySec: absoluteRetention(room),
      replyToId: validReplyId(messages[chatId], replyToId),
      mine: true,
      senderClient: LOCAL_SENDER_CLIENT,
    };
    if (isMlsRoom) {
      let plaintext = new Uint8Array(0);
      try {
        plaintext = new TextEncoder().encode(JSON.stringify(messagePayload(message, directoryStampRef.current)));
        const prepared = mlsRef.current?.prepareApplication(chatId, message.id, currentSession.username, plaintext);
        if (!prepared) return false;
        const outcome = await runMlsTransaction(currentSession, generation, connectionGeneration, prepared);
        if (outcome === "ACCEPTED") {
          rememberBoundedId(ownMessageIdsRef.current, message.id, MAX_OWN_MESSAGE_IDS);
          updateMessages((current) => appendBoundedMessage(current, message));
        }
        return outcome === "ACCEPTED";
      } catch { return false; }
      finally { plaintext.fill(0); }
    }
    const outcome = await runOutboundTransaction(
      currentSession,
      generation,
      connectionGeneration,
      chatId,
      message.id,
      recipients,
      (directoryStamp) => cipherRef.current.encryptText(
        chatId,
        message.id,
        currentSession.username,
        JSON.stringify(messagePayload(message, directoryStamp)),
        recipients,
      ),
    );
    if (outcome === "ACCEPTED") {
      rememberBoundedId(ownMessageIdsRef.current, message.id, MAX_OWN_MESSAGE_IDS);
      updateMessages((current) => appendBoundedMessage(current, message));
    }
    return outcome === "ACCEPTED";
  }, [activeRoomId, connection, directOperationAllowed, messages, recipientKeysFor, runMlsTransaction, runOutboundTransaction, updateMessages]);

  const sendAttachment = useCallback(async ({ file, options, replyToId, reactionShortcode }: AttachmentInput): Promise<boolean> => {
    const currentSession = sessionRef.current;
    const chatId = activeRoomId;
    const room = conversationForId(roomsRef.current, directsRef.current, chatId);
    const mediaType = classifyMedia(file);
    const reaction = reactionByShortcode(reactionShortcode);
    if (
      !currentSession ||
      !chatId ||
      !room ||
      connection !== "connected" ||
      file.size <= 0 ||
      file.size > MEDIA_LIMIT_BYTES[mediaType] ||
      !mediaAllowed(room, mediaType) ||
      (reactionShortcode !== undefined && (
        !reaction ||
        reaction.filename !== file.name ||
        reaction.mimeType !== file.type
      ))
    ) {
      setNotice("Action unavailable.");
      return false;
    }
    if (!directOperationAllowed(chatId)) {
      setNotice("Verify this direct chat's safety number before sending.");
      return false;
    }
    const recipients = recipientKeysFor(chatId);
    const isMlsRoom = room.conversation_type !== "direct" && room.mlsActive !== undefined;
    if (!isMlsRoom && recipients.length === 0) {
      setNotice("Action unavailable.");
      return false;
    }

    let plain: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let encrypted: EncryptedAttachment | null = null;
    let message: ChatMessage | null = null;
    let retainedMessage: ChatMessage | null = null;
    let uploadedAttachmentId: string | null = null;
    let metadataAmbiguous = false;
    const operation = startAttachmentOperation(() => {
      wipeBytes(plain);
      if (encrypted) {
        wipeBytes(encrypted.key);
        wipeBytes(encrypted.blob);
      }
      if (!retainedMessage?.attachment && message?.attachment) {
        wipeBytes(message.attachment.encryptionKey);
      }
    });
    try {
      setUpload({ active: true, name: file.name || "attachment", loaded: 0, total: file.size });
      const fileBuffer = await file.arrayBuffer();
      plain = new Uint8Array(fileBuffer);
      if (!attachmentOperationActive(operation, currentSession.token)) throw new Error("Action unavailable");
      const messageId = crypto.randomUUID();
      encrypted = cipherRef.current.encryptAttachment(
        chatId,
        messageId,
        currentSession.username,
        mediaType,
        plain,
      );
      if (!attachmentOperationActive(operation, currentSession.token)) throw new Error("Action unavailable");
      const ttlSec = absoluteRetention(room, mediaType);
      const attachmentId = await uploadEncryptedAttachment(
        currentSession,
        chatId,
        messageId,
        mediaType,
        encrypted.blob,
        { ...options, ttlSec },
        (progress) => {
          if (attachmentOperationActive(operation, currentSession.token)) {
            setUpload({ active: true, name: file.name || "attachment", ...progress });
          }
        },
        operation.controller.signal,
      );
      uploadedAttachmentId = attachmentId;
      if (!attachmentOperationActive(operation, currentSession.token)) throw new Error("Action unavailable");
      const now = Date.now();
      const outgoingMessage: ChatMessage = {
        id: messageId,
        chatId,
        sender: currentSession.username,
        content: file.name || "attachment",
        kind: "attachment",
        createdAtMs: now,
        receivedAtMs: now,
        selfDestructSec: room.conversation_type === "direct"
          ? clampDirectRetention(options.readSec)
          : readRetention(room, mediaType),
        absoluteExpirySec: ttlSec,
        replyToId: validReplyId(messages[chatId], replyToId),
        mine: true,
        senderClient: LOCAL_SENDER_CLIENT,
        senderPublicKeyB64: bytesToBase64(currentSession.identityPublicKey),
        attachment: {
          id: attachmentId,
          encryptionVersion: encrypted.version,
          encryptionKey: encrypted.key.slice(),
          name: (file.name || "attachment").slice(0, 160),
          mediaType,
          mimeType: (file.type || "application/octet-stream").slice(0, 120),
          sizeBytes: file.size,
          oneTime: options.oneTime,
          deleteAfterDownload: options.deleteAfterDownload || options.oneTime,
          reactionShortcode: reaction?.shortcode,
        },
      };
      message = outgoingMessage;
      let outcome: EncryptedSendOutcome;
      if (!isMlsRoom) {
        outcome = await runOutboundTransaction(
          currentSession, operation.generation, operation.connectionGeneration, chatId, outgoingMessage.id, recipients,
          (directoryStamp) => cipherRef.current.encryptText(
            chatId, outgoingMessage.id, currentSession.username,
            JSON.stringify(messagePayload(outgoingMessage, directoryStamp)), recipients,
          ),
        );
      } else {
        const metadata = new TextEncoder().encode(JSON.stringify(messagePayload(outgoingMessage, directoryStampRef.current)));
        try {
          const prepared = mlsRef.current?.prepareApplication(chatId, outgoingMessage.id, currentSession.username, metadata);
          outcome = prepared
            ? await runMlsTransaction(currentSession, operation.generation, operation.connectionGeneration, prepared)
            : "NOT_SENT";
        } finally { metadata.fill(0); }
      }
      metadataAmbiguous = outcome === "AMBIGUOUS";
      if (outcome === "ACCEPTED") {
        rememberBoundedId(ownMessageIdsRef.current, outgoingMessage.id, MAX_OWN_MESSAGE_IDS);
        updateMessages((current) => appendBoundedMessage(current, outgoingMessage));
        retainedMessage = outgoingMessage;
      }
      return outcome === "ACCEPTED";
    } catch {
      if (attachmentOperationActive(operation, currentSession.token)) setNotice("Action unavailable.");
      return false;
    } finally {
      finishAttachmentOperation(operation);
      recipients.forEach((recipient) => wipeBytes(recipient.publicKey));
      if (uploadedAttachmentId && !retainedMessage && !metadataAmbiguous &&
        operation.connectionGeneration === connectionGenerationRef.current) {
        await deleteUploadedAttachment(currentSession, uploadedAttachmentId).catch(() => undefined);
      }
      if (operation.generation === sessionGenerationRef.current) setUpload(EMPTY_UPLOAD);
    }
  }, [
    activeRoomId,
    attachmentOperationActive,
    connection,
    directOperationAllowed,
    finishAttachmentOperation,
    messages,
    recipientKeysFor,
    runMlsTransaction,
    runOutboundTransaction,
    startAttachmentOperation,
    updateMessages,
  ]);

  const viewAttachment = useCallback(async (message: ChatMessage): Promise<void> => {
    const currentSession = sessionRef.current;
    const attachment = message.attachment;
    const chatId = activeRoomRef.current;
    if (!currentSession || !attachment || !chatId || message.chatId !== chatId ||
      !conversationForId(roomsRef.current, directsRef.current, message.chatId) ||
      connection !== "connected") return;
    if (!directOperationAllowed(message.chatId)) {
      setNotice("Verify this direct chat's safety number before opening attachments.");
      return;
    }
    clearMedia();
    let encrypted: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let plain: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let key: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let downloaded: DownloadedEncryptedAttachment | null = null;
    let claimHandled = false;
    let objectUrl: string | null = null;
    const operation = startAttachmentOperation(() => {
      wipeBytes(key);
      wipeBytes(encrypted);
      wipeBytes(plain);
    });
    try {
      if (!attachmentOperationActive(operation, currentSession.token)) throw new Error("Action unavailable");
      if (
        attachment.encryptionVersion !== ATTACHMENT_CIPHER_VERSION ||
        attachment.encryptionKey.byteLength !== 32
      ) throw new Error("Payload unavailable");
      key = attachment.encryptionKey.slice();
      downloaded = await downloadEncryptedAttachment(
        currentSession,
        attachment.id,
        { mediaType: attachment.mediaType, expectedPlaintextBytes: attachment.sizeBytes },
        operation.controller.signal,
      );
      encrypted = downloaded.bytes;
      if (!attachmentOperationActive(operation, currentSession.token)) throw new Error("Action unavailable");
      try {
        plain = await decryptAndCompleteAttachment(
          currentSession,
          attachment.id,
          downloaded,
          () => {
            if (!attachmentOperationActive(operation, currentSession.token)) throw new Error("Action unavailable");
            return cipherRef.current.decryptAttachment(
              message.chatId,
              message.id,
              message.sender,
              attachment.mediaType,
              key,
              encrypted,
            );
          },
          attachmentPlaintextPolicy(attachment),
          operation.controller.signal,
        );
      } finally {
        claimHandled = downloaded.claim !== undefined;
      }
      if (downloaded.claim) wipeMessageAttachment(message);
      if (!attachmentOperationActive(operation, currentSession.token)) throw new Error("Action unavailable");
      const blob = attachmentDownloadBlob(plain, attachment.mimeType);
      objectUrl = URL.createObjectURL(blob);
      if (!attachmentOperationActive(operation, currentSession.token)) throw new Error("Action unavailable");
      const nextMedia: DecryptedMedia = {
        messageId: message.id,
        name: attachment.name,
        mediaType: attachment.mediaType,
        mimeType: attachment.mimeType,
        objectUrl,
        oneTime: attachment.oneTime,
      };
      mediaRef.current = nextMedia;
      setMedia(nextMedia);
      objectUrl = null;
      markRoomRead(message.chatId);
      if (attachment.oneTime) wipeMessageAttachment(message);
    } catch {
      if (objectUrl) URL.revokeObjectURL(objectUrl);
      if (downloaded?.claim && !claimHandled) {
        await releaseAttachmentDownloadClaim(currentSession, attachment.id, downloaded.claim).catch(() => undefined);
      }
      if (attachmentOperationActive(operation, currentSession.token)) setNotice("Action unavailable.");
    } finally {
      finishAttachmentOperation(operation);
    }
  }, [
    attachmentOperationActive,
    clearMedia,
    connection,
    directOperationAllowed,
    finishAttachmentOperation,
    markRoomRead,
    startAttachmentOperation,
  ]);

  const exportAttachment = useCallback(async (message: ChatMessage): Promise<void> => {
    const currentSession = sessionRef.current;
    const attachment = message.attachment;
    const chatId = activeRoomRef.current;
    if (!currentSession || !attachment || attachment.oneTime || !chatId || message.chatId !== chatId ||
      !conversationForId(roomsRef.current, directsRef.current, message.chatId) ||
      connection !== "connected") return;
    if (!directOperationAllowed(message.chatId)) {
      setNotice("Verify this direct chat's safety number before exporting attachments.");
      return;
    }
    let encrypted: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let plain: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let key: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let downloaded: DownloadedEncryptedAttachment | null = null;
    let claimHandled = false;
    let exportUrl: string | null = null;
    const operation = startAttachmentOperation(() => {
      wipeBytes(key);
      wipeBytes(encrypted);
      wipeBytes(plain);
    });
    try {
      if (!attachmentOperationActive(operation, currentSession.token)) throw new Error("Action unavailable");
      if (
        attachment.encryptionVersion !== ATTACHMENT_CIPHER_VERSION ||
        attachment.encryptionKey.byteLength !== 32
      ) throw new Error("Payload unavailable");
      key = attachment.encryptionKey.slice();
      downloaded = await downloadEncryptedAttachment(
        currentSession,
        attachment.id,
        { mediaType: attachment.mediaType, expectedPlaintextBytes: attachment.sizeBytes },
        operation.controller.signal,
      );
      encrypted = downloaded.bytes;
      if (!attachmentOperationActive(operation, currentSession.token)) throw new Error("Action unavailable");
      try {
        plain = await decryptAndCompleteAttachment(
          currentSession,
          attachment.id,
          downloaded,
          () => {
            if (!attachmentOperationActive(operation, currentSession.token)) throw new Error("Action unavailable");
            return cipherRef.current.decryptAttachment(
              message.chatId,
              message.id,
              message.sender,
              attachment.mediaType,
              key,
              encrypted,
            );
          },
          attachmentPlaintextPolicy(attachment),
          operation.controller.signal,
        );
      } finally {
        claimHandled = downloaded.claim !== undefined;
      }
      if (downloaded.claim) wipeMessageAttachment(message);
      if (!attachmentOperationActive(operation, currentSession.token)) throw new Error("Action unavailable");
      exportUrl = URL.createObjectURL(attachmentDownloadBlob(plain, attachment.mimeType));
      if (!attachmentOperationActive(operation, currentSession.token)) throw new Error("Action unavailable");
      exportUrlsRef.current.set(exportUrl, null);
      const link = document.createElement("a");
      link.href = exportUrl;
      link.download = attachmentDownloadName(attachment.name);
      link.rel = "noopener";
      link.style.display = "none";
      document.body.append(link);
      link.click();
      link.remove();
      const completedUrl = exportUrl;
      const timer = window.setTimeout(() => revokeExportUrl(completedUrl), DOWNLOAD_URL_CLEANUP_DELAY_MS);
      exportUrlsRef.current.set(completedUrl, timer);
      exportUrl = null;
      markRoomRead(message.chatId);
    } catch {
      if (exportUrl) revokeExportUrl(exportUrl);
      if (downloaded?.claim && !claimHandled) {
        await releaseAttachmentDownloadClaim(currentSession, attachment.id, downloaded.claim).catch(() => undefined);
      }
      if (attachmentOperationActive(operation, currentSession.token)) setNotice("Action unavailable.");
    } finally {
      finishAttachmentOperation(operation);
    }
  }, [
    attachmentOperationActive,
    connection,
    directOperationAllowed,
    finishAttachmentOperation,
    markRoomRead,
    revokeExportUrl,
    startAttachmentOperation,
  ]);

  const createRoom = useCallback((room: RoomRecord): boolean => {
    if (connection !== "connected") return false;
    try {
      const frame = mlsRef.current?.createRoom(room);
      if (!frame || !socketRef.current?.sendMlsControl(frame)) { mlsRef.current?.removeRoom(room.id); return false; }
      return true;
    } catch { return false; }
  }, [connection]);

  const joinRoom = useCallback((roomId: string): boolean => connection === "connected" &&
    /^[A-Za-z0-9_-]{1,128}$/u.test(roomId) &&
    (socketRef.current?.sendMlsControl({ type: "mls_discover_room", protocol_version: 10, room_id: roomId }) ?? false), [connection]);

  const acceptRoomJoin = useCallback(async (requestId: string): Promise<boolean> => {
    const current = sessionRef.current;
    if (!current || connection !== "connected") return false;
    try {
      const prepared = mlsRef.current?.acceptJoin(requestId);
      if (!prepared) return false;
      const outcome = await runMlsTransaction(current, sessionGenerationRef.current, connectionGenerationRef.current, prepared);
      setPendingMlsJoins(mlsRef.current?.pendingJoins() ?? []);
      return outcome === "ACCEPTED";
    } catch { return false; }
  }, [connection, runMlsTransaction]);

  const rejectRoomJoin = useCallback((requestId: string): boolean => {
    try {
      const frame = mlsRef.current?.rejectJoin(requestId);
      const sent = !!frame && (socketRef.current?.sendMlsControl(frame) ?? false);
      if (sent && frame && typeof frame.room_id === "string" && typeof frame.request_id === "string") {
        mlsRef.current?.forgetJoin(frame.room_id, frame.request_id);
      }
      setPendingMlsJoins(mlsRef.current?.pendingJoins() ?? []);
      return sent;
    } catch { return false; }
  }, []);

  const leaveRoom = useCallback((roomId: string): boolean => {
    if (connection !== "connected") return false;
    try {
      const frame = mlsRef.current?.beginLeave(roomId);
      const sent = !!frame && (socketRef.current?.sendMlsControl(frame) ?? false);
      if (!sent && frame && typeof frame.request_id === "string") mlsRef.current?.forgetLeave(roomId, frame.request_id);
      setPendingMlsLeaves(mlsRef.current?.pendingLeaves() ?? []);
      return sent;
    } catch { return false; }
  }, [connection]);

  const acceptRoomLeave = useCallback(async (requestId: string): Promise<boolean> => {
    const current = sessionRef.current;
    if (!current || connection !== "connected") return false;
    try {
      const prepared = mlsRef.current?.acceptLeave(requestId);
      if (!prepared) return false;
      const outcome = await runMlsTransaction(current, sessionGenerationRef.current, connectionGenerationRef.current, prepared);
      setPendingMlsLeaves(mlsRef.current?.pendingLeaves() ?? []);
      return outcome === "ACCEPTED";
    } catch { return false; }
  }, [connection, runMlsTransaction]);

  const rejectRoomLeave = useCallback((requestId: string): boolean => {
    try {
      const frame = mlsRef.current?.rejectLeave(requestId);
      const sent = !!frame && (socketRef.current?.sendMlsControl(frame) ?? false);
      if (sent && frame && typeof frame.room_id === "string" && typeof frame.request_id === "string") {
        mlsRef.current?.forgetLeave(frame.room_id, frame.request_id);
      }
      setPendingMlsLeaves(mlsRef.current?.pendingLeaves() ?? []);
      return sent;
    } catch { return false; }
  }, []);

  const deleteRoom = useCallback((chatId: string): boolean => {
    if (connection !== "connected") return false;
    return socketRef.current?.sendMlsControl({ type: "mls_delete_room", protocol_version: 10, room_id: chatId }) ?? false;
  }, [connection]);

  const wipeRelay = useCallback((): boolean => socketRef.current?.wipe() ?? false, []);

  const activeRoom = useMemo(
    () => conversationForId(rooms, directs, activeRoomId),
    [activeRoomId, directs, rooms],
  );
  const safetyNumber = useMemo(() => {
    if (!session || activeRoom?.conversation_type !== "direct") return null;
    const peer = presence.find((user) => user.username === activeRoom.peer_username);
    if (!peer) return null;
    try {
      return conversationSafetyNumber(
        session.identityPublicKey,
        base64ToBytes(peer.identity_public_b64),
      );
    } catch {
      return null;
    }
  }, [activeRoom, presence, session]);

  return {
    session,
    connection,
    rooms,
    directs,
    presence,
    messages,
    activeRoom,
    activeRoomId,
    safetyNumber,
    directTrust,
    remainingSessionSec,
    upload,
    media,
    notice,
    securityWarning,
    pendingMlsJoins,
    pendingMlsLeaves,
    retainWhenHiddenRef,
    login,
    logout,
    clearMemory,
    clearPrivateView,
    touchActivity,
    openRoom,
    openDirect,
    verifyDirectSafetyNumber,
    markRoomRead,
    sendText,
    sendAttachment,
    viewAttachment,
    exportAttachment,
    clearMedia,
    createRoom,
    joinRoom,
    acceptRoomJoin,
    rejectRoomJoin,
    leaveRoom,
    acceptRoomLeave,
    rejectRoomLeave,
    deleteRoom,
    wipeRelay,
    clearNotice: () => setNotice(null),
  };
}

function validRoom(value: unknown): value is RoomRecord {
  if (!plainRecord(value) || Object.keys(value).some((key) => !ROOM_KEYS.has(key))) return false;
  const room = value as Partial<RoomRecord>;
  const timers = [
    room.self_destruct_timer_sec,
    room.overall_expiry_sec,
    room.image_read_timer_sec,
    room.image_overall_expiry_sec,
    room.video_read_timer_sec,
    room.video_overall_expiry_sec,
    room.file_read_timer_sec,
    room.file_overall_expiry_sec,
  ];
  const flags = [
    room.allow_images,
    room.allow_videos,
    room.allow_files,
    room.enforce_text_absolute_expiry,
    room.enforce_image_absolute_expiry,
    room.enforce_video_absolute_expiry,
    room.enforce_file_absolute_expiry,
  ];
  return typeof room.id === "string" &&
    room.id.length <= MAX_ROOM_ID_BYTES && ROOM_ID_PATTERN.test(room.id) &&
    typeof room.name === "string" && room.name.length > 0 &&
    room.name.length <= MAX_ROOM_NAME_LENGTH && ![...room.name].some((character) => /\p{Cc}/u.test(character)) &&
    typeof room.owner_username === "string" && USERNAME_PATTERN.test(room.owner_username) &&
    timers.every((timer) => typeof timer === "number" && Number.isSafeInteger(timer) && timer >= 0 && timer <= MAX_TIMER_SECONDS) &&
    flags.every((flag) => typeof flag === "boolean") &&
    (room.conversation_type === undefined || room.conversation_type === "room") &&
    room.peer_username === undefined;
}

function validDirect(value: unknown): value is DirectRecord {
  if (!plainRecord(value) || Object.keys(value).length !== DIRECT_KEYS.size ||
    Object.keys(value).some((key) => !DIRECT_KEYS.has(key))) return false;
  const direct = value as Partial<DirectRecord>;
  return typeof direct.id === "string" && /^dm_[A-Za-z0-9_-]{1,125}$/u.test(direct.id) &&
    typeof direct.peer_username === "string" && USERNAME_PATTERN.test(direct.peer_username);
}

function validRoomCatalog(rooms: unknown[]): rooms is RoomRecord[] {
  if (rooms.length > MAX_ROOM_CATALOG) return false;
  const ids = new Set<string>();
  for (const value of rooms) {
    if (!validRoom(value)) return false;
    const room = value;
    const key = room.id.toLowerCase();
    if (ids.has(key)) return false;
    ids.add(key);
  }
  return true;
}

function validDirectCatalog(directs: unknown[]): directs is DirectRecord[] {
  if (directs.length > MAX_DIRECT_CATALOG) return false;
  const ids = new Set<string>();
  const peers = new Set<string>();
  for (const value of directs) {
    if (!validDirect(value)) return false;
    const direct = value;
    const id = direct.id.toLowerCase();
    const peer = direct.peer_username.toLowerCase();
    if (ids.has(id) || peers.has(peer)) return false;
    ids.add(id);
    peers.add(peer);
  }
  return true;
}

function validPresence(value: unknown): value is PresenceUser {
  if (!plainRecord(value) || Object.keys(value).length !== PRESENCE_KEYS.size ||
    Object.keys(value).some((key) => !PRESENCE_KEYS.has(key))) return false;
  const user = value as Partial<PresenceUser>;
  if (
    typeof user.username !== "string" ||
    !USERNAME_PATTERN.test(user.username) ||
    typeof user.connected !== "boolean" ||
    typeof user.identity_public_b64 !== "string" ||
    typeof user.identity_prekey_id !== "string" ||
    !/^[A-Za-z0-9_-]{1,32}$/u.test(user.identity_prekey_id) ||
    typeof user.directory_digest !== "string"
  ) {
    return false;
  }
  if (
    typeof user.directory_node_id !== "string" ||
    !/^[A-Za-z0-9._:-]{1,128}$/u.test(user.directory_node_id) ||
    typeof user.directory_revision !== "number" ||
    !Number.isSafeInteger(user.directory_revision) ||
    user.directory_revision < 1 || user.directory_revision > MAX_DIRECTORY_REVISION
  ) return false;
  return canonicalBase64Bytes(user.identity_public_b64, IDENTITY_PUBLIC_KEY_BYTES) &&
    canonicalBase64Bytes(user.directory_digest, 32);
}

function presenceDirectoryStamp(users: PresenceUser[]): DirectoryStamp | null {
  if (users.length > 0 && users.every((user) =>
    user.directory_node_id === users[0]?.directory_node_id &&
    user.directory_revision === users[0]?.directory_revision
  )) {
    const node = users[0]?.directory_node_id ?? "";
    const revision = users[0]?.directory_revision ?? 0;
    if (/^[A-Za-z0-9._:-]{1,128}$/u.test(node) &&
      Number.isSafeInteger(revision) && revision > 0 && revision <= MAX_DIRECTORY_REVISION) {
      return { directory_node_id: node, directory_revision: revision, directory_digest: users[0]?.directory_digest ?? "" };
    }
  }
  return null;
}

function u32(value: number): Uint8Array {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, false);
  return bytes;
}

function u64(value: number): Uint8Array {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(value), false);
  return bytes;
}

async function directoryDigestV2(
  nodeId: string,
  revision: number,
  users: PresenceUser[],
): Promise<string> {
  const encoder = new TextEncoder();
  const entries = users
    .map((user) => {
      const decoded = base64ToBytes(user.identity_public_b64);
      return {
        username: user.username,
        identity: decoded.slice(0, 64),
        decoded,
      };
    })
    .sort((left, right) => left.username < right.username ? -1 : left.username > right.username ? 1 : 0);
  const parts: Uint8Array[] = [
    encoder.encode("ABYSSAL_DIRECTORY_CHECKPOINT_V2"),
    u32(encoder.encode(nodeId).byteLength),
    encoder.encode(nodeId),
    u64(revision),
    u32(entries.length),
  ];
  entries.forEach((entry) => {
    const username = encoder.encode(entry.username);
    parts.push(u32(username.byteLength), username, entry.identity);
  });
  const transcript = new Uint8Array(parts.reduce((total, part) => total + part.byteLength, 0));
  let offset = 0;
  parts.forEach((part) => { transcript.set(part, offset); offset += part.byteLength; });
  try {
    return bytesToBase64(new Uint8Array(await crypto.subtle.digest("SHA-256", transcript)));
  } finally {
    transcript.fill(0);
    parts.forEach((part) => part.fill(0));
    entries.forEach((entry) => {
      entry.identity.fill(0);
      entry.decoded.fill(0);
    });
  }
}

function canonicalBase64Bytes(value: string, expectedBytes: number): boolean {
  const expectedLength = Math.floor(expectedBytes / 3) * 4 +
    (expectedBytes % 3 === 0 ? 0 : expectedBytes % 3 === 1 ? 2 : 3);
  if (value.length !== expectedLength || !/^[A-Za-z0-9_-]+$/u.test(value)) return false;
  let decoded: Uint8Array | null = null;
  try {
    decoded = base64ToBytes(value);
    return decoded.byteLength === expectedBytes && bytesToBase64(decoded) === value;
  } catch {
    return false;
  } finally {
    decoded?.fill(0);
  }
}

function stableIdentityFingerprint(publicKeyB64: string): string {
  let decoded: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  try {
    decoded = base64ToBytes(publicKeyB64);
    if (decoded.byteLength !== IDENTITY_PUBLIC_KEY_BYTES || bytesToBase64(decoded) !== publicKeyB64) {
      throw new Error("Identity unavailable");
    }
    return bytesToBase64(decoded.subarray(0, 64));
  } finally {
    wipeBytes(decoded);
  }
}

function conversationForId(
  rooms: RoomRecord[],
  directs: DirectRecord[],
  chatId: string | null,
): RoomRecord | undefined {
  if (!chatId) return undefined;
  const room = rooms.find((candidate) => candidate.id === chatId);
  if (room) return { ...room, conversation_type: "room" };
  const direct = directs.find((candidate) => candidate.id === chatId);
  if (!direct) return undefined;
  return {
    id: direct.id,
    name: direct.peer_username,
    peer_username: direct.peer_username,
    conversation_type: "direct",
    self_destruct_timer_sec: 5,
    overall_expiry_sec: 0,
    allow_images: true,
    allow_videos: true,
    allow_files: true,
    enforce_text_absolute_expiry: false,
    image_read_timer_sec: 5,
    image_overall_expiry_sec: 0,
    enforce_image_absolute_expiry: false,
    video_read_timer_sec: 5,
    video_overall_expiry_sec: 0,
    enforce_video_absolute_expiry: false,
    file_read_timer_sec: 5,
    file_overall_expiry_sec: 0,
    enforce_file_absolute_expiry: false,
  };
}

function clampDirectRetention(value: number | undefined): number {
  if (value === undefined || !Number.isFinite(value)) return 5;
  return Math.min(86_400, Math.max(0, Math.floor(value)));
}

function parsePayload(
  chatId: string,
  authoritativeMessageId: string,
  payload: Record<string, unknown>,
  room: RoomRecord | undefined,
  currentUsername: string,
  authoritativeSender?: string,
  authoritativeSenderPublicKeyB64?: string,
  ownMessageIds: ReadonlySet<string> = new Set(),
): ChatMessage | null {
  const kind = payload.kind;
  const id = cleanString(payload.id, 128);
  const sender = cleanString(authoritativeSender, 80) || cleanString(payload.sender, 80);
  if ((kind !== "text" && kind !== "attachment") ||
    !validControlId(authoritativeMessageId) || id !== authoritativeMessageId || !sender) return null;
  const receivedAtMs = Date.now();
  const sentAt = safeTimestamp(payload.timestamp_ms, receivedAtMs);
  const replyToId = cleanString(payload.reply_to_id, 128) || undefined;
  const senderClient = parseSenderClient(payload.sender_client);
  if (!senderClient) return null;

  if (kind === "text") {
    const content = cleanString(payload.content, 8_000);
    if (!content) return null;
    return {
      id,
      chatId,
      sender,
      content,
      kind,
      createdAtMs: sentAt,
      receivedAtMs,
      selfDestructSec: incomingReadRetention(room, payload.self_destruct_sec),
      absoluteExpirySec: absoluteRetention(room),
      replyToId,
      mine: sender === currentUsername,
      mentionsCurrentUser: sender !== currentUsername && mentionsUsername(content, currentUsername),
      repliesToCurrentUser: replyTargetsCurrentUser(sender, currentUsername, replyToId, ownMessageIds),
      senderPublicKeyB64: authoritativeSenderPublicKeyB64,
      senderClient,
    };
  }

  const attachmentId = cleanString(payload.attachment_id, 128);
  const mediaType = normalizeMediaType(payload.media_type);
  const encryptionVersion = payload.attachment_cipher_version;
  if (
    !attachmentId ||
    encryptionVersion !== ATTACHMENT_CIPHER_VERSION ||
    !mediaType ||
    !mediaAllowed(room, mediaType)
  ) return null;
  let encryptionKey: Uint8Array;
  try {
    if (typeof payload.attachment_key_b64 !== "string") return null;
    encryptionKey = base64ToBytes(payload.attachment_key_b64);
  } catch {
    return null;
  }
  if (encryptionKey.byteLength !== 32) {
    wipeBytes(encryptionKey);
    return null;
  }
  const name = cleanString(payload.name, 160) || "attachment";
  const mimeType = cleanString(payload.mime_type, 120) || "application/octet-stream";
  const reaction = reactionByShortcode(cleanString(payload.reaction_shortcode, 80));
  const reactionShortcode = reaction?.filename === name && reaction.mimeType === mimeType
    ? reaction.shortcode
    : undefined;
  return {
    id,
    chatId,
    sender,
    content: name,
    kind,
    createdAtMs: sentAt,
    receivedAtMs,
    selfDestructSec: incomingReadRetention(room, payload.self_destruct_sec, mediaType),
    absoluteExpirySec: absoluteRetention(room, mediaType),
    replyToId,
    mine: sender === currentUsername,
    repliesToCurrentUser: replyTargetsCurrentUser(sender, currentUsername, replyToId, ownMessageIds),
    senderPublicKeyB64: authoritativeSenderPublicKeyB64,
    senderClient,
    attachment: {
      id: attachmentId,
      encryptionVersion,
      encryptionKey,
      name,
      mediaType,
      mimeType,
      sizeBytes: safeNumber(payload.size_bytes, 0, MEDIA_LIMIT_BYTES[mediaType]),
      oneTime: payload.one_time === true,
      deleteAfterDownload: payload.delete_after_download === true || payload.one_time === true,
      reactionShortcode,
    },
  };
}

function incomingReadRetention(
  room: RoomRecord | undefined,
  requested: unknown,
  mediaType?: MediaType,
): number {
  if (room?.conversation_type === "direct") {
    return clampDirectRetention(typeof requested === "number" ? requested : undefined);
  }
  return readRetention(room, mediaType);
}

function directoryStampFields(stamp: DirectoryStamp): Record<string, unknown> {
  return {
    directory_node_id: stamp.directory_node_id,
    directory_revision: stamp.directory_revision,
    directory_digest: stamp.directory_digest,
  };
}

function directoryStampMatches(
  frame: Extract<IncomingFrame, { type: "message" }>,
  payload: unknown,
): boolean {
  if (!plainRecord(payload) ||
    typeof frame.directory_node_id !== "string" ||
    typeof frame.directory_revision !== "number" ||
    typeof frame.directory_digest !== "string") return false;
  return payload.directory_node_id === frame.directory_node_id &&
    payload.directory_revision === frame.directory_revision &&
    payload.directory_digest === frame.directory_digest;
}

function messagePayload(
  message: ChatMessage,
  directoryStamp: DirectoryStamp | null = null,
): Record<string, unknown> {
  const common: Record<string, unknown> = {
    kind: message.kind,
    id: message.id,
    sender: message.sender,
    timestamp_ms: message.createdAtMs,
    self_destruct_sec: message.selfDestructSec,
    absolute_expiry_sec: message.absoluteExpirySec,
    sender_client: LOCAL_SENDER_CLIENT,
    ...(directoryStamp ? directoryStampFields(directoryStamp) : {}),
  };
  if (message.replyToId) common.reply_to_id = message.replyToId;
  if (message.kind === "text") return { ...common, content: message.content };
  const attachment = message.attachment;
  return {
    ...common,
    attachment_id: attachment?.id,
    name: attachment?.name,
    media_type: attachment?.mediaType,
    mime_type: attachment?.mimeType,
    size_bytes: attachment?.sizeBytes,
    attachment_cipher_version: attachment?.encryptionVersion,
    attachment_key_b64: attachment ? bytesToBase64(attachment.encryptionKey) : undefined,
    one_time: attachment?.oneTime,
    delete_after_download: attachment?.deleteAfterDownload,
    reaction_shortcode: attachment?.reactionShortcode,
  };
}

function pruneExpired(current: Record<string, ChatMessage[]>, now: number): Record<string, ChatMessage[]> {
  let changed = false;
  const next: Record<string, ChatMessage[]> = {};
  for (const [chatId, list] of Object.entries(current)) {
    const active = list.filter((message) => !isExpired(message, now));
    list.filter((message) => isExpired(message, now)).forEach(wipeEvictedMessage);
    if (active.length > 0) next[chatId] = active;
    else if (list.length === 0) changed = true;
    if (active.length !== list.length) changed = true;
  }
  return changed ? next : current;
}

function wipeMessageList(messages: ChatMessage[] | undefined): void {
  messages?.forEach(wipeEvictedMessage);
}

function wipeMessageMap(messages: Record<string, ChatMessage[]>): void {
  Object.values(messages).forEach(wipeMessageList);
}

function validReplyId(messages: ChatMessage[] | undefined, value?: string): string | undefined {
  if (!value || !messages?.some((message) => message.id === value)) return undefined;
  return value;
}

function validControlId(value: string): boolean {
  return /^[A-Za-z0-9_-]{1,128}$/.test(value);
}

export function rememberBoundedId(ids: Set<string>, value: string, maxSize: number): void {
  if (ids.has(value)) return;
  while (ids.size >= maxSize) {
    const oldest = ids.values().next().value;
    if (oldest === undefined) break;
    ids.delete(oldest);
  }
  ids.add(value);
}

function normalizeMediaType(value: unknown): MediaType | null {
  if (value === "IMAGE" || value === "VIDEO" || value === "FILE") return value;
  return null;
}

function cleanString(value: unknown, maxLength: number): string {
  return typeof value === "string" ? value.trim().slice(0, maxLength) : "";
}

function safeNumber(value: unknown, min: number, max: number): number {
  return typeof value === "number" && Number.isFinite(value) ? Math.min(max, Math.max(min, value)) : min;
}

function safeTimestamp(value: unknown, fallback: number): number {
  if (typeof value !== "number" || !Number.isFinite(value)) return fallback;
  const lower = fallback - MAX_MESSAGE_AGE_MS;
  const upper = fallback + 60_000;
  return Math.min(upper, Math.max(lower, Math.floor(value)));
}

function plainRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

function wipeEncryptedPayload(payload: EncryptedPayload): void {
  wipeBytes(payload.nonce);
  wipeBytes(payload.ciphertext);
  payload.envelopes.forEach((envelope) => {
    wipeBytes(envelope.wrappedKey);
    wipeBytes(envelope.signature);
  });
  wipeBytes(payload.identityEnvelope);
  wipeBytes(payload.identityPublicKey);
  wipeBytes(payload.stateSignature);
}

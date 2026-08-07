import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  absoluteRetention,
  classifyMedia,
  isExpired,
  MEDIA_LIMIT_BYTES,
  mediaAllowed,
  readRetention,
} from "../domain/messagePolicy";
import { mentionsUsername, replyTargetsCurrentUser } from "../domain/messageAttention";
import { reactionByShortcode } from "../domain/reactions";
import type {
  AccountSession,
  AttachmentOptions,
  ChatMessage,
  ConnectionState,
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
  finishOpaqueLogin,
  finishOpaqueRegistration,
  identityContext,
  InMemoryPayloadCipher,
  payloadToFrame,
  startOpaque,
  type EncryptedPayload,
  wipeBytes,
  wipeOpaqueStart,
} from "../security/crypto";
import { attachmentDownloadBlob, attachmentDownloadName } from "../security/attachmentExport";
import { normalizeNodeUrl } from "../security/nodeUrl";
import {
  downloadEncryptedAttachment,
  finishOpaqueAccount,
  RelaySocket,
  revokeSession,
  startOpaqueAccount,
  uploadEncryptedAttachment,
} from "../transport/nodeClient";

const ACTIVITY_SIGNAL_INTERVAL_MS = 20_000;
const MAX_MESSAGE_AGE_MS = 24 * 60 * 60 * 1000;

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

const EMPTY_UPLOAD: UploadState = { active: false, name: "", loaded: 0, total: 0 };

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
  const socketRef = useRef<RelaySocket | null>(null);
  const cipherRef = useRef(new InMemoryPayloadCipher());
  const lastActivityRef = useRef(0);
  const lastActivitySignalRef = useRef(0);
  const retainWhenHiddenRef = useRef(false);
  const sessionRef = useRef<AccountSession | null>(null);
  const roomsRef = useRef<RoomRecord[]>([]);
  const directsRef = useRef<DirectRecord[]>([]);
  const presenceRef = useRef<PresenceUser[]>([]);
  const activeRoomRef = useRef<string | null>(null);
  const requestedDirectRef = useRef<string | null>(null);
  const ownMessageIdsRef = useRef(new Set<string>());
  const receivedFrameIdsRef = useRef(new Set<string>());
  const identityPinsRef = useRef(new Map<string, string>());
  const sendReadReceiptRef = useRef<(chatId: string, messageId: string) => void>(() => undefined);

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
    activeRoomRef.current = activeRoomId;
  }, [activeRoomId]);

  const clearMedia = useCallback(() => {
    setMedia((current) => {
      if (current) URL.revokeObjectURL(current.objectUrl);
      return null;
    });
  }, []);

  const clearMemory = useCallback(() => {
    socketRef.current?.close();
    socketRef.current = null;
    cipherRef.current.clear();
    clearMedia();
    setSession(null);
    setConnection("disconnected");
    setRooms([]);
    setDirects([]);
    setPresence([]);
    setMessages({});
    setActiveRoomId(null);
    setRemainingSessionSec(0);
    setUpload(EMPTY_UPLOAD);
    ownMessageIdsRef.current.clear();
    receivedFrameIdsRef.current.clear();
    identityPinsRef.current.clear();
    roomsRef.current = [];
    directsRef.current = [];
    presenceRef.current = [];
    activeRoomRef.current = null;
    requestedDirectRef.current = null;
    retainWhenHiddenRef.current = false;
    lastActivityRef.current = 0;
    lastActivitySignalRef.current = 0;
  }, [clearMedia]);

  const logout = useCallback(async () => {
    const current = sessionRef.current;
    clearMemory();
    if (current) await revokeSession(current);
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

  const applyFrame = useCallback(async (frame: IncomingFrame) => {
    if (frame.type === "GLOBAL_WIPE" || frame.type === "global_wipe") {
      clearMemory();
      return;
    }
    if (frame.type === "presence") {
      const next = frame.users.filter(validPresence);
      const identityChanged = next.some((user) => {
        const key = user.username.toLowerCase();
        const pinned = identityPinsRef.current.get(key);
        if (pinned && pinned !== user.identity_public_b64) return true;
        identityPinsRef.current.set(key, user.identity_public_b64);
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
    if (frame.type === "rooms") {
      const next = frame.rooms.filter(validRoom);
      setRooms(next);
      next.forEach((room) => socketRef.current?.join(room.id));
      return;
    }
    if (frame.type === "room_created" && validRoom(frame.room)) {
      setRooms((current) => [...current.filter((room) => room.id !== frame.room.id), frame.room]);
      socketRef.current?.join(frame.room.id);
      return;
    }
    if (frame.type === "room_deleted") {
      setRooms((current) => current.filter((room) => room.id !== frame.chat_id));
      setMessages((current) => {
        const next = { ...current };
        delete next[frame.chat_id];
        return next;
      });
      setActiveRoomId((current) => (current === frame.chat_id ? null : current));
      return;
    }
    if (frame.type === "directs") {
      const next = frame.directs.filter(validDirect);
      directsRef.current = next;
      setDirects(next);
      next.forEach((direct) => socketRef.current?.join(direct.id));
      return;
    }
    if (frame.type === "direct_opened" && validDirect(frame.direct)) {
      const direct = frame.direct;
      directsRef.current = [
        ...directsRef.current.filter((current) => current.id !== direct.id),
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
    if (frame.type !== "message" || frame.version !== 4) return;

    try {
      const currentSession = sessionRef.current;
      if (!currentSession) return;
      const replayKey = `${frame.chat_id}\u0000${frame.sender_username}\u0000${frame.message_id}`;
      if (receivedFrameIdsRef.current.has(replayKey)) {
        const stateSnapshot = cipherRef.current.stateSnapshot();
        if (!stateSnapshot) {
          clearMemory();
          return;
        }
        const acknowledged = socketRef.current?.acknowledge(
          frame.chat_id,
          frame.message_id,
          frame.sender_username,
          stateSnapshot,
        ) ?? false;
        wipeBytes(stateSnapshot.envelope);
        if (!acknowledged) clearMemory();
        return;
      }
      if (receivedFrameIdsRef.current.size >= 10_000) {
        const oldest = receivedFrameIdsRef.current.values().next().value;
        if (oldest) receivedFrameIdsRef.current.delete(oldest);
      }
      const senderPublicKey = base64ToBytes(frame.sender_public_key_b64);
      const decrypted = cipherRef.current.decryptText(
        frame.chat_id,
        frame.message_id,
        frame.sender_username,
        senderPublicKey,
        {
          nonce: base64ToBytes(frame.nonce_b64),
          ciphertext: base64ToBytes(frame.ciphertext_b64),
          signature: base64ToBytes(frame.signature_b64),
        },
        base64ToBytes(frame.wrapped_key_b64),
        currentSession.username,
      );
      const stateSnapshot = cipherRef.current.stateSnapshot();
      if (!stateSnapshot) throw new Error("Identity unavailable");
      const acknowledged = socketRef.current?.acknowledge(
        frame.chat_id,
        frame.message_id,
        frame.sender_username,
        stateSnapshot,
      ) ?? false;
      wipeBytes(stateSnapshot.envelope);
      if (!acknowledged) {
        clearMemory();
        return;
      }
      receivedFrameIdsRef.current.add(replayKey);
      const payload = JSON.parse(decrypted) as Record<string, unknown>;
      if (payload.kind === "read_receipt") {
        const targetId = typeof payload.message_id === "string" ? payload.message_id : "";
        if (!ownMessageIdsRef.current.has(targetId)) return;
        const readAtMs = Date.now();
        setMessages((current) => {
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
      const room = conversationForId(roomsRef.current, directsRef.current, frame.chat_id);
      const message = parsePayload(
        frame.chat_id,
        payload,
        room,
        currentSession.username,
        frame.sender_username,
        frame.sender_public_key_b64,
        ownMessageIdsRef.current,
      );
      if (!message || isExpired(message, Date.now())) return;
      if (message.mine) ownMessageIdsRef.current.add(message.id);
      if (activeRoomRef.current === frame.chat_id) {
        message.readAtMs = Date.now();
        sendReadReceiptRef.current(frame.chat_id, message.id);
      }
      setMessages((current) => appendUnique(current, message));
    } catch {
      // Authentication failure or malformed plaintext stays outside UI state.
    }
  }, [clearMemory]);

  const login = useCallback(async (input: LoginInput): Promise<AccountSession> => {
    setNotice(null);
    const endpoint = normalizeNodeUrl(input.nodeUrl);
    const opaque = await startOpaque(input.password);
    let nextSession: AccountSession;
    try {
      const start = await startOpaqueAccount(
        endpoint,
        input.code,
        opaque.registrationRequest,
        opaque.credentialRequest,
      );
      const context = identityContext(start.node_id, input.code);
      const response = base64ToBytes(start.response_b64!);
      try {
        if (start.mode === "registration") {
          const result = await finishOpaqueRegistration(input.password, opaque, response);
          const identity = cipherRef.current.createIdentity(result.exportKey, context);
          nextSession = await finishOpaqueAccount(endpoint, {
            handshakeId: start.handshake_id!,
            registrationUpload: result.registrationUpload,
            identityPublicKey: identity.publicKey,
            identityEnvelope: identity.envelope,
          });
          wipeBytes(result.registrationUpload);
          wipeBytes(result.exportKey);
          wipeBytes(identity.publicKey);
          wipeBytes(identity.envelope);
        } else {
          const result = await finishOpaqueLogin(input.password, opaque, response);
          const identityPublic = base64ToBytes(start.identity_public_b64!);
          const identityEnvelope = base64ToBytes(start.identity_envelope_b64!);
          cipherRef.current.recoverIdentity(
            result.exportKey,
            context,
            identityEnvelope,
            identityPublic,
          );
          nextSession = await finishOpaqueAccount(endpoint, {
            handshakeId: start.handshake_id!,
            credentialFinalization: result.credentialFinalization,
          });
          wipeBytes(result.credentialFinalization);
          wipeBytes(result.exportKey);
          wipeBytes(result.sessionKey);
          wipeBytes(identityPublic);
          wipeBytes(identityEnvelope);
        }
      } finally {
        wipeBytes(context);
        wipeBytes(response);
      }
    } catch (error) {
      wipeOpaqueStart(opaque);
      cipherRef.current.clear();
      throw error;
    }
    if (!equalBytes(cipherRef.current.publicKey(), nextSession.identityPublicKey)) {
      cipherRef.current.clear();
      throw new Error("Wrong information");
    }
    retainWhenHiddenRef.current = input.retainWhenHidden;
    lastActivityRef.current = Date.now();
    lastActivitySignalRef.current = Date.now();
    setRemainingSessionSec(nextSession.sessionInactivitySec);
    setSession(nextSession);
    const relay = new RelaySocket(nextSession, (frame) => void applyFrame(frame), setConnection);
    socketRef.current = relay;
    relay.connect();
    return nextSession;
  }, [applyFrame]);

  useEffect(() => {
    if (connection !== "connected") return;
    rooms.forEach((room) => socketRef.current?.join(room.id));
    directs.forEach((direct) => socketRef.current?.join(direct.id));
  }, [connection, directs, rooms]);

  useEffect(() => {
    if (!session) return;
    const timer = window.setInterval(() => {
      const now = Date.now();
      const remaining = Math.max(0, Math.ceil((lastActivityRef.current + session.sessionInactivitySec * 1000 - now) / 1000));
      setRemainingSessionSec(remaining);
      if (remaining === 0) void logout();
      setMessages((current) => pruneExpired(current, now));
    }, 500);
    return () => window.clearInterval(timer);
  }, [logout, session]);

  useEffect(() => {
    const pageHide = () => {
      const current = sessionRef.current;
      if (!current) return;
      socketRef.current?.close();
      void revokeSession(current);
      cipherRef.current.clear();
    };
    const pageShow = (event: PageTransitionEvent) => {
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
    const now = Date.now();
    setMessages((current) => {
      const roomMessages = current[chatId];
      if (!roomMessages) return current;
      let changed = false;
      const nextMessages = roomMessages.map((message) => {
        if (message.mine || message.readAtMs !== undefined) return message;
        changed = true;
        sendReadReceiptRef.current(chatId, message.id);
        return { ...message, readAtMs: now };
      });
      return changed ? { ...current, [chatId]: nextMessages } : current;
    });
  }, []);

  const openRoom = useCallback((chatId: string | null) => {
    activeRoomRef.current = chatId;
    setActiveRoomId(chatId);
    if (chatId) {
      socketRef.current?.join(chatId);
      window.setTimeout(() => markRoomRead(chatId), 350);
    }
  }, [markRoomRead]);

  const openDirect = useCallback((peerUsername: string): boolean => {
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
  }, [connection, openRoom]);

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
      }));
    if (includeSelf) {
      recipients.push({
        username: currentSession.username,
        publicKey: currentSession.identityPublicKey.slice(),
      });
    }
    return recipients;
  }, []);

  const sendReadReceipt = useCallback((chatId: string, messageId: string) => {
    const currentSession = sessionRef.current;
    if (!currentSession || !validControlId(messageId)) return;
    const receiptId = crypto.randomUUID();
    const encrypted = cipherRef.current.encryptText(
      chatId,
      receiptId,
      currentSession.username,
      JSON.stringify({ kind: "read_receipt", message_id: messageId }),
      recipientKeysFor(chatId),
    );
    socketRef.current?.send({
      type: "message",
      chat_id: chatId,
      ...payloadToFrame(encrypted),
    });
    wipeEncryptedPayload(encrypted);
  }, [recipientKeysFor]);

  useEffect(() => {
    sendReadReceiptRef.current = sendReadReceipt;
  }, [sendReadReceipt]);

  const sendText = useCallback(async (content: string, replyToId?: string, retentionSec?: number): Promise<boolean> => {
    const currentSession = sessionRef.current;
    const chatId = activeRoomId;
    const room = conversationForId(roomsRef.current, directsRef.current, chatId);
    const clean = content.trim();
    if (!currentSession || !chatId || !room || !clean || connection !== "connected") return false;
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
    };
    const encrypted = cipherRef.current.encryptText(
      chatId,
      message.id,
      currentSession.username,
      JSON.stringify(messagePayload(message)),
      recipientKeysFor(chatId),
    );
    const accepted = socketRef.current?.send({
      type: "message",
      chat_id: chatId,
      ...payloadToFrame(encrypted),
    }) ?? false;
    wipeEncryptedPayload(encrypted);
    if (accepted) {
      ownMessageIdsRef.current.add(message.id);
      setMessages((current) => appendUnique(current, message));
    }
    return accepted;
  }, [activeRoomId, connection, messages, recipientKeysFor]);

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

    let plain: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let encrypted: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    try {
      setUpload({ active: true, name: file.name || "attachment", loaded: 0, total: file.size });
      const fileBuffer = await file.arrayBuffer();
      plain = new Uint8Array(fileBuffer);
      const attachmentCryptoId = crypto.randomUUID();
      encrypted = cipherRef.current.encryptBytes(
        chatId,
        attachmentCryptoId,
        currentSession.username,
        plain,
        recipientKeysFor(chatId, true),
      );
      wipeBytes(plain);
      const ttlSec = absoluteRetention(room, mediaType);
      const attachmentId = await uploadEncryptedAttachment(
        currentSession,
        chatId,
        mediaType,
        encrypted,
        { ...options, ttlSec },
        (progress) => setUpload({ active: true, name: file.name || "attachment", ...progress }),
      );
      const now = Date.now();
      const message: ChatMessage = {
        id: crypto.randomUUID(),
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
        senderPublicKeyB64: bytesToBase64(currentSession.identityPublicKey),
        attachment: {
          id: attachmentId,
          name: (file.name || "attachment").slice(0, 160),
          mediaType,
          mimeType: (file.type || "application/octet-stream").slice(0, 120),
          sizeBytes: file.size,
          oneTime: options.oneTime,
          deleteAfterDownload: options.deleteAfterDownload || options.oneTime,
          reactionShortcode: reaction?.shortcode,
        },
      };
      const metadata = cipherRef.current.encryptText(
        chatId,
        message.id,
        currentSession.username,
        JSON.stringify(messagePayload(message)),
        recipientKeysFor(chatId),
      );
      const accepted = socketRef.current?.send({
        type: "message",
        chat_id: chatId,
        ...payloadToFrame(metadata),
      }) ?? false;
      wipeEncryptedPayload(metadata);
      if (accepted) {
        ownMessageIdsRef.current.add(message.id);
        setMessages((current) => appendUnique(current, message));
      }
      return accepted;
    } catch {
      setNotice("Action unavailable.");
      return false;
    } finally {
      wipeBytes(plain);
      wipeBytes(encrypted);
      setUpload(EMPTY_UPLOAD);
    }
  }, [activeRoomId, connection, messages, recipientKeysFor]);

  const viewAttachment = useCallback(async (message: ChatMessage): Promise<void> => {
    const currentSession = sessionRef.current;
    if (!currentSession || !message.attachment) return;
    clearMedia();
    let encrypted: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let plain: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    try {
      encrypted = await downloadEncryptedAttachment(currentSession, message.attachment.id);
      plain = cipherRef.current.decryptBytes(
        message.chatId,
        message.sender,
        base64ToBytes(
          message.senderPublicKeyB64 ?? bytesToBase64(currentSession.identityPublicKey),
        ),
        encrypted,
        currentSession.username,
      );
      const stateSnapshot = cipherRef.current.stateSnapshot();
      if (!stateSnapshot) throw new Error("Identity unavailable");
      const synced = socketRef.current?.syncIdentityState(stateSnapshot) ?? false;
      wipeBytes(stateSnapshot.envelope);
      if (!synced) {
        clearMemory();
        return;
      }
      const blob = new Blob([plain.slice().buffer], { type: message.attachment.mimeType });
      setMedia({
        messageId: message.id,
        name: message.attachment.name,
        mediaType: message.attachment.mediaType,
        mimeType: message.attachment.mimeType,
        objectUrl: URL.createObjectURL(blob),
        oneTime: message.attachment.oneTime,
      });
      markRoomRead(message.chatId);
    } catch {
      setNotice("Action unavailable.");
    } finally {
      wipeBytes(encrypted);
      wipeBytes(plain);
    }
  }, [clearMedia, clearMemory, markRoomRead]);

  const exportAttachment = useCallback(async (message: ChatMessage): Promise<void> => {
    const currentSession = sessionRef.current;
    if (!currentSession || !message.attachment || message.attachment.oneTime) return;
    let encrypted: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let plain: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    try {
      encrypted = await downloadEncryptedAttachment(currentSession, message.attachment.id);
      plain = cipherRef.current.decryptBytes(
        message.chatId,
        message.sender,
        base64ToBytes(
          message.senderPublicKeyB64 ?? bytesToBase64(currentSession.identityPublicKey),
        ),
        encrypted,
        currentSession.username,
      );
      const stateSnapshot = cipherRef.current.stateSnapshot();
      if (!stateSnapshot) throw new Error("Identity unavailable");
      const synced = socketRef.current?.syncIdentityState(stateSnapshot) ?? false;
      wipeBytes(stateSnapshot.envelope);
      if (!synced) {
        clearMemory();
        return;
      }
      const url = URL.createObjectURL(attachmentDownloadBlob(plain, message.attachment.mimeType));
      const link = document.createElement("a");
      link.href = url;
      link.download = attachmentDownloadName(message.attachment.name);
      link.rel = "noopener";
      link.style.display = "none";
      document.body.append(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1_000);
      markRoomRead(message.chatId);
    } catch {
      setNotice("Action unavailable.");
    } finally {
      wipeBytes(encrypted);
      wipeBytes(plain);
    }
  }, [clearMemory, markRoomRead]);

  const createRoom = useCallback((room: RoomRecord): boolean => {
    if (connection !== "connected") return false;
    return socketRef.current?.createRoom(room) ?? false;
  }, [connection]);

  const deleteRoom = useCallback((chatId: string): boolean => {
    if (connection !== "connected") return false;
    return socketRef.current?.deleteRoom(chatId) ?? false;
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
    remainingSessionSec,
    upload,
    media,
    notice,
    retainWhenHiddenRef,
    login,
    logout,
    clearMemory,
    touchActivity,
    openRoom,
    openDirect,
    markRoomRead,
    sendText,
    sendAttachment,
    viewAttachment,
    exportAttachment,
    clearMedia,
    createRoom,
    deleteRoom,
    wipeRelay,
    clearNotice: () => setNotice(null),
  };
}

function validRoom(value: unknown): value is RoomRecord {
  if (!value || typeof value !== "object") return false;
  const room = value as Partial<RoomRecord>;
  return typeof room.id === "string" && room.id.startsWith("forum_") && typeof room.name === "string";
}

function validDirect(value: unknown): value is DirectRecord {
  if (!value || typeof value !== "object") return false;
  const direct = value as Partial<DirectRecord>;
  return typeof direct.id === "string" && /^dm_[A-Za-z0-9_-]{1,125}$/.test(direct.id) &&
    typeof direct.peer_username === "string" && direct.peer_username.length > 0 && direct.peer_username.length <= 80;
}

function validPresence(value: unknown): value is PresenceUser {
  if (!value || typeof value !== "object") return false;
  const user = value as Partial<PresenceUser>;
  if (
    typeof user.username !== "string" ||
    user.username.length === 0 ||
    user.username.length > 80 ||
    typeof user.connected !== "boolean" ||
    typeof user.identity_public_b64 !== "string"
  ) {
    return false;
  }
  try {
    return base64ToBytes(user.identity_public_b64).byteLength === 96;
  } catch {
    return false;
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
  if ((kind !== "text" && kind !== "attachment") || !id || !sender) return null;
  const receivedAtMs = Date.now();
  const sentAt = safeTimestamp(payload.timestamp_ms, receivedAtMs);
  const replyToId = cleanString(payload.reply_to_id, 128) || undefined;

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
    };
  }

  const attachmentId = cleanString(payload.attachment_id, 128);
  const mediaType = normalizeMediaType(payload.media_type);
  if (!attachmentId || !mediaType || !mediaAllowed(room, mediaType)) return null;
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
    attachment: {
      id: attachmentId,
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

function messagePayload(message: ChatMessage): Record<string, unknown> {
  const common: Record<string, unknown> = {
    kind: message.kind,
    id: message.id,
    sender: message.sender,
    timestamp_ms: message.createdAtMs,
    self_destruct_sec: message.selfDestructSec,
    absolute_expiry_sec: message.absoluteExpirySec,
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
    one_time: attachment?.oneTime,
    delete_after_download: attachment?.deleteAfterDownload,
    reaction_shortcode: attachment?.reactionShortcode,
  };
}

function appendUnique(current: Record<string, ChatMessage[]>, message: ChatMessage): Record<string, ChatMessage[]> {
  const list = current[message.chatId] ?? [];
  if (list.some((candidate) => candidate.id === message.id)) return current;
  return { ...current, [message.chatId]: [...list, message].slice(-500) };
}

function pruneExpired(current: Record<string, ChatMessage[]>, now: number): Record<string, ChatMessage[]> {
  let changed = false;
  const next: Record<string, ChatMessage[]> = {};
  for (const [chatId, list] of Object.entries(current)) {
    const active = list.filter((message) => !isExpired(message, now));
    next[chatId] = active;
    if (active.length !== list.length) changed = true;
  }
  return changed ? next : current;
}

function validReplyId(messages: ChatMessage[] | undefined, value?: string): string | undefined {
  if (!value || !messages?.some((message) => message.id === value)) return undefined;
  return value;
}

function validControlId(value: string): boolean {
  return /^[A-Za-z0-9_-]{1,128}$/.test(value);
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
  wipeBytes(payload.signature);
  payload.envelopes.forEach((envelope) => wipeBytes(envelope.wrappedKey));
  wipeBytes(payload.identityEnvelope);
}

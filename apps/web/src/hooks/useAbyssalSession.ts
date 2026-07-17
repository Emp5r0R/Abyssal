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
  IncomingFrame,
  MediaType,
  PresenceUser,
  RoomRecord,
  UploadProgress,
} from "../domain/types";
import { base64ToBytes, bytesToBase64, InMemoryPayloadCipher, wipeBytes } from "../security/crypto";
import { normalizeNodeUrl } from "../security/nodeUrl";
import {
  downloadEncryptedAttachment,
  enterAccount,
  RelaySocket,
  revokeSession,
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
  const activeRoomRef = useRef<string | null>(null);
  const ownMessageIdsRef = useRef(new Set<string>());

  useEffect(() => {
    sessionRef.current = session;
  }, [session]);

  useEffect(() => {
    roomsRef.current = rooms;
  }, [rooms]);

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
    setPresence([]);
    setMessages({});
    setActiveRoomId(null);
    setRemainingSessionSec(0);
    setUpload(EMPTY_UPLOAD);
    ownMessageIdsRef.current.clear();
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
      setPresence(frame.users.filter((user) => typeof user.username === "string"));
      return;
    }
    if (frame.type === "read_receipt") {
      if (!frame.message_id) return;
      const readAtMs = Date.now();
      setMessages((current) => {
        const list = current[frame.chat_id];
        if (!list) return current;
        let changed = false;
        const next = list.map((message) => {
          if (message.id !== frame.message_id || message.readAtMs !== undefined) return message;
          changed = true;
          return { ...message, readAtMs };
        });
        return changed ? { ...current, [frame.chat_id]: next } : current;
      });
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
    if (frame.type !== "message" || typeof frame.payload_b64 !== "string") return;

    try {
      const decrypted = await cipherRef.current.decryptText(base64ToBytes(frame.payload_b64));
      const payload = JSON.parse(decrypted) as Record<string, unknown>;
      const currentSession = sessionRef.current;
      if (!currentSession) return;
      const room = roomsRef.current.find((candidate) => candidate.id === frame.chat_id);
      const message = parsePayload(
        frame.chat_id,
        payload,
        room,
        currentSession.username,
        frame.sender_username,
        ownMessageIdsRef.current,
      );
      if (!message || isExpired(message, Date.now())) return;
      if (message.mine) ownMessageIdsRef.current.add(message.id);
      if (activeRoomRef.current === frame.chat_id) {
        message.readAtMs = Date.now();
        socketRef.current?.send({ type: "read_receipt", chat_id: frame.chat_id, message_id: message.id });
      }
      setMessages((current) => appendUnique(current, message));
    } catch {
      // Authentication failure or malformed plaintext stays outside UI state.
    }
  }, [clearMemory]);

  const login = useCallback(async (input: LoginInput): Promise<AccountSession> => {
    setNotice(null);
    const endpoint = normalizeNodeUrl(input.nodeUrl);
    const nextSession = await enterAccount(endpoint, input.code, input.password);
    await cipherRef.current.initialize(nextSession.nodeId);
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
  }, [connection, rooms]);

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
        socketRef.current?.send({ type: "read_receipt", chat_id: chatId, message_id: message.id });
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

  const sendText = useCallback(async (content: string, replyToId?: string): Promise<boolean> => {
    const currentSession = sessionRef.current;
    const chatId = activeRoomId;
    const room = roomsRef.current.find((candidate) => candidate.id === chatId);
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
      selfDestructSec: readRetention(room),
      absoluteExpirySec: absoluteRetention(room),
      replyToId: validReplyId(messages[chatId], replyToId),
      mine: true,
    };
    const encrypted = await cipherRef.current.encryptText(JSON.stringify(messagePayload(message)));
    const accepted = socketRef.current?.send({ type: "message", chat_id: chatId, payload_b64: bytesToBase64(encrypted) }) ?? false;
    wipeBytes(encrypted);
    if (accepted) {
      ownMessageIdsRef.current.add(message.id);
      setMessages((current) => appendUnique(current, message));
    }
    return accepted;
  }, [activeRoomId, connection, messages]);

  const sendAttachment = useCallback(async ({ file, options, replyToId, reactionShortcode }: AttachmentInput): Promise<boolean> => {
    const currentSession = sessionRef.current;
    const chatId = activeRoomId;
    const room = roomsRef.current.find((candidate) => candidate.id === chatId);
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
      encrypted = await cipherRef.current.encryptBytes(fileBuffer);
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
        selfDestructSec: readRetention(room, mediaType),
        absoluteExpirySec: ttlSec,
        replyToId: validReplyId(messages[chatId], replyToId),
        mine: true,
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
      const metadata = await cipherRef.current.encryptText(JSON.stringify(messagePayload(message)));
      const accepted = socketRef.current?.send({ type: "message", chat_id: chatId, payload_b64: bytesToBase64(metadata) }) ?? false;
      wipeBytes(metadata);
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
  }, [activeRoomId, connection, messages]);

  const viewAttachment = useCallback(async (message: ChatMessage): Promise<void> => {
    const currentSession = sessionRef.current;
    if (!currentSession || !message.attachment) return;
    clearMedia();
    let encrypted: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let plain: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    try {
      encrypted = await downloadEncryptedAttachment(currentSession, message.attachment.id);
      plain = await cipherRef.current.decryptBytes(encrypted);
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
  }, [clearMedia, markRoomRead]);

  const exportAttachment = useCallback(async (message: ChatMessage): Promise<void> => {
    const currentSession = sessionRef.current;
    if (!currentSession || !message.attachment || message.attachment.oneTime) return;
    let encrypted: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    try {
      encrypted = await downloadEncryptedAttachment(currentSession, message.attachment.id);
      const url = URL.createObjectURL(new Blob([encrypted.slice().buffer], { type: "application/octet-stream" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = `${message.id}.abyssal`;
      link.rel = "noopener";
      link.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 0);
    } catch {
      setNotice("Action unavailable.");
    } finally {
      wipeBytes(encrypted);
    }
  }, []);

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
    () => rooms.find((room) => room.id === activeRoomId),
    [activeRoomId, rooms],
  );

  return {
    session,
    connection,
    rooms,
    presence,
    messages,
    activeRoom,
    activeRoomId,
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

function parsePayload(
  chatId: string,
  payload: Record<string, unknown>,
  room: RoomRecord | undefined,
  currentUsername: string,
  authoritativeSender?: string,
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
      selfDestructSec: readRetention(room),
      absoluteExpirySec: absoluteRetention(room),
      replyToId,
      mine: sender === currentUsername,
      mentionsCurrentUser: sender !== currentUsername && mentionsUsername(content, currentUsername),
      repliesToCurrentUser: replyTargetsCurrentUser(sender, currentUsername, replyToId, ownMessageIds),
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
    selfDestructSec: readRetention(room, mediaType),
    absoluteExpirySec: absoluteRetention(room, mediaType),
    replyToId,
    mine: sender === currentUsername,
    repliesToCurrentUser: replyTargetsCurrentUser(sender, currentUsername, replyToId, ownMessageIds),
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

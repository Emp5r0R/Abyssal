import type {
  AccountSession,
  AttachmentOptions,
  DirectoryStamp,
  IncomingFrame,
  MediaType,
  RoomRecord,
  UploadProgress,
} from "../domain/types";
import { currentBuildAttestation } from "../buildIdentity";
import {
  attachmentIdBytes,
  attachmentIdString,
  completeDownloadV11,
  deleteAttachmentV11,
  downloadAttachmentV11,
  releaseDownloadV11,
  uploadAttachmentV11,
} from "./v11Attachment";
import { ControlRejected, issueWsTicketV11, logoutV11 } from "./v11Control";
import { wipeTransportKeys, type TransportKeys } from "./v11Account";
import { V11SocketChannel, WS_PROTOCOL_V11 } from "./v11Socket";
import {
  base64ToBytes,
  bytesToBase64,
  ATTACHMENT_CHUNK_RECORD_BYTES,
  ATTACHMENT_CIPHER_VERSION,
  IDENTITY_PUBLIC_KEY_BYTES,
  maxSerializedAttachmentBytes,
  serializedAttachmentBytes,
  STATE_SIGNATURE_BYTES,
  type IdentityStateSnapshot,
  wipeBytes,
} from "../security/crypto";
import {
  CONTROL_TRANSPORT_MAX_BYTES,
  LEGACY_RELAY_DOMAIN_MAX_BYTES,
  MLS_RELAY_DOMAIN_MAX_BYTES,
  padOutgoingControlFrame,
  padOutgoingMessageFrame,
  validateAndStripIncomingControlPadding,
  validateAndStripIncomingMessagePadding,
} from "./messagePadding";
import { MLS_MAX_FRAME_BYTES, parseMlsIncomingFrame, validMlsControlFrame } from "./mlsWire";

const ATTACHMENT_CLAIM_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ATTACHMENT_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const UUID_V4_PATTERN = ATTACHMENT_ID_PATTERN;
const USERNAME_PATTERN = /^[A-Za-z0-9_-]{1,80}$/u;
const CHAT_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/u;
export const MAX_RELAY_TEXT_BYTES = 1024 * 1024;
export const PURGE_CLOSE_CODE = 4001;
export const PURGE_CLOSE_REASON = "purge";
const MESSAGE_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/u;
const PREKEY_ID_PATTERN = /^[A-Za-z0-9_-]{1,32}$/u;
const MAX_PENDING_MESSAGE_RESULTS = 256;
const MAX_PENDING_ACK_RESULTS = 256;
const MAX_PENDING_MLS_RESULTS = 256;
export const MAX_PENDING_PREKEY_LEASES = 256;
const TRANSACTION_RETRY_INTERVAL_MS = 3_000;
const TRANSACTION_RECOVERY_TIMEOUT_MS = 30_000;
export const PREKEY_LEASE_TIMEOUT_MS = 10_000;
const ATTACHMENT_CLEANUP_TIMEOUT_MS = 5_000;
const SESSION_REVOKE_TIMEOUT_MS = 5_000;
const RECONNECT_JITTER_BOUND_MS = 500;
const RECONNECT_JITTER_SAMPLE_RANGE = 2 ** 16;
const RECONNECT_JITTER_SAMPLE_LIMIT =
  Math.floor(RECONNECT_JITTER_SAMPLE_RANGE / RECONNECT_JITTER_BOUND_MS) *
  RECONNECT_JITTER_BOUND_MS;
const MAX_ATTACHMENT_PLAINTEXT_BYTES = 200 * 1024 * 1024;

export interface DownloadedEncryptedAttachmentStream {
  claim?: string;
}

export interface AttachmentPlaintextPolicy {
  expectedBytes: number;
  maxBytes: number;
}

export interface AttachmentDownloadPolicy {
  mediaType: MediaType;
  expectedPlaintextBytes: number;
}

export type RelayOperationOutcome = "ACCEPTED" | "REJECTED" | "NOT_SENT" | "AMBIGUOUS";
export type EncryptedSendOutcome = RelayOperationOutcome;

interface PendingMessageResult {
  generation: number;
  resolve: (outcome: EncryptedSendOutcome) => void;
  timer: number;
  serialized: string;
  expiresAtMs: number;
}

interface PendingMlsResult extends PendingMessageResult {
  roomId: string;
  revision: string;
  resultType: "mls_room_result" | "mls_snapshot_result";
}

export interface PrekeyLease {
  chatId: string;
  messageId: string;
  recipientUsername: string;
  recipientPublicKey: Uint8Array;
  prekeyId: string;
  expiresAtMs: number;
}

export type PrekeyLeaseErrorCode = "NOT_SENT" | "AMBIGUOUS" | "INVALID_RESPONSE" | "CLOSED";

export class PrekeyLeaseError extends Error {
  readonly code: PrekeyLeaseErrorCode;

  constructor(code: PrekeyLeaseErrorCode) {
    super(`Prekey lease ${code.toLowerCase()}`);
    this.name = "PrekeyLeaseError";
    this.code = code;
  }
}

interface PendingPrekeyLease {
  generation: number;
  key: string;
  chatId: string;
  messageId: string;
  recipientUsername: string;
  resolve: (lease: PrekeyLease) => void;
  reject: (error: PrekeyLeaseError) => void;
  timer: number;
}

interface MessageResultFrame {
  type: "message_result";
  message_id: string;
  accepted: boolean;
}

interface AckResultFrame {
  type: "ack_result";
  message_id: string;
  accepted: boolean;
}

interface MlsResultFrame {
  type: "mls_room_result" | "mls_snapshot_result";
  protocol_version: 10;
  room_id: string;
  message_id: string;
  revision: string;
  accepted: boolean;
}

interface PrekeyLeaseFrame {
  type: "prekey_lease";
  chat_id: string;
  message_id: string;
  recipient_username: string;
  recipient_public_key_b64: string;
  prekey_id: string;
  expires_at_ms: number;
}

/**
 * Best-effort logout for transport keys that will not be used again; the
 * keys are wiped whether or not the relay answers.
 */
export async function revokeTransportKeys(
  apiBaseUrl: string,
  keys: TransportKeys,
  signal?: AbortSignal,
): Promise<void> {
  try {
    await logoutV11(apiBaseUrl, keys, signal ?? AbortSignal.timeout(SESSION_REVOKE_TIMEOUT_MS)).catch(() => false);
  } finally {
    wipeTransportKeys(keys);
  }
}

export async function revokeSession(session: AccountSession, signal?: AbortSignal): Promise<void> {
  await revokeTransportKeys(session.endpoint.apiBaseUrl, session.transport, signal);
}

async function requestWebSocketTicket(
  session: AccountSession,
  signal: AbortSignal,
): Promise<string> {
  const attestation = currentBuildAttestation();
  try {
    const { ticket } = await issueWsTicketV11(session.endpoint.apiBaseUrl, session.transport, {
      platform: attestation.platform,
      version: attestation.version,
      buildSignatureB64: attestation.build_signature_b64,
    }, signal);
    return ticket;
  } catch (error) {
    if (error instanceof ControlRejected && error.rejection) {
      throw error.rejection === "build" ? new BuildAdmissionError() : new RelayRejectionError(error.rejection);
    }
    throw error;
  }
}

/**
 * Terminal ws-ticket outcomes. Anything else (5xx, 429, network, an
 * unexpected reply) is transient and retried with backoff.
 */
export type RelayRejection = "build" | "session-expired" | "platform-conflict";

export class RelayRejectionError extends Error {
  constructor(readonly rejection: RelayRejection) {
    super("Relay rejected the session");
    this.name = "RelayRejectionError";
  }
}

export class BuildAdmissionError extends RelayRejectionError {
  constructor() {
    super("build");
    this.message = "Release verification rejected";
    this.name = "BuildAdmissionError";
  }
}

/** One socket's record layer: the v11 AEAD channel in production. */
export interface SocketChannel {
  /** True once frames may be sent (after the relay's handshake reply). */
  readonly ready: boolean;
  /** The first message to send when the socket opens, if the channel needs a handshake. */
  clientHello(): Uint8Array | null;
  /** Opens one incoming message; null for a handshake message. Throws if it does not authenticate. */
  receive(data: unknown): string | null;
  seal(text: string): Uint8Array | string;
  destroy(): void;
}

/** How a RelaySocket obtains tickets and record channels; replaceable in tests. */
export interface RelaySocketTransport {
  subprotocols: readonly string[];
  issueTicket(session: AccountSession, signal: AbortSignal): Promise<string>;
  openChannel(session: AccountSession, ticket: string): SocketChannel;
}

export const V11_RELAY_TRANSPORT: RelaySocketTransport = {
  subprotocols: [WS_PROTOCOL_V11],
  issueTicket: (session, signal) => requestWebSocketTicket(session, signal),
  openChannel: (session, ticket) => new V11SocketChannel(session.transport, ticket),
};

export class RelaySocket {
  #socket: WebSocket | null = null;
  /** The record layer of each open socket. */
  #channels = new WeakMap<WebSocket, SocketChannel>();

  /** Seals one text frame for [socket]; throws before the handshake completes. */
  #sendSealed(socket: WebSocket, text: string): void {
    const channel = this.#channels.get(socket);
    if (!channel?.ready) throw new Error("Transport unavailable");
    const sealed = channel.seal(text);
    socket.send(typeof sealed === "string" ? sealed : sealed as BufferSource);
  }
  #socketGeneration = 0;
  #manualClose = false;
  #reconnectTimer: number | undefined;
  #attempt = 0;
  #connectGeneration = 0;
  #ticketAbort: AbortController | null = null;
  #connecting = false;
  #purgeFrameSeen = false;
  #purgeNotified = false;
  #pendingResults = new Map<string, PendingMessageResult>();
  #pendingAckResults = new Map<string, PendingMessageResult>();
  #pendingMlsResults = new Map<string, PendingMlsResult>();
  #pendingPrekeyLeases = new Map<string, PendingPrekeyLease>();
  #directoryStamp: DirectoryStamp | null = null;

  constructor(
    private readonly session: AccountSession,
    private readonly onFrame: (frame: IncomingFrame) => void,
    private readonly onState: (state: "connecting" | "connected" | "disconnected") => void,
    private readonly onPurge?: () => void,
    private readonly onRejected?: (rejection: RelayRejection) => void,
    private readonly transport: RelaySocketTransport = V11_RELAY_TRANSPORT,
  ) {}

  connect(): void {
    if (this.#socket || this.#manualClose || this.#connecting) return;
    const generation = ++this.#connectGeneration;
    this.#purgeFrameSeen = false;
    const ticketAbort = new AbortController();
    this.#ticketAbort = ticketAbort;
    this.#connecting = true;
    this.onState("connecting");
    void this.openSocketWithTicket(generation, ticketAbort);
  }

  send(frame: object): boolean {
    const serialized = serializeRelayFrame(frame);
    if (serialized === null || this.#socket?.readyState !== WebSocket.OPEN) return false;
    try {
      this.#sendSealed(this.#socket, serialized);
      return true;
    } catch {
      return false;
    }
  }

  /** Installs the latest authenticated directory evidence for encrypted sends. */
  setDirectoryStamp(stamp: DirectoryStamp | null): void {
    this.#directoryStamp = stamp ? { ...stamp } : null;
  }

  sendEncryptedPayload(messageId: string, frame: object): Promise<EncryptedSendOutcome> {
    if (
      !MESSAGE_ID_PATTERN.test(messageId) ||
      !plainRecord(frame) ||
      frame.type !== "message" ||
      frame.message_id !== messageId ||
      this.#socket?.readyState !== WebSocket.OPEN ||
      this.#pendingResults.size >= MAX_PENDING_MESSAGE_RESULTS ||
      this.#pendingResults.has(messageId)
    ) {
      return Promise.resolve("NOT_SENT");
    }
    const stamp = this.#directoryStamp;
    if (!stamp || !frameDirectoryStampMatches(frame, stamp)) {
      return Promise.resolve("NOT_SENT");
    }
    const serialized = padOutgoingMessageFrame(frame);
    if (serialized === null) return Promise.resolve("NOT_SENT");
    const socket = this.#socket;
    const generation = this.#socketGeneration;
    return new Promise<EncryptedSendOutcome>((resolve) => {
      const pending: PendingMessageResult = {
        generation,
        resolve,
        timer: 0,
        serialized,
        expiresAtMs: Date.now() + TRANSACTION_RECOVERY_TIMEOUT_MS,
      };
      this.#pendingResults.set(messageId, pending);
      try {
        this.#sendSealed(socket, serialized);
        this.armRecoverableTimer(this.#pendingResults, messageId, pending, "message recovery expired");
      } catch {
        window.clearTimeout(pending.timer);
        this.#pendingResults.delete(messageId);
        pending.serialized = "";
        resolve("NOT_SENT");
      }
    });
  }

  sendMlsTransaction(roomId: string, messageId: string, revision: bigint, frame: object): Promise<EncryptedSendOutcome> {
    const revisionText = revision.toString(10);
    if (!CHAT_ID_PATTERN.test(roomId) || !MESSAGE_ID_PATTERN.test(messageId) ||
      !plainRecord(frame) || frame.room_id !== roomId || frame.message_id !== messageId ||
      frame.revision !== revisionText ||
      (frame.type !== "mls_application" && frame.type !== "mls_membership_commit") ||
      this.#socket?.readyState !== WebSocket.OPEN || this.#pendingMlsResults.size >= MAX_PENDING_MLS_RESULTS ||
      this.#pendingMlsResults.has(messageId)) return Promise.resolve("NOT_SENT");
    const serialized = serializeRelayFrame(frame, MLS_MAX_FRAME_BYTES);
    if (serialized === null) return Promise.resolve("NOT_SENT");
    const socket = this.#socket;
    const generation = this.#socketGeneration;
    return new Promise<EncryptedSendOutcome>((resolve) => {
      const pending: PendingMlsResult = {
        generation, resolve, timer: 0, serialized,
        expiresAtMs: Date.now() + TRANSACTION_RECOVERY_TIMEOUT_MS,
        roomId, revision: revisionText, resultType: "mls_room_result",
      };
      this.#pendingMlsResults.set(messageId, pending);
      try {
        this.#sendSealed(socket, serialized);
        this.armRecoverableTimer(this.#pendingMlsResults, messageId, pending, "MLS recovery expired");
      }
      catch {
        window.clearTimeout(pending.timer);
        this.#pendingMlsResults.delete(messageId);
        pending.serialized = "";
        resolve("NOT_SENT");
      }
    });
  }

  sendMlsSnapshot(roomId: string, messageId: string, revision: bigint, frame: object): Promise<EncryptedSendOutcome> {
    const revisionText = revision.toString(10);
    if (!CHAT_ID_PATTERN.test(roomId) || !MESSAGE_ID_PATTERN.test(messageId) || !plainRecord(frame) ||
      frame.type !== "mls_state_snapshot" || frame.room_id !== roomId || frame.message_id !== messageId ||
      frame.revision !== revisionText || this.#socket?.readyState !== WebSocket.OPEN ||
      this.#pendingMlsResults.size >= MAX_PENDING_MLS_RESULTS || this.#pendingMlsResults.has(messageId)) return Promise.resolve("NOT_SENT");
    const serialized = serializeRelayFrame(frame, MLS_MAX_FRAME_BYTES);
    if (serialized === null) return Promise.resolve("NOT_SENT");
    const socket = this.#socket; const generation = this.#socketGeneration;
    return new Promise<EncryptedSendOutcome>((resolve) => {
      const pending: PendingMlsResult = {
        generation, resolve, timer: 0, serialized,
        expiresAtMs: Date.now() + TRANSACTION_RECOVERY_TIMEOUT_MS,
        roomId, revision: revisionText, resultType: "mls_snapshot_result",
      };
      this.#pendingMlsResults.set(messageId, pending);
      try {
        this.#sendSealed(socket, serialized);
        this.armRecoverableTimer(this.#pendingMlsResults, messageId, pending, "MLS snapshot recovery expired");
      } catch {
        window.clearTimeout(pending.timer);
        this.#pendingMlsResults.delete(messageId);
        pending.serialized = "";
        resolve("NOT_SENT");
      }
    });
  }

  sendMlsControl(frame: object): boolean {
    if (!plainRecord(frame) || !validMlsControlFrame(frame)) return false;
    const serialized = serializeRelayFrame(frame, MLS_MAX_FRAME_BYTES);
    if (serialized === null || this.#socket?.readyState !== WebSocket.OPEN) return false;
    try { this.#sendSealed(this.#socket, serialized); return true; } catch { return false; }
  }

  requestPrekeyLease(
    chatId: string,
    messageId: string,
    recipientUsername: string,
  ): Promise<PrekeyLease> {
    const key = prekeyLeaseKey(chatId, messageId, recipientUsername);
    if (
      !CHAT_ID_PATTERN.test(chatId) ||
      !MESSAGE_ID_PATTERN.test(messageId) ||
      !USERNAME_PATTERN.test(recipientUsername) ||
      this.#socket?.readyState !== WebSocket.OPEN ||
      this.#pendingPrekeyLeases.size >= MAX_PENDING_PREKEY_LEASES ||
      this.#pendingPrekeyLeases.has(key)
    ) return Promise.reject(new PrekeyLeaseError("NOT_SENT"));

    const socket = this.#socket;
    const generation = this.#socketGeneration;
    const serialized = serializeRelayFrame({
      type: "prekey_lease",
      chat_id: chatId,
      message_id: messageId,
      recipient_username: recipientUsername,
    });
    if (serialized === null) return Promise.reject(new PrekeyLeaseError("NOT_SENT"));
    return new Promise<PrekeyLease>((resolve, reject) => {
      const timer = window.setTimeout(() => {
        const pending = this.#pendingPrekeyLeases.get(key);
        if (!pending || pending.generation !== generation) return;
        this.#pendingPrekeyLeases.delete(key);
        pending.reject(new PrekeyLeaseError("AMBIGUOUS"));
      }, PREKEY_LEASE_TIMEOUT_MS);
      this.#pendingPrekeyLeases.set(key, {
        generation,
        key,
        chatId,
        messageId,
        recipientUsername,
        resolve,
        reject,
        timer,
      });
      try {
        this.#sendSealed(socket, serialized);
      } catch {
        window.clearTimeout(timer);
        this.#pendingPrekeyLeases.delete(key);
        reject(new PrekeyLeaseError("NOT_SENT"));
      }
    });
  }

  releasePrekeyLease(lease: Pick<PrekeyLease, "chatId" | "messageId" | "recipientUsername" | "prekeyId">): boolean {
    if (
      !CHAT_ID_PATTERN.test(lease.chatId) ||
      !MESSAGE_ID_PATTERN.test(lease.messageId) ||
      !USERNAME_PATTERN.test(lease.recipientUsername) ||
      !PREKEY_ID_PATTERN.test(lease.prekeyId)
    ) return false;
    return this.send({
      type: "prekey_lease_release",
      chat_id: lease.chatId,
      message_id: lease.messageId,
      recipient_username: lease.recipientUsername,
      prekey_id: lease.prekeyId,
    });
  }

  join(chatId: string): boolean {
    return this.send({ type: "join", chat_id: chatId });
  }

  leave(chatId: string): boolean {
    return this.send({ type: "leave", chat_id: chatId });
  }

  createRoom(room: RoomRecord): boolean {
    return this.send({ type: "create_room", room });
  }

  deleteRoom(chatId: string): boolean {
    return this.send({ type: "delete_room", chat_id: chatId });
  }

  openDirect(peerUsername: string): boolean {
    return this.send({ type: "open_direct", peer_username: peerUsername });
  }

  wipe(): boolean {
    return this.send({ type: "global_wipe" });
  }

  activity(): boolean {
    return this.send({ type: "activity" });
  }

  acknowledge(
    chatId: string,
    messageId: string,
    senderUsername: string,
    state: IdentityStateSnapshot,
    ackSignature: Uint8Array,
    usedPrekeyId: string,
  ): Promise<RelayOperationOutcome> {
    if (
      !MESSAGE_ID_PATTERN.test(messageId) ||
      state.stateSignature.byteLength !== STATE_SIGNATURE_BYTES ||
      state.identityPublicKey.byteLength !== IDENTITY_PUBLIC_KEY_BYTES ||
      !PREKEY_ID_PATTERN.test(state.prekeyId) ||
      ackSignature.byteLength !== STATE_SIGNATURE_BYTES ||
      this.#socket?.readyState !== WebSocket.OPEN ||
      this.#pendingAckResults.size >= MAX_PENDING_ACK_RESULTS ||
      this.#pendingAckResults.has(messageId)
    ) return Promise.resolve("NOT_SENT");
    const frame: Record<string, unknown> = {
      type: "message_ack",
      chat_id: chatId,
      message_id: messageId,
      sender_username: senderUsername,
      state_revision: state.revision,
      identity_envelope_b64: bytesToBase64(state.envelope),
      identity_public_b64: bytesToBase64(state.identityPublicKey),
      prekey_id: state.prekeyId,
      state_signature_b64: bytesToBase64(state.stateSignature),
      ack_signature_b64: bytesToBase64(ackSignature),
      used_prekey_id: usedPrekeyId,
    };
    const serialized = serializeRelayFrame(frame);
    if (serialized === null) return Promise.resolve("NOT_SENT");
    const socket = this.#socket;
    const generation = this.#socketGeneration;
    return new Promise<RelayOperationOutcome>((resolve) => {
      const pending: PendingMessageResult = {
        generation,
        resolve,
        timer: 0,
        serialized,
        expiresAtMs: Date.now() + TRANSACTION_RECOVERY_TIMEOUT_MS,
      };
      this.#pendingAckResults.set(messageId, pending);
      try {
        this.#sendSealed(socket, serialized);
        this.armRecoverableTimer(this.#pendingAckResults, messageId, pending, "ack recovery expired");
      } catch {
        window.clearTimeout(pending.timer);
        this.#pendingAckResults.delete(messageId);
        pending.serialized = "";
        resolve("NOT_SENT");
      }
    });
  }

  syncIdentityState(state: IdentityStateSnapshot): boolean {
    if (state.stateSignature.byteLength !== STATE_SIGNATURE_BYTES ||
      state.identityPublicKey.byteLength !== IDENTITY_PUBLIC_KEY_BYTES ||
      !PREKEY_ID_PATTERN.test(state.prekeyId)) return false;
    return this.send({
      type: "identity_state",
      state_revision: state.revision,
      identity_envelope_b64: bytesToBase64(state.envelope),
      identity_public_b64: bytesToBase64(state.identityPublicKey),
      prekey_id: state.prekeyId,
      state_signature_b64: bytesToBase64(state.stateSignature),
    });
  }

  close(): void {
    this.#manualClose = true;
    this.#connectGeneration += 1;
    this.#ticketAbort?.abort();
    this.#ticketAbort = null;
    this.#connecting = false;
    window.clearTimeout(this.#reconnectTimer);
    this.#reconnectTimer = undefined;
    this.settlePending("AMBIGUOUS");
    this.settleAckPending("AMBIGUOUS");
    this.settleMlsPending("AMBIGUOUS");
    this.settlePrekeyPending(new PrekeyLeaseError("CLOSED"));
    this.#socket?.close(1000, "client disconnect");
    this.#socket = null;
    this.#socketGeneration = 0;
    this.#directoryStamp = null;
    this.onState("disconnected");
  }

  private scheduleReconnect(): void {
    if (this.#manualClose || this.#socket || this.#connecting || this.#reconnectTimer !== undefined) return;
    const jitter = randomReconnectJitter();
    const delay = Math.min(15_000, 750 * 2 ** Math.min(this.#attempt++, 5)) + jitter;
    this.#reconnectTimer = window.setTimeout(() => {
      this.#reconnectTimer = undefined;
      this.connect();
    }, delay);
  }

  private async openSocketWithTicket(
    generation: number,
    ticketAbort: AbortController,
  ): Promise<void> {
    const ticketHolder = { value: "" };
    let protocols: string[] | null = null;
    try {
      ticketHolder.value = await this.transport.issueTicket(this.session, ticketAbort.signal);
      if (!this.isCurrentConnectionAttempt(generation, ticketAbort)) return;
      // The ticket travels inside the encrypted ClientHello, never in a header.
      const channel = this.transport.openChannel(this.session, ticketHolder.value);
      protocols = [...this.transport.subprotocols];
      const socket = new WebSocket(`${this.session.endpoint.wsBaseUrl}/v1/ws`, protocols);
      socket.binaryType = "arraybuffer";
      this.#channels.set(socket, channel);
      this.#socket = socket;
      this.#socketGeneration = generation;
      const markConnected = () => {
        this.#attempt = 0;
        this.onState("connected");
        this.resendPendingTransactions(socket, generation);
      };
      socket.onopen = () => {
        if (this.#socket !== socket || this.#socketGeneration !== generation) return;
        try {
          const hello = channel.clientHello();
          if (hello) socket.send(hello as BufferSource);
        } catch {
          socket.close();
          return;
        }
        if (channel.ready) markConnected();
      };
      socket.onmessage = (event) => {
        if (this.#socket !== socket || this.#socketGeneration !== generation) return;
        let text: string | null;
        try {
          text = channel.receive(event.data);
        } catch {
          this.failClosed("unauthenticated relay frame");
          return;
        }
        if (text === null) {
          // The relay's handshake reply verified: the channel is ready.
          if (channel.ready) markConnected();
          return;
        }
        if (!utf8LengthWithin(text, CONTROL_TRANSPORT_MAX_BYTES) ||
          (!utf8LengthWithin(text, MAX_RELAY_TEXT_BYTES) && !looksLikeMlsFrame(text))) {
          this.#manualClose = true;
          socket.close(1009, "frame too large");
          return;
        }
        const parsed = parseRelayFrame(text);
        if (parsed.kind === "invalid-result") {
          this.failClosed("invalid relay result");
          return;
        }
        if (parsed.kind === "result") {
          if (parsed.result.type === "message_result") {
            this.resolveMessageResult(parsed.result);
          } else {
            this.resolveAckResult(parsed.result);
          }
          return;
        }
        if (parsed.kind === "mls-result") {
          this.resolveMlsResult(parsed.result);
          return;
        }
        if (parsed.kind === "prekey-lease") {
          this.resolvePrekeyLease(parsed.lease);
          return;
        }
        if (parsed.kind !== "frame") return;
        const frame = parsed.frame;
        if (frame.type === "GLOBAL_WIPE" || frame.type === "global_wipe") {
          // The text command remains the compatibility fallback. If the relay
          // follows it with the purge close, do not invoke the callback twice.
          this.#purgeFrameSeen = true;
        }
        this.onFrame(frame);
      };
      socket.onerror = () => {
        if (this.#socket !== socket || this.#socketGeneration !== generation) return;
        this.settlePrekeyPending(new PrekeyLeaseError("AMBIGUOUS"));
        socket.close();
      };
      socket.onclose = (event) => {
        this.#channels.get(socket)?.destroy();
        this.#channels.delete(socket);
        if (this.#socket !== socket || this.#socketGeneration !== generation) return;
        if (event.code === PURGE_CLOSE_CODE && event.reason === PURGE_CLOSE_REASON) {
          this.terminateForPurge();
          return;
        }
        this.settlePrekeyPending(new PrekeyLeaseError("AMBIGUOUS"));
        this.#socket = null;
        this.#socketGeneration = 0;
        this.onState("disconnected");
        if (!this.#manualClose) this.scheduleReconnect();
      };
    } catch (error) {
      if (this.isCurrentConnectionAttempt(generation, ticketAbort)) {
        this.#ticketAbort = null;
        this.#connecting = false;
        this.onState("disconnected");
        if (error instanceof RelayRejectionError) {
          this.#manualClose = true;
          this.onRejected?.(error.rejection);
        } else {
          this.scheduleReconnect();
        }
      }
    } finally {
      ticketHolder.value = "";
      if (protocols) protocols[1] = "ticket.";
      if (this.#connectGeneration === generation && this.#ticketAbort === ticketAbort) {
        this.#ticketAbort = null;
        this.#connecting = false;
      }
    }
  }

  private isCurrentConnectionAttempt(generation: number, ticketAbort: AbortController): boolean {
    return this.#connectGeneration === generation &&
      this.#ticketAbort === ticketAbort &&
      !ticketAbort.signal.aborted &&
      !this.#manualClose;
  }

  private terminateForPurge(): void {
    this.#manualClose = true;
    this.#connectGeneration += 1;
    this.#ticketAbort?.abort();
    this.#ticketAbort = null;
    this.#connecting = false;
    window.clearTimeout(this.#reconnectTimer);
    this.#reconnectTimer = undefined;
    this.settlePending("AMBIGUOUS");
    this.settleAckPending("AMBIGUOUS");
    this.settleMlsPending("AMBIGUOUS");
    this.settlePrekeyPending(new PrekeyLeaseError("CLOSED"));
    this.#socket = null;
    this.#socketGeneration = 0;
    this.#directoryStamp = null;
    this.onState("disconnected");
    if (!this.#purgeFrameSeen && !this.#purgeNotified) {
      this.#purgeNotified = true;
      this.onPurge?.();
    }
  }

  private resolveMessageResult(result: MessageResultFrame): void {
    const pending = this.#pendingResults.get(result.message_id);
    if (!pending || pending.generation !== this.#socketGeneration) {
      this.failClosed("unknown message result");
      return;
    }
    this.#pendingResults.delete(result.message_id);
    window.clearTimeout(pending.timer);
    pending.serialized = "";
    pending.resolve(result.accepted ? "ACCEPTED" : "REJECTED");
  }

  private resolveAckResult(result: AckResultFrame): void {
    const pending = this.#pendingAckResults.get(result.message_id);
    if (!pending || pending.generation !== this.#socketGeneration) {
      this.failClosed("unknown ack result");
      return;
    }
    this.#pendingAckResults.delete(result.message_id);
    window.clearTimeout(pending.timer);
    pending.serialized = "";
    pending.resolve(result.accepted ? "ACCEPTED" : "REJECTED");
  }

  private resolveMlsResult(result: MlsResultFrame): void {
    const pending = this.#pendingMlsResults.get(result.message_id);
    if (!pending || pending.generation !== this.#socketGeneration || pending.resultType !== result.type ||
      pending.roomId !== result.room_id || pending.revision !== result.revision) {
      this.failClosed("unknown MLS result");
      return;
    }
    this.#pendingMlsResults.delete(result.message_id);
    window.clearTimeout(pending.timer);
    pending.serialized = "";
    pending.resolve(result.accepted ? "ACCEPTED" : "REJECTED");
  }

  private armRecoverableTimer<T extends PendingMessageResult>(
    pendingMap: Map<string, T>,
    messageId: string,
    pending: T,
    expiryReason: string,
  ): void {
    window.clearTimeout(pending.timer);
    const remaining = pending.expiresAtMs - Date.now();
    if (remaining <= 0) {
      if (pendingMap.get(messageId) !== pending) return;
      pendingMap.delete(messageId);
      pending.serialized = "";
      pending.resolve("AMBIGUOUS");
      this.failClosed(expiryReason);
      return;
    }
    pending.timer = window.setTimeout(() => {
      if (pendingMap.get(messageId) !== pending) return;
      const socket = this.#socket;
      if (socket?.readyState === WebSocket.OPEN) {
        this.resendPendingTransaction(pendingMap, messageId, pending, socket, this.#socketGeneration, expiryReason);
      } else {
        this.armRecoverableTimer(pendingMap, messageId, pending, expiryReason);
      }
    }, Math.min(TRANSACTION_RETRY_INTERVAL_MS, remaining));
  }

  private resendPendingTransaction<T extends PendingMessageResult>(
    pendingMap: Map<string, T>,
    messageId: string,
    pending: T,
    socket: WebSocket,
    generation: number,
    expiryReason: string,
  ): void {
    if (pendingMap.get(messageId) !== pending) return;
    if (pending.expiresAtMs <= Date.now()) {
      this.armRecoverableTimer(pendingMap, messageId, pending, expiryReason);
      return;
    }
    pending.generation = generation;
    try {
      this.#sendSealed(socket, pending.serialized);
    } catch {
      try { socket.close(); } catch { /* recovery timer remains authoritative */ }
    }
    this.armRecoverableTimer(pendingMap, messageId, pending, expiryReason);
  }

  private resendPendingTransactions(socket: WebSocket, generation: number): void {
    const replay = <T extends PendingMessageResult>(
      pendingMap: Map<string, T>,
      expiryReason: string,
    ) => {
      [...pendingMap.entries()].forEach(([messageId, pending]) => {
        if (this.#socket !== socket || this.#socketGeneration !== generation) return;
        this.resendPendingTransaction(pendingMap, messageId, pending, socket, generation, expiryReason);
      });
    };
    replay(this.#pendingResults, "message recovery expired");
    replay(this.#pendingAckResults, "ack recovery expired");
    replay(this.#pendingMlsResults, "MLS recovery expired");
  }

  private settlePending(outcome: RelayOperationOutcome): void {
    const pending = [...this.#pendingResults.values()];
    this.#pendingResults.clear();
    pending.forEach((entry) => {
      window.clearTimeout(entry.timer);
      entry.serialized = "";
      entry.resolve(outcome);
    });
  }

  private settleAckPending(outcome: RelayOperationOutcome): void {
    const pending = [...this.#pendingAckResults.values()];
    this.#pendingAckResults.clear();
    pending.forEach((entry) => {
      window.clearTimeout(entry.timer);
      entry.serialized = "";
      entry.resolve(outcome);
    });
  }

  private settleMlsPending(outcome: RelayOperationOutcome): void {
    const pending = [...this.#pendingMlsResults.values()];
    this.#pendingMlsResults.clear();
    pending.forEach((entry) => {
      window.clearTimeout(entry.timer);
      entry.serialized = "";
      entry.resolve(outcome);
    });
  }

  private settlePrekeyPending(error: PrekeyLeaseError): void {
    const pending = [...this.#pendingPrekeyLeases.values()];
    this.#pendingPrekeyLeases.clear();
    pending.forEach((entry) => {
      window.clearTimeout(entry.timer);
      entry.reject(error);
    });
  }

  private resolvePrekeyLease(frame: PrekeyLeaseFrame): void {
    const key = prekeyLeaseKey(frame.chat_id, frame.message_id, frame.recipient_username);
    const pending = this.#pendingPrekeyLeases.get(key);
    if (!pending || pending.generation !== this.#socketGeneration) {
      this.failClosed("unknown prekey lease");
      return;
    }
    let recipientPublicKey: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    try {
      recipientPublicKey = base64ToBytes(frame.recipient_public_key_b64);
      if (
        recipientPublicKey.byteLength !== IDENTITY_PUBLIC_KEY_BYTES ||
        bytesToBase64(recipientPublicKey) !== frame.recipient_public_key_b64 ||
        !PREKEY_ID_PATTERN.test(frame.prekey_id) ||
        !Number.isSafeInteger(frame.expires_at_ms) ||
        frame.expires_at_ms <= 0
      ) throw new Error("invalid prekey lease");
      this.#pendingPrekeyLeases.delete(key);
      window.clearTimeout(pending.timer);
      pending.resolve({
        chatId: frame.chat_id,
        messageId: frame.message_id,
        recipientUsername: frame.recipient_username,
        recipientPublicKey,
        prekeyId: frame.prekey_id,
        expiresAtMs: frame.expires_at_ms,
      });
    } catch {
      wipeBytes(recipientPublicKey);
      this.#pendingPrekeyLeases.delete(key);
      window.clearTimeout(pending.timer);
      pending.reject(new PrekeyLeaseError("INVALID_RESPONSE"));
      this.failClosed("invalid prekey lease");
    }
  }

  private failClosed(reason: string): void {
    this.#manualClose = true;
    this.#connectGeneration += 1;
    this.#ticketAbort?.abort();
    this.#ticketAbort = null;
    this.#connecting = false;
    window.clearTimeout(this.#reconnectTimer);
    this.#reconnectTimer = undefined;
    this.settlePending("AMBIGUOUS");
    this.settleAckPending("AMBIGUOUS");
    this.settleMlsPending("AMBIGUOUS");
    this.settlePrekeyPending(new PrekeyLeaseError("CLOSED"));
    const socket = this.#socket;
    this.#socket = null;
    this.#socketGeneration = 0;
    try {
      socket?.close(1002, reason);
    } catch {
      // The pending operations have already been failed closed.
    }
    this.onState("disconnected");
  }
}

export function uploadEncryptedAttachment(
  session: AccountSession,
  chatId: string,
  messageId: string,
  mediaType: string,
  encrypted: Uint8Array | Blob,
  options: AttachmentOptions,
  onProgress: (progress: UploadProgress) => void,
  signal?: AbortSignal,
): Promise<string> {
  if (!validUuid(messageId)) return Promise.reject(new Error("Upload rejected"));
  if (signal?.aborted) return Promise.reject(new Error("Upload aborted"));
  const encryptedBytes = encrypted instanceof Blob ? encrypted.size : encrypted.byteLength;
  if (!Number.isSafeInteger(encryptedBytes) || encryptedBytes <= 0 ||
    encryptedBytes > maxSerializedAttachmentBytes(mediaType) ||
    encryptedBytes % ATTACHMENT_CHUNK_RECORD_BYTES !== 0) {
    return Promise.reject(new Error("Upload rejected"));
  }
  const ciphertext = encrypted instanceof Blob ? encrypted : new Blob([encrypted as BlobPart]);
  return uploadAttachmentV11(session.endpoint.apiBaseUrl, session.transport, {
    chatId,
    messageId,
    mediaType,
    cipherVersion: ATTACHMENT_CIPHER_VERSION,
    ciphertext,
    oneTime: options.oneTime,
    deleteAfterDownload: options.deleteAfterDownload || options.oneTime,
    ttlSec: Math.max(0, options.ttlSec),
  }, (loaded, total) => onProgress({
    // The sealed body adds a header and padding; report progress over the attachment bytes.
    loaded: Math.min(encryptedBytes, Math.floor((loaded / Math.max(1, total)) * encryptedBytes)),
    total: encryptedBytes,
  }), signal);
}

export async function streamEncryptedAttachmentRecords(
  session: AccountSession,
  attachmentId: string,
  policy: AttachmentDownloadPolicy,
  onRecord: (record: Uint8Array, chunkIndex: number) => void | Promise<void>,
  signal?: AbortSignal,
): Promise<DownloadedEncryptedAttachmentStream> {
  const validatedAttachmentId = validateAttachmentId(attachmentId);
  const expectedEncryptedBytes = expectedAttachmentCiphertextBytes(policy);
  let claim: string | undefined;
  const record = new Uint8Array(ATTACHMENT_CHUNK_RECORD_BYTES);
  let recordOffset = 0;
  let chunkIndex = 0;
  try {
    const result = await downloadAttachmentV11(
      session.endpoint.apiBaseUrl,
      session.transport,
      validatedAttachmentId,
      maxSerializedAttachmentBytes(policy.mediaType),
      async (payload) => {
        // Re-chunk the transport payloads into the inner cipher's fixed records.
        let sourceOffset = 0;
        while (sourceOffset < payload.byteLength) {
          const copied = Math.min(ATTACHMENT_CHUNK_RECORD_BYTES - recordOffset, payload.byteLength - sourceOffset);
          record.set(payload.subarray(sourceOffset, sourceOffset + copied), recordOffset);
          recordOffset += copied;
          sourceOffset += copied;
          if (recordOffset === ATTACHMENT_CHUNK_RECORD_BYTES) {
            await onRecord(record, chunkIndex);
            record.fill(0);
            recordOffset = 0;
            chunkIndex += 1;
          }
        }
      },
      signal,
    );
    if (result.claimId) {
      claim = attachmentIdString(result.claimId);
      result.claimId.fill(0);
    }
    if (result.total !== expectedEncryptedBytes || recordOffset !== 0 ||
      chunkIndex !== expectedEncryptedBytes / ATTACHMENT_CHUNK_RECORD_BYTES) {
      throw new Error("Attachment unavailable");
    }
    return claim ? { claim } : {};
  } catch (error) {
    if (claim) {
      await releaseAttachmentDownloadClaim(session, validatedAttachmentId, claim).catch(() => undefined);
    }
    throw error;
  } finally {
    record.fill(0);
  }
}

export async function completeAttachmentDownload(
  session: AccountSession,
  attachmentId: string,
  claim: string,
  signal?: AbortSignal,
): Promise<void> {
  const claimId = attachmentIdBytes(validateAttachmentClaim(claim));
  try {
    if (!await completeDownloadV11(session.endpoint.apiBaseUrl, session.transport, validateAttachmentId(attachmentId), claimId, signal)) {
      throw new Error("Attachment unavailable");
    }
  } finally {
    claimId.fill(0);
  }
}

export async function releaseAttachmentDownloadClaim(
  session: AccountSession,
  attachmentId: string,
  claim: string,
  signal?: AbortSignal,
): Promise<void> {
  const claimId = attachmentIdBytes(validateAttachmentClaim(claim));
  try {
    if (!await releaseDownloadV11(
      session.endpoint.apiBaseUrl,
      session.transport,
      validateAttachmentId(attachmentId),
      claimId,
      signal ?? AbortSignal.timeout(ATTACHMENT_CLEANUP_TIMEOUT_MS),
    )) {
      throw new Error("Attachment unavailable");
    }
  } finally {
    claimId.fill(0);
  }
}

export async function deleteUploadedAttachment(
  session: AccountSession,
  attachmentId: string,
  signal?: AbortSignal,
): Promise<void> {
  // Deleting an attachment that is already gone counts as done.
  await deleteAttachmentV11(
    session.endpoint.apiBaseUrl,
    session.transport,
    validateAttachmentId(attachmentId),
    signal ?? AbortSignal.timeout(ATTACHMENT_CLEANUP_TIMEOUT_MS),
  );
}

export async function decryptAndCompleteAttachment(
  session: AccountSession,
  attachmentId: string,
  claim: string | undefined,
  decrypt: () => Uint8Array | Promise<Uint8Array>,
  policy?: AttachmentPlaintextPolicy,
  signal?: AbortSignal,
): Promise<Uint8Array> {
  let plaintext: Uint8Array | undefined;
  let claimCompleted = false;
  try {
    signal?.throwIfAborted();
    plaintext = await decrypt();
    signal?.throwIfAborted();
    const maxBytes = policy?.maxBytes ?? MAX_ATTACHMENT_PLAINTEXT_BYTES;
    if (
      !Number.isSafeInteger(maxBytes) ||
      maxBytes <= 0 ||
      plaintext.byteLength === 0 ||
      plaintext.byteLength > maxBytes ||
      (policy !== undefined && (
        !Number.isSafeInteger(policy.expectedBytes) ||
        policy.expectedBytes <= 0 ||
        policy.expectedBytes > maxBytes ||
        plaintext.byteLength !== policy.expectedBytes
      ))
    ) {
      throw new Error("Attachment unavailable");
    }
    if (claim) {
      await completeAttachmentDownload(session, attachmentId, claim, signal);
      claimCompleted = true;
    }
    signal?.throwIfAborted();
    return plaintext;
  } catch (error) {
    if (plaintext) plaintext.fill(0);
    if (claim && !claimCompleted) {
      await releaseAttachmentDownloadClaim(session, attachmentId, claim).catch(() => undefined);
    }
    throw error;
  }
}

function expectedAttachmentCiphertextBytes(policy: AttachmentDownloadPolicy): number {
  if (policy.mediaType !== "IMAGE" && policy.mediaType !== "VIDEO" && policy.mediaType !== "FILE") {
    throw new Error("Attachment unavailable");
  }
  const plaintextLimit = policy.mediaType === "IMAGE"
    ? 20 * 1024 * 1024
    : policy.mediaType === "VIDEO"
      ? 100 * 1024 * 1024
      : MAX_ATTACHMENT_PLAINTEXT_BYTES;
  if (!Number.isSafeInteger(policy.expectedPlaintextBytes) ||
    policy.expectedPlaintextBytes <= 0 ||
    policy.expectedPlaintextBytes > plaintextLimit) {
    throw new Error("Attachment unavailable");
  }
  return serializedAttachmentBytes(policy.expectedPlaintextBytes);
}

function validateAttachmentClaim(claim: string): string {
  // Keep the length check alongside the regex: JavaScript's `$` can match
  // immediately before a trailing line terminator.
  if (claim.length !== 36 || !ATTACHMENT_CLAIM_PATTERN.test(claim)) {
    throw new Error("Attachment unavailable");
  }
  return claim;
}

function validateAttachmentId(attachmentId: string): string {
  const normalized = attachmentId.trim().toLowerCase();
  if (!ATTACHMENT_ID_PATTERN.test(normalized)) throw new Error("Attachment unavailable");
  return normalized;
}

function validUuid(value: unknown): value is string {
  return typeof value === "string" && UUID_V4_PATTERN.test(value);
}

type ParsedRelayFrame =
  | { kind: "frame"; frame: IncomingFrame }
  | { kind: "result"; result: MessageResultFrame | AckResultFrame }
  | { kind: "mls-result"; result: MlsResultFrame }
  | { kind: "prekey-lease"; lease: PrekeyLeaseFrame }
  | { kind: "invalid-result" }
  | { kind: "ignored" };

function parseRelayFrame(text: string): ParsedRelayFrame {
  if (!utf8LengthWithin(text, CONTROL_TRANSPORT_MAX_BYTES)) return { kind: "ignored" };
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    return { kind: "ignored" };
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) return { kind: "ignored" };
  const frame = value as Record<string, unknown>;
  const mls = typeof frame.type === "string" && frame.type.startsWith("mls_");
  if (frame.type === "message") {
    if (!validateAndStripIncomingMessagePadding(text, frame)) {
      return { kind: "invalid-result" };
    }
  } else if (!validateAndStripIncomingControlPadding(
    text,
    frame,
    mls ? MLS_RELAY_DOMAIN_MAX_BYTES : LEGACY_RELAY_DOMAIN_MAX_BYTES,
  )) {
    return { kind: "invalid-result" };
  }
  if (mls) {
    const parsed = parseMlsIncomingFrame(frame);
    if (!parsed) return { kind: "invalid-result" };
    if (parsed.type === "mls_room_result" || parsed.type === "mls_snapshot_result") return { kind: "mls-result", result: parsed };
    return { kind: "frame", frame: parsed };
  }
  if (frame.type === "prekey_lease") {
    if (!exactObjectKeys(frame, [
      "type", "chat_id", "message_id", "recipient_username", "recipient_public_key_b64",
      "prekey_id", "expires_at_ms",
    ]) ||
      typeof frame.chat_id !== "string" || !CHAT_ID_PATTERN.test(frame.chat_id) ||
      typeof frame.message_id !== "string" || !MESSAGE_ID_PATTERN.test(frame.message_id) ||
      typeof frame.recipient_username !== "string" || !USERNAME_PATTERN.test(frame.recipient_username) ||
      typeof frame.recipient_public_key_b64 !== "string" ||
      typeof frame.prekey_id !== "string" || !PREKEY_ID_PATTERN.test(frame.prekey_id) ||
      typeof frame.expires_at_ms !== "number" || !Number.isSafeInteger(frame.expires_at_ms)) {
      return { kind: "invalid-result" };
    }
    return {
      kind: "prekey-lease",
      lease: frame as unknown as PrekeyLeaseFrame,
    };
  }
  if (frame.type === "message_result") {
    if (!exactObjectKeys(frame, ["type", "message_id", "accepted"]) ||
      typeof frame.message_id !== "string" ||
      !MESSAGE_ID_PATTERN.test(frame.message_id) ||
      typeof frame.accepted !== "boolean") {
      return { kind: "invalid-result" };
    }
    return {
      kind: "result",
      result: {
        type: "message_result",
        message_id: frame.message_id,
        accepted: frame.accepted,
      },
    };
  }
  if (frame.type === "ack_result") {
    if (!exactObjectKeys(frame, ["type", "message_id", "accepted"]) ||
      typeof frame.message_id !== "string" ||
      !MESSAGE_ID_PATTERN.test(frame.message_id) ||
      typeof frame.accepted !== "boolean") {
      return { kind: "invalid-result" };
    }
    return {
      kind: "result",
      result: {
        type: "ack_result",
        message_id: frame.message_id,
        accepted: frame.accepted,
      },
    };
  }
  const parsed = parseIncomingFrameValue(frame);
  if (parsed) return { kind: "frame", frame: parsed };
  return frame.type === "message" || frame.type === "presence"
    ? { kind: "invalid-result" }
    : { kind: "ignored" };
}

function parseIncomingFrameValue(frame: Record<string, unknown>): IncomingFrame | null {
  switch (frame.type) {
    case "GLOBAL_WIPE":
    case "global_wipe":
      return frame as IncomingFrame;
    case "presence":
      return Array.isArray(frame.users) ? frame as IncomingFrame : null;
    case "rooms":
      return Array.isArray(frame.rooms) ? frame as IncomingFrame : null;
    case "room_created":
      return plainRecord(frame.room) ? frame as IncomingFrame : null;
    case "room_deleted":
      return typeof frame.chat_id === "string" ? frame as IncomingFrame : null;
    case "directs":
      return Array.isArray(frame.directs) ? frame as IncomingFrame : null;
    case "direct_opened":
      return plainRecord(frame.direct) ? frame as IncomingFrame : null;
    case "message":
      return Number.isSafeInteger(frame.version) &&
        typeof frame.chat_id === "string" &&
        typeof frame.message_id === "string" &&
        typeof frame.nonce_b64 === "string" &&
        typeof frame.ciphertext_b64 === "string" &&
        typeof frame.signature_b64 === "string" &&
        typeof frame.wrapped_key_b64 === "string" &&
        typeof frame.sender_username === "string" &&
        typeof frame.sender_public_key_b64 === "string" &&
        (frame.identity_public_b64 === undefined || typeof frame.identity_public_b64 === "string") &&
        typeof frame.prekey_id === "string" &&
        typeof frame.is_prekey === "boolean" &&
        typeof frame.directory_node_id === "string" &&
        typeof frame.directory_revision === "number" &&
        Number.isSafeInteger(frame.directory_revision) &&
        typeof frame.directory_digest === "string"
        ? frame as IncomingFrame
        : null;
    default:
      return null;
  }
}

function randomReconnectJitter(): number {
  const sample = new Uint16Array(1);
  do {
    crypto.getRandomValues(sample);
  } while (sample[0] >= RECONNECT_JITTER_SAMPLE_LIMIT);
  return sample[0] -
    Math.floor(sample[0] / RECONNECT_JITTER_BOUND_MS) * RECONNECT_JITTER_BOUND_MS;
}

function prekeyLeaseKey(chatId: string, messageId: string, recipientUsername: string): string {
  return `${chatId}\u0000${messageId}\u0000${recipientUsername}`;
}

function serializeRelayFrame(frame: object, maxBytes = MAX_RELAY_TEXT_BYTES): string | null {
  if (maxBytes !== MAX_RELAY_TEXT_BYTES && maxBytes !== MLS_MAX_FRAME_BYTES) return null;
  return padOutgoingControlFrame(
    frame,
    maxBytes === MLS_MAX_FRAME_BYTES
      ? MLS_RELAY_DOMAIN_MAX_BYTES
      : LEGACY_RELAY_DOMAIN_MAX_BYTES,
  );
}

function frameDirectoryStampMatches(frame: object, stamp: DirectoryStamp): boolean {
  if (!plainRecord(frame)) return false;
  const record = frame as Record<string, unknown>;
  return record.directory_node_id === stamp.directory_node_id &&
    record.directory_revision === stamp.directory_revision &&
    record.directory_digest === stamp.directory_digest;
}

function exactObjectKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const expected = new Set(keys);
  const actual = Object.keys(value);
  return actual.length === expected.size && actual.every((key) => expected.has(key));
}

function plainRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function utf8LengthWithin(value: string, maxBytes: number): boolean {
  let bytes = 0;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x7f) bytes += 1;
    else if (code <= 0x7ff) bytes += 2;
    else if (code >= 0xd800 && code <= 0xdbff && index + 1 < value.length &&
      value.charCodeAt(index + 1) >= 0xdc00 && value.charCodeAt(index + 1) <= 0xdfff) {
      bytes += 4;
      index += 1;
    } else bytes += 3;
    if (bytes > maxBytes) return false;
  }
  return true;
}

function looksLikeMlsFrame(value: string): boolean {
  return /^\s*\{\s*"type"\s*:\s*"mls_[a-z_]+"/u.test(value.slice(0, 160));
}

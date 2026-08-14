import type {
  AccountResponse,
  AccountSession,
  AttachmentOptions,
  IncomingFrame,
  MediaType,
  NodeEndpoint,
  OpaqueAccountStartResponse,
  RoomRecord,
  UploadProgress,
} from "../domain/types";
import {
  base64ToBytes,
  bytesToBase64,
  maxSerializedAttachmentBytes,
  STATE_SIGNATURE_BYTES,
  type IdentityStateSnapshot,
} from "../security/crypto";

const JSON_HEADERS = { "Content-Type": "application/json" } as const;
const ATTACHMENT_CLAIM_HEADER = "X-Abyssal-Attachment-Claim";
const ATTACHMENT_CLAIM_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ATTACHMENT_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const UUID_V4_PATTERN = ATTACHMENT_ID_PATTERN;
const BASE64_URL_PATTERN = /^[A-Za-z0-9_-]+$/u;
const NODE_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/u;
const USERNAME_PATTERN = /^[A-Za-z0-9_-]{1,80}$/u;
const MAX_OPAQUE_JSON_BYTES = 768 * 1024;
const MAX_OPAQUE_MESSAGE_BYTES = 16 * 1024;
const MAX_IDENTITY_ENVELOPE_BYTES = 512 * 1024;
export const MAX_RELAY_TEXT_BYTES = 1024 * 1024;
export const PURGE_CLOSE_CODE = 4001;
export const PURGE_CLOSE_REASON = "purge";
const MESSAGE_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/u;
const MAX_PENDING_MESSAGE_RESULTS = 256;
const MAX_PENDING_ACK_RESULTS = 256;
const MESSAGE_RESULT_TIMEOUT_MS = 10_000;
const ACK_RESULT_TIMEOUT_MS = 10_000;
const MAX_WS_TICKET_JSON_BYTES = 4 * 1024;
const MAX_ATTACHMENT_UPLOAD_JSON_BYTES = 4 * 1024;
const ATTACHMENT_CLEANUP_TIMEOUT_MS = 5_000;
const SESSION_REVOKE_TIMEOUT_MS = 5_000;
const WS_TICKET_BYTES = 32;
const WS_TICKET_LENGTH = 43;
const WS_TICKET_MIN_EXPIRY_SEC = 1;
const WS_TICKET_MAX_EXPIRY_SEC = 30;
const RECONNECT_JITTER_BOUND_MS = 500;
const RECONNECT_JITTER_SAMPLE_RANGE = 2 ** 16;
const RECONNECT_JITTER_SAMPLE_LIMIT =
  Math.floor(RECONNECT_JITTER_SAMPLE_RANGE / RECONNECT_JITTER_BOUND_MS) *
  RECONNECT_JITTER_BOUND_MS;
const ATTACHMENT_BLOB_OVERHEAD_BYTES = 41;
const MAX_ATTACHMENT_PLAINTEXT_BYTES =
  maxSerializedAttachmentBytes("FILE") - ATTACHMENT_BLOB_OVERHEAD_BYTES;

export interface DownloadedEncryptedAttachment {
  bytes: Uint8Array;
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

export async function startOpaqueAccount(
  endpoint: NodeEndpoint,
  code: string,
  registrationRequest: Uint8Array,
  credentialRequest: Uint8Array,
  signal?: AbortSignal,
): Promise<OpaqueAccountStartResponse> {
  const response = await fetch(`${endpoint.apiBaseUrl}/v2/account/start`, {
    method: "POST",
    cache: "no-store",
    credentials: "omit",
    referrerPolicy: "no-referrer",
    headers: JSON_HEADERS,
    body: JSON.stringify({
      code: code.trim(),
      registration_request_b64: bytesToBase64(registrationRequest),
      credential_request_b64: bytesToBase64(credentialRequest),
    }),
    signal,
  });
  const payload = await readBoundedJson(response, MAX_OPAQUE_JSON_BYTES, signal).catch(() => null);
  if (!response.ok || !validOpaqueStartResponse(payload)) {
    throw new Error("Wrong information");
  }
  return payload;
}

interface FinishOpaqueAccountInput {
  handshakeId: string;
  registrationUpload?: Uint8Array;
  credentialFinalization?: Uint8Array;
  identityPublicKey?: Uint8Array;
  identityPrekeyId?: string;
  identityEnvelope?: Uint8Array;
  identityProof?: Uint8Array;
}

export async function finishOpaqueAccount(
  endpoint: NodeEndpoint,
  input: FinishOpaqueAccountInput,
  signal?: AbortSignal,
): Promise<AccountSession> {
  const response = await fetch(`${endpoint.apiBaseUrl}/v2/account/finish`, {
    method: "POST",
    cache: "no-store",
    credentials: "omit",
    referrerPolicy: "no-referrer",
    headers: JSON_HEADERS,
    body: JSON.stringify({
      handshake_id: input.handshakeId,
      registration_upload_b64: input.registrationUpload
        ? bytesToBase64(input.registrationUpload)
        : undefined,
      credential_finalization_b64: input.credentialFinalization
        ? bytesToBase64(input.credentialFinalization)
        : undefined,
      identity_public_b64: input.identityPublicKey
        ? bytesToBase64(input.identityPublicKey)
        : undefined,
      identity_prekey_id: input.identityPrekeyId,
      identity_envelope_b64: input.identityEnvelope
        ? bytesToBase64(input.identityEnvelope)
        : undefined,
      identity_proof_b64: input.identityProof
        ? bytesToBase64(input.identityProof)
        : undefined,
    }),
    signal,
  });
  const payload = await readBoundedJson(response, MAX_OPAQUE_JSON_BYTES, signal).catch(() => null);
  if (!response.ok || !validAccountResponse(payload)) {
    throw new Error("Wrong information");
  }
  const identityPublicKey = base64ToBytes(payload.identity_public_b64);
  if (identityPublicKey.byteLength !== 128 || !/^[A-Za-z0-9_-]{1,32}$/.test(payload.identity_prekey_id)) {
    identityPublicKey.fill(0);
    throw new Error("Wrong information");
  }
  return {
    token: payload.token,
    nodeId: payload.node_id,
    username: payload.username,
    maxRoomsPerUser: payload.max_rooms_per_user,
    sessionInactivitySec: payload.session_inactivity_sec,
    endpoint,
    created: payload.created,
    identityPublicKey,
    identityPrekeyId: payload.identity_prekey_id,
  };
}

export async function revokeSession(session: AccountSession, signal?: AbortSignal): Promise<void> {
  await fetch(`${session.endpoint.apiBaseUrl}/v1/account/logout`, {
    method: "POST",
    cache: "no-store",
    credentials: "omit",
    referrerPolicy: "no-referrer",
    keepalive: true,
    headers: { Authorization: `Bearer ${session.token}` },
    signal: signal ?? AbortSignal.timeout(SESSION_REVOKE_TIMEOUT_MS),
  }).catch(() => undefined);
}

async function requestWebSocketTicket(
  session: AccountSession,
  signal: AbortSignal,
): Promise<string> {
  const response = await fetch(`${session.endpoint.apiBaseUrl}/v1/ws-ticket`, {
    method: "POST",
    cache: "no-store",
    credentials: "omit",
    referrerPolicy: "no-referrer",
    headers: { Authorization: `Bearer ${session.token}` },
    signal,
  });
  const payload = await readBoundedJson(response, MAX_WS_TICKET_JSON_BYTES, signal).catch(() => null);
  if (!response.ok || !validWebSocketTicketResponse(payload)) {
    throw new Error("Session unavailable");
  }
  return payload.ticket;
}

export class RelaySocket {
  #socket: WebSocket | null = null;
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

  constructor(
    private readonly session: AccountSession,
    private readonly onFrame: (frame: IncomingFrame) => void,
    private readonly onState: (state: "connecting" | "connected" | "disconnected") => void,
    private readonly onPurge?: () => void,
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
      this.#socket.send(serialized);
      return true;
    } catch {
      return false;
    }
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
    const serialized = serializeRelayFrame(frame);
    if (serialized === null) return Promise.resolve("NOT_SENT");
    const socket = this.#socket;
    const generation = this.#socketGeneration;
    return new Promise<EncryptedSendOutcome>((resolve) => {
      const timer = window.setTimeout(() => {
        const pending = this.#pendingResults.get(messageId);
        if (!pending || pending.generation !== generation) return;
        this.#pendingResults.delete(messageId);
        pending.resolve("AMBIGUOUS");
        this.failClosed("message result timeout");
      }, MESSAGE_RESULT_TIMEOUT_MS);
      this.#pendingResults.set(messageId, { generation, resolve, timer });
      try {
        socket.send(serialized);
      } catch {
        window.clearTimeout(timer);
        this.#pendingResults.delete(messageId);
        resolve("NOT_SENT");
      }
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
      ackSignature.byteLength !== STATE_SIGNATURE_BYTES ||
      this.#socket?.readyState !== WebSocket.OPEN ||
      this.#pendingAckResults.size >= MAX_PENDING_ACK_RESULTS ||
      this.#pendingAckResults.has(messageId)
    ) return Promise.resolve("NOT_SENT");
    const frame = {
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
      const timer = window.setTimeout(() => {
        const pending = this.#pendingAckResults.get(messageId);
        if (!pending || pending.generation !== generation) return;
        this.#pendingAckResults.delete(messageId);
        pending.resolve("AMBIGUOUS");
        this.failClosed("ack result timeout");
      }, ACK_RESULT_TIMEOUT_MS);
      this.#pendingAckResults.set(messageId, { generation, resolve, timer });
      try {
        socket.send(serialized);
      } catch {
        window.clearTimeout(timer);
        this.#pendingAckResults.delete(messageId);
        resolve("NOT_SENT");
      }
    });
  }

  syncIdentityState(state: IdentityStateSnapshot): boolean {
    if (state.stateSignature.byteLength !== STATE_SIGNATURE_BYTES) return false;
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
    this.#socket?.close(1000, "client disconnect");
    this.#socket = null;
    this.#socketGeneration = 0;
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
      ticketHolder.value = await requestWebSocketTicket(this.session, ticketAbort.signal);
      if (!this.isCurrentConnectionAttempt(generation, ticketAbort)) return;
      protocols = ["abyssal-v1", `ticket.${ticketHolder.value}`];
      const socket = new WebSocket(`${this.session.endpoint.wsBaseUrl}/v1/ws`, protocols);
      protocols[1] = "ticket.";
      this.#socket = socket;
      this.#socketGeneration = generation;
      socket.onopen = () => {
        if (this.#socket !== socket || this.#socketGeneration !== generation) return;
        this.#attempt = 0;
        this.onState("connected");
      };
      socket.onmessage = (event) => {
        if (this.#socket !== socket || this.#socketGeneration !== generation) return;
        if (typeof event.data !== "string") return;
        if (!utf8LengthWithin(event.data, MAX_RELAY_TEXT_BYTES)) {
          this.#manualClose = true;
          socket.close(1009, "frame too large");
          return;
        }
        const parsed = parseRelayFrame(event.data);
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
        this.settlePending("AMBIGUOUS");
        this.settleAckPending("AMBIGUOUS");
        socket.close();
      };
      socket.onclose = (event) => {
        if (this.#socket !== socket || this.#socketGeneration !== generation) return;
        if (event.code === PURGE_CLOSE_CODE && event.reason === PURGE_CLOSE_REASON) {
          this.terminateForPurge();
          return;
        }
        this.settlePending("AMBIGUOUS");
        this.settleAckPending("AMBIGUOUS");
        this.#socket = null;
        this.#socketGeneration = 0;
        this.onState("disconnected");
        if (!this.#manualClose) this.scheduleReconnect();
      };
    } catch {
      if (this.isCurrentConnectionAttempt(generation, ticketAbort)) {
        this.#ticketAbort = null;
        this.#connecting = false;
        this.onState("disconnected");
        this.scheduleReconnect();
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
    this.#socket = null;
    this.#socketGeneration = 0;
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
    pending.resolve(result.accepted ? "ACCEPTED" : "REJECTED");
  }

  private settlePending(outcome: RelayOperationOutcome): void {
    const pending = [...this.#pendingResults.values()];
    this.#pendingResults.clear();
    pending.forEach((entry) => {
      window.clearTimeout(entry.timer);
      entry.resolve(outcome);
    });
  }

  private settleAckPending(outcome: RelayOperationOutcome): void {
    const pending = [...this.#pendingAckResults.values()];
    this.#pendingAckResults.clear();
    pending.forEach((entry) => {
      window.clearTimeout(entry.timer);
      entry.resolve(outcome);
    });
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
  mediaType: string,
  encrypted: Uint8Array,
  options: AttachmentOptions,
  onProgress: (progress: UploadProgress) => void,
  signal?: AbortSignal,
): Promise<string> {
  return new Promise((resolve, reject) => {
    const query = new URLSearchParams({
      chat_id: chatId,
      media_type: mediaType,
      one_time: String(options.oneTime),
      delete_after_download: String(options.deleteAfterDownload || options.oneTime),
      ttl_sec: String(Math.max(0, options.ttlSec)),
    });
    const request = new XMLHttpRequest();
    let settled = false;
    const finish = (callback: () => void) => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener("abort", abort);
      callback();
    };
    const fail = (message: string) => finish(() => reject(new Error(message)));
    const abort = () => request.abort();
    if (signal?.aborted) {
      fail("Upload aborted");
      return;
    }
    request.open("POST", `${session.endpoint.apiBaseUrl}/v1/attachment?${query}`);
    request.responseType = "text";
    request.setRequestHeader("Authorization", `Bearer ${session.token}`);
    request.setRequestHeader("Content-Type", "application/octet-stream");
    request.upload.onprogress = (event) => onProgress({ loaded: event.loaded, total: event.total || encrypted.byteLength });
    request.onprogress = (event) => {
      if (event.loaded > MAX_ATTACHMENT_UPLOAD_JSON_BYTES) {
        fail("Upload rejected");
        request.abort();
      }
    };
    request.onreadystatechange = () => {
      if (request.readyState !== XMLHttpRequest.HEADERS_RECEIVED) return;
      const declared = request.getResponseHeader("content-length");
      if (declared !== null && !validBoundedResponseLength(declared, MAX_ATTACHMENT_UPLOAD_JSON_BYTES)) {
        fail("Upload rejected");
        request.abort();
      }
    };
    request.onerror = () => fail("Upload failed");
    request.onabort = () => fail("Upload aborted");
    request.onload = () => {
      if (request.status < 200 || request.status >= 300 ||
        !utf8LengthWithin(request.responseText, MAX_ATTACHMENT_UPLOAD_JSON_BYTES)) {
        fail("Upload rejected");
        return;
      }
      try {
        const payload = JSON.parse(request.responseText) as unknown;
        if (!plainObjectWithKeys(payload, ["attachment_id"]) ||
          typeof payload.attachment_id !== "string") throw new Error("Upload rejected");
        const id = validateAttachmentId(payload.attachment_id);
        finish(() => resolve(id));
      } catch {
        fail("Upload rejected");
      }
    };
    signal?.addEventListener("abort", abort, { once: true });
    // XMLHttpRequest accepts ArrayBufferView at runtime. TypeScript's DOM
    // declaration does not model the generic Uint8Array used here, so keep
    // the view intact through the boundary instead of copying 200 MiB.
    request.send(encrypted as unknown as ArrayBuffer);
  });
}

export async function downloadEncryptedAttachment(
  session: AccountSession,
  attachmentId: string,
  policy: AttachmentDownloadPolicy,
  signal?: AbortSignal,
): Promise<DownloadedEncryptedAttachment> {
  const validatedAttachmentId = validateAttachmentId(attachmentId);
  const expectedEncryptedBytes = expectedAttachmentCiphertextBytes(policy);
  let claim: string | undefined;
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  let encrypted: Uint8Array | undefined;
  try {
    const response = await fetch(`${session.endpoint.apiBaseUrl}/v1/attachment/${validatedAttachmentId}`, {
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
      headers: { Authorization: `Bearer ${session.token}` },
      signal,
    });
    claim = readAttachmentClaim(response.headers);
    if (!response.ok) throw new Error("Attachment unavailable");
    const contentLength = response.headers.get("content-length");
    const advertisedLength = parseAttachmentContentLength(
      contentLength,
      maxSerializedAttachmentBytes(policy.mediaType),
    );
    if (advertisedLength !== undefined && advertisedLength !== expectedEncryptedBytes) {
      throw new Error("Attachment unavailable");
    }
    encrypted = new Uint8Array(expectedEncryptedBytes);
    reader = response.body?.getReader();
    if (!reader) throw new Error("Attachment unavailable");
    let offset = 0;
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      const chunk = result.value;
      try {
        if (offset > expectedEncryptedBytes - chunk.byteLength) {
          throw new Error("Attachment unavailable");
        }
        encrypted.set(chunk, offset);
        offset += chunk.byteLength;
      } finally {
        chunk.fill(0);
      }
    }
    if (offset !== expectedEncryptedBytes) {
      throw new Error("Attachment unavailable");
    }
    return claim ? { bytes: encrypted, claim } : { bytes: encrypted };
  } catch (error) {
    encrypted?.fill(0);
    if (reader) await reader.cancel().catch(() => undefined);
    if (claim) await releaseAttachmentDownloadClaim(session, validatedAttachmentId, claim).catch(() => undefined);
    throw error;
  } finally {
    reader?.releaseLock();
  }
}

export async function completeAttachmentDownload(
  session: AccountSession,
  attachmentId: string,
  claim: string,
  signal?: AbortSignal,
): Promise<void> {
  const validatedAttachmentId = validateAttachmentId(attachmentId);
  const validatedClaim = validateAttachmentClaim(claim);
  const response = await fetch(
    `${session.endpoint.apiBaseUrl}/v1/attachment/${validatedAttachmentId}/complete`,
    {
      method: "POST",
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
      headers: attachmentClaimHeaders(session, validatedClaim),
      signal,
    },
  );
  if (!response.ok) throw new Error("Attachment unavailable");
}

export async function releaseAttachmentDownloadClaim(
  session: AccountSession,
  attachmentId: string,
  claim: string,
  signal?: AbortSignal,
): Promise<void> {
  const validatedAttachmentId = validateAttachmentId(attachmentId);
  const validatedClaim = validateAttachmentClaim(claim);
  const response = await fetch(
    `${session.endpoint.apiBaseUrl}/v1/attachment/${validatedAttachmentId}/claim`,
    {
      method: "DELETE",
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
      headers: attachmentClaimHeaders(session, validatedClaim),
      signal: signal ?? AbortSignal.timeout(ATTACHMENT_CLEANUP_TIMEOUT_MS),
    },
  );
  if (!response.ok) throw new Error("Attachment unavailable");
}

export async function deleteUploadedAttachment(
  session: AccountSession,
  attachmentId: string,
  signal?: AbortSignal,
): Promise<void> {
  const validatedAttachmentId = validateAttachmentId(attachmentId);
  const response = await fetch(
    `${session.endpoint.apiBaseUrl}/v1/attachment/${validatedAttachmentId}`,
    {
      method: "DELETE",
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
      headers: { Authorization: `Bearer ${session.token}` },
      signal: signal ?? AbortSignal.timeout(ATTACHMENT_CLEANUP_TIMEOUT_MS),
    },
  );
  if (!response.ok && response.status !== 404) throw new Error("Attachment unavailable");
}

export async function decryptAndCompleteAttachment(
  session: AccountSession,
  attachmentId: string,
  downloaded: DownloadedEncryptedAttachment,
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
    if (downloaded.claim) {
      await completeAttachmentDownload(session, attachmentId, downloaded.claim, signal);
      claimCompleted = true;
    }
    signal?.throwIfAborted();
    return plaintext;
  } catch (error) {
    if (plaintext) plaintext.fill(0);
    if (downloaded.claim && !claimCompleted) {
      await releaseAttachmentDownloadClaim(session, attachmentId, downloaded.claim).catch(() => undefined);
    }
    throw error;
  }
}

function validBoundedResponseLength(value: string, maxBytes: number): boolean {
  const normalized = value.trim();
  if (!/^\d+$/u.test(normalized)) return false;
  const length = Number(normalized);
  return Number.isSafeInteger(length) && length > 0 && length <= maxBytes;
}

function readAttachmentClaim(headers: Headers): string | undefined {
  const value = headers.get(ATTACHMENT_CLAIM_HEADER);
  if (value === null) return undefined;
  return validateAttachmentClaim(value);
}

function parseAttachmentContentLength(value: string | null, maxBytes: number): number | undefined {
  if (value === null) return undefined;
  const normalized = value.trim();
  if (!/^\d+$/.test(normalized)) throw new Error("Attachment unavailable");
  const length = Number(normalized);
  if (!Number.isSafeInteger(length) || length <= 0 || length > maxBytes) {
    throw new Error("Attachment unavailable");
  }
  return length;
}

function expectedAttachmentCiphertextBytes(policy: AttachmentDownloadPolicy): number {
  if (policy.mediaType !== "IMAGE" && policy.mediaType !== "VIDEO" && policy.mediaType !== "FILE") {
    throw new Error("Attachment unavailable");
  }
  const maxBytes = maxSerializedAttachmentBytes(policy.mediaType);
  if (!Number.isSafeInteger(policy.expectedPlaintextBytes) ||
    policy.expectedPlaintextBytes <= 0 ||
    policy.expectedPlaintextBytes > maxBytes - ATTACHMENT_BLOB_OVERHEAD_BYTES) {
    throw new Error("Attachment unavailable");
  }
  return policy.expectedPlaintextBytes + ATTACHMENT_BLOB_OVERHEAD_BYTES;
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

async function readBoundedJson(
  response: Response,
  maxBytes: number,
  signal?: AbortSignal,
): Promise<unknown> {
  const reader = response.body?.getReader();
  if (!reader) throw new Error("Wrong information");
  let bytes = new Uint8Array(0);
  let length = 0;
  try {
    signal?.throwIfAborted();
    const declared = parseBoundedContentLength(response.headers.get("content-length"), maxBytes);
    const contentEncoding = response.headers.get("content-encoding")?.trim().toLowerCase();
    const exactDeclaredLength = !contentEncoding || contentEncoding === "identity";
    bytes = new Uint8Array(declared ?? Math.min(4_096, maxBytes));
    while (true) {
      signal?.throwIfAborted();
      const { done, value } = await reader.read();
      if (done) break;
      try {
        const nextLength = length + value.byteLength;
        if (!Number.isSafeInteger(nextLength) || nextLength > maxBytes) {
          throw new Error("Wrong information");
        }
        if (nextLength > bytes.byteLength) {
          const nextCapacity = Math.min(maxBytes, Math.max(nextLength, bytes.byteLength * 2 || 4_096));
          const expanded = new Uint8Array(nextCapacity);
          expanded.set(bytes.subarray(0, length));
          bytes.fill(0);
          bytes = expanded;
        }
        bytes.set(value, length);
        length = nextLength;
      } finally {
        value.fill(0);
      }
    }
    signal?.throwIfAborted();
    if (length === 0 || (exactDeclaredLength && declared !== undefined && declared !== length)) {
      throw new Error("Wrong information");
    }
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, length));
    return JSON.parse(text) as unknown;
  } catch (error) {
    await reader.cancel().catch(() => undefined);
    throw error;
  } finally {
    bytes.fill(0);
    reader.releaseLock();
  }
}

function parseBoundedContentLength(value: string | null, maxBytes: number): number | undefined {
  if (value === null) return undefined;
  const normalized = value.trim();
  if (!/^\d+$/u.test(normalized)) throw new Error("Wrong information");
  const length = Number(normalized);
  if (!Number.isSafeInteger(length) || length <= 0 || length > maxBytes) {
    throw new Error("Wrong information");
  }
  return length;
}

function validOpaqueStartResponse(value: unknown): value is OpaqueAccountStartResponse {
  if (!plainObjectWithKeys(value, [
    "accepted", "mode", "handshake_id", "response_b64", "challenge_b64", "node_id",
    "identity_public_b64", "identity_prekey_id", "identity_envelope_b64", "error",
  ])) return false;
  const payload = value as Record<string, unknown>;
  if (
    payload.accepted !== true ||
    (payload.mode !== "registration" && payload.mode !== "login") ||
    !validUuid(payload.handshake_id) ||
    !validBase64Url(payload.response_b64, 1, MAX_OPAQUE_MESSAGE_BYTES) ||
    !validNodeId(payload.node_id) ||
    !nullish(payload.error)
  ) return false;
  if (payload.mode === "registration") {
    return nullish(payload.identity_public_b64) &&
      nullish(payload.identity_prekey_id) &&
      nullish(payload.identity_envelope_b64) &&
      validBase64Url(payload.challenge_b64, 32, 32);
  }
  return nullish(payload.challenge_b64) &&
    validBase64Url(payload.identity_public_b64, 128, 128) &&
    typeof payload.identity_prekey_id === "string" &&
    /^[A-Za-z0-9_-]{1,32}$/u.test(payload.identity_prekey_id) &&
    validBase64Url(payload.identity_envelope_b64, 1, MAX_IDENTITY_ENVELOPE_BYTES);
}

function validWebSocketTicketResponse(value: unknown): value is {
  ticket: string;
  expires_in_sec: number;
} {
  if (!plainObjectWithKeys(value, ["ticket", "expires_in_sec"])) return false;
  const payload = value as Record<string, unknown>;
  return typeof payload.ticket === "string" &&
    payload.ticket.length === WS_TICKET_LENGTH &&
    validBase64Url(payload.ticket, WS_TICKET_BYTES, WS_TICKET_BYTES) &&
    typeof payload.expires_in_sec === "number" &&
    Number.isInteger(payload.expires_in_sec) &&
    payload.expires_in_sec >= WS_TICKET_MIN_EXPIRY_SEC &&
    payload.expires_in_sec <= WS_TICKET_MAX_EXPIRY_SEC;
}

function validAccountResponse(value: unknown): value is AccountResponse & {
  token: string;
  username: string;
  identity_public_b64: string;
  identity_prekey_id: string;
  identity_envelope_b64: string;
} {
  if (!plainObjectWithKeys(value, [
    "accepted", "created", "token", "node_id", "username", "max_rooms_per_user",
    "session_inactivity_sec", "identity_public_b64", "identity_prekey_id",
    "identity_envelope_b64", "error",
  ])) return false;
  const payload = value as Record<string, unknown>;
  return payload.accepted === true &&
    typeof payload.created === "boolean" &&
    validUuid(payload.token) &&
    validNodeId(payload.node_id) &&
    typeof payload.username === "string" && USERNAME_PATTERN.test(payload.username) &&
    Number.isInteger(payload.max_rooms_per_user) &&
    (payload.max_rooms_per_user as number) >= 1 &&
    (payload.max_rooms_per_user as number) <= 100 &&
    Number.isInteger(payload.session_inactivity_sec) &&
    (payload.session_inactivity_sec as number) >= 60 &&
    (payload.session_inactivity_sec as number) <= 86_400 &&
    validBase64Url(payload.identity_public_b64, 128, 128) &&
    typeof payload.identity_prekey_id === "string" &&
    /^[A-Za-z0-9_-]{1,32}$/u.test(payload.identity_prekey_id) &&
    validBase64Url(payload.identity_envelope_b64, 1, MAX_IDENTITY_ENVELOPE_BYTES) &&
    nullish(payload.error);
}

function plainObjectWithKeys(value: unknown, allowedKeys: readonly string[]): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    return false;
  }
  return Object.keys(value).every((key) => allowedKeys.includes(key)) &&
    allowedKeys.every((key) => Object.prototype.hasOwnProperty.call(value, key));
}

function validUuid(value: unknown): value is string {
  return typeof value === "string" && UUID_V4_PATTERN.test(value);
}

function validNodeId(value: unknown): value is string {
  return typeof value === "string" && NODE_ID_PATTERN.test(value);
}

function validBase64Url(value: unknown, minBytes: number, maxBytes: number): value is string {
  if (
    typeof value !== "string" ||
    !BASE64_URL_PATTERN.test(value) ||
    value.length > Math.ceil(maxBytes / 3) * 4
  ) return false;
  let decoded: Uint8Array | null = null;
  try {
    decoded = base64ToBytes(value);
    // Decoders can accept non-canonical unused bits (and some malformed
    // modulo-four lengths). Re-encoding is the strict, allocation-bounded
    // canonicality check for every security-sensitive response field.
    return decoded.byteLength >= minBytes &&
      decoded.byteLength <= maxBytes &&
      bytesToBase64(decoded) === value;
  } catch {
    return false;
  } finally {
    decoded?.fill(0);
  }
}

function nullish(value: unknown): boolean {
  return value === undefined || value === null;
}

type ParsedRelayFrame =
  | { kind: "frame"; frame: IncomingFrame }
  | { kind: "result"; result: MessageResultFrame | AckResultFrame }
  | { kind: "invalid-result" }
  | { kind: "ignored" };

function parseRelayFrame(text: string): ParsedRelayFrame {
  if (!utf8LengthWithin(text, MAX_RELAY_TEXT_BYTES)) return { kind: "ignored" };
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    return { kind: "ignored" };
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) return { kind: "ignored" };
  const frame = value as Record<string, unknown>;
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
  return parsed ? { kind: "frame", frame: parsed } : { kind: "ignored" };
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
        typeof frame.is_prekey === "boolean"
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

function serializeRelayFrame(frame: object): string | null {
  let serialized: string;
  try {
    serialized = JSON.stringify(frame);
  } catch {
    return null;
  }
  return typeof serialized === "string" && utf8LengthWithin(serialized, MAX_RELAY_TEXT_BYTES)
    ? serialized
    : null;
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

function attachmentClaimHeaders(session: AccountSession, claim: string): Record<string, string> {
  return {
    Authorization: `Bearer ${session.token}`,
    [ATTACHMENT_CLAIM_HEADER]: claim,
  };
}

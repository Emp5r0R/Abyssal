import type {
  AccountResponse,
  AccountSession,
  AttachmentOptions,
  IncomingFrame,
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
const MAX_WS_TICKET_JSON_BYTES = 4 * 1024;
const WS_TICKET_BYTES = 32;
const WS_TICKET_LENGTH = 43;
const WS_TICKET_MIN_EXPIRY_SEC = 1;
const WS_TICKET_MAX_EXPIRY_SEC = 30;
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

export async function revokeSession(session: AccountSession): Promise<void> {
  await fetch(`${session.endpoint.apiBaseUrl}/v1/account/logout`, {
    method: "POST",
    cache: "no-store",
    credentials: "omit",
    referrerPolicy: "no-referrer",
    keepalive: true,
    headers: { Authorization: `Bearer ${session.token}` },
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
  #manualClose = false;
  #reconnectTimer: number | undefined;
  #attempt = 0;
  #connectGeneration = 0;
  #ticketAbort: AbortController | null = null;
  #connecting = false;

  constructor(
    private readonly session: AccountSession,
    private readonly onFrame: (frame: IncomingFrame) => void,
    private readonly onState: (state: "connecting" | "connected" | "disconnected") => void,
  ) {}

  connect(): void {
    if (this.#socket || this.#manualClose || this.#connecting) return;
    const generation = ++this.#connectGeneration;
    const ticketAbort = new AbortController();
    this.#ticketAbort = ticketAbort;
    this.#connecting = true;
    this.onState("connecting");
    void this.openSocketWithTicket(generation, ticketAbort);
  }

  send(frame: object): boolean {
    if (this.#socket?.readyState !== WebSocket.OPEN) return false;
    let serialized: string | undefined;
    try {
      serialized = JSON.stringify(frame);
    } catch {
      return false;
    }
    if (typeof serialized !== "string" || !utf8LengthWithin(serialized, MAX_RELAY_TEXT_BYTES)) {
      return false;
    }
    this.#socket.send(serialized);
    return true;
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
  ): boolean {
    if (
      state.stateSignature.byteLength !== STATE_SIGNATURE_BYTES ||
      ackSignature.byteLength !== STATE_SIGNATURE_BYTES
    ) return false;
    return this.send({
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
    this.#socket?.close(1000, "client disconnect");
    this.#socket = null;
    this.onState("disconnected");
  }

  private scheduleReconnect(): void {
    if (this.#manualClose || this.#socket || this.#connecting || this.#reconnectTimer !== undefined) return;
    const jitter = crypto.getRandomValues(new Uint16Array(1))[0] % 500;
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
      socket.onopen = () => {
        this.#attempt = 0;
        this.onState("connected");
      };
      socket.onmessage = (event) => {
        if (typeof event.data !== "string") return;
        if (!utf8LengthWithin(event.data, MAX_RELAY_TEXT_BYTES)) {
          this.#manualClose = true;
          socket.close(1009, "frame too large");
          return;
        }
        const frame = parseIncomingFrame(event.data);
        if (frame) this.onFrame(frame);
      };
      socket.onerror = () => socket.close();
      socket.onclose = () => {
        this.#socket = null;
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
}

export function uploadEncryptedAttachment(
  session: AccountSession,
  chatId: string,
  mediaType: string,
  encrypted: Uint8Array,
  options: AttachmentOptions,
  onProgress: (progress: UploadProgress) => void,
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
    request.open("POST", `${session.endpoint.apiBaseUrl}/v1/attachment?${query}`);
    request.responseType = "json";
    request.setRequestHeader("Authorization", `Bearer ${session.token}`);
    request.setRequestHeader("Content-Type", "application/octet-stream");
    request.upload.onprogress = (event) => onProgress({ loaded: event.loaded, total: event.total || encrypted.byteLength });
    request.onerror = () => reject(new Error("Upload failed"));
    request.onabort = () => reject(new Error("Upload aborted"));
    request.onload = () => {
      const id = (request.response as { attachment_id?: unknown } | null)?.attachment_id;
      if (request.status < 200 || request.status >= 300 || typeof id !== "string") {
        reject(new Error("Upload rejected"));
      } else {
        try {
          resolve(validateAttachmentId(id));
        } catch {
          reject(new Error("Upload rejected"));
        }
      }
    };
    // XMLHttpRequest accepts ArrayBufferView at runtime. TypeScript's DOM
    // declaration does not model the generic Uint8Array used here, so keep
    // the view intact through the boundary instead of copying 200 MiB.
    request.send(encrypted as unknown as ArrayBuffer);
  });
}

export async function downloadEncryptedAttachment(
  session: AccountSession,
  attachmentId: string,
): Promise<DownloadedEncryptedAttachment> {
  const validatedAttachmentId = validateAttachmentId(attachmentId);
  let claim: string | undefined;
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  let encrypted: Uint8Array | undefined;
  try {
    const response = await fetch(`${session.endpoint.apiBaseUrl}/v1/attachment/${validatedAttachmentId}`, {
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
      headers: { Authorization: `Bearer ${session.token}` },
    });
    claim = readAttachmentClaim(response.headers);
    if (!response.ok) throw new Error("Attachment unavailable");
    const maxBytes = maxSerializedAttachmentBytes("FILE");
    const contentLength = response.headers.get("content-length");
    const advertisedLength = parseAttachmentContentLength(contentLength, maxBytes);
    encrypted = new Uint8Array(advertisedLength);
    reader = response.body?.getReader();
    if (!reader) throw new Error("Attachment unavailable");
    let offset = 0;
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      const chunk = result.value;
      try {
        if (offset > advertisedLength - chunk.byteLength) {
          throw new Error("Attachment unavailable");
        }
        encrypted.set(chunk, offset);
        offset += chunk.byteLength;
      } finally {
        chunk.fill(0);
      }
    }
    if (offset !== advertisedLength) {
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
    },
  );
  if (!response.ok) throw new Error("Attachment unavailable");
}

export async function releaseAttachmentDownloadClaim(
  session: AccountSession,
  attachmentId: string,
  claim: string,
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
    },
  );
  if (!response.ok) throw new Error("Attachment unavailable");
}

export async function deleteUploadedAttachment(
  session: AccountSession,
  attachmentId: string,
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
): Promise<Uint8Array> {
  let plaintext: Uint8Array | undefined;
  let claimCompleted = false;
  try {
    plaintext = await decrypt();
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
      await completeAttachmentDownload(session, attachmentId, downloaded.claim);
      claimCompleted = true;
    }
    return plaintext;
  } catch (error) {
    if (plaintext) plaintext.fill(0);
    if (downloaded.claim && !claimCompleted) {
      await releaseAttachmentDownloadClaim(session, attachmentId, downloaded.claim).catch(() => undefined);
    }
    throw error;
  }
}

function readAttachmentClaim(headers: Headers): string | undefined {
  const value = headers.get(ATTACHMENT_CLAIM_HEADER);
  if (value === null) return undefined;
  return validateAttachmentClaim(value);
}

function parseAttachmentContentLength(value: string | null, maxBytes: number): number {
  const normalized = value?.trim() ?? "";
  if (!/^\d+$/.test(normalized)) throw new Error("Attachment unavailable");
  const length = Number(normalized);
  if (!Number.isSafeInteger(length) || length <= 0 || length > maxBytes) {
    throw new Error("Attachment unavailable");
  }
  return length;
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
    "accepted", "mode", "handshake_id", "response_b64", "node_id",
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
      nullish(payload.identity_envelope_b64);
  }
  return validBase64Url(payload.identity_public_b64, 128, 128) &&
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

function parseIncomingFrame(text: string): IncomingFrame | null {
  if (!utf8LengthWithin(text, MAX_RELAY_TEXT_BYTES)) return null;
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    return null;
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const frame = value as Record<string, unknown>;
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

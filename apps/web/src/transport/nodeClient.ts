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
  type IdentityStateSnapshot,
} from "../security/crypto";

const JSON_HEADERS = { "Content-Type": "application/json" } as const;

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
  const payload = (await response.json().catch(() => null)) as OpaqueAccountStartResponse | null;
  if (
    !response.ok ||
    !payload?.accepted ||
    !payload.handshake_id ||
    !payload.response_b64 ||
    (payload.mode !== "registration" && payload.mode !== "login")
  ) {
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
  const payload = (await response.json().catch(() => null)) as AccountResponse | null;
  if (
    !response.ok ||
    !payload?.accepted ||
    !payload.token ||
    !payload.username ||
    !payload.identity_public_b64 ||
    !payload.identity_prekey_id ||
    !payload.identity_envelope_b64
  ) {
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

export class RelaySocket {
  #socket: WebSocket | null = null;
  #manualClose = false;
  #reconnectTimer: number | undefined;
  #attempt = 0;

  constructor(
    private readonly session: AccountSession,
    private readonly onFrame: (frame: IncomingFrame) => void,
    private readonly onState: (state: "connecting" | "connected" | "disconnected") => void,
  ) {}

  connect(): void {
    if (this.#socket || this.#manualClose) return;
    this.onState("connecting");
    const socket = new WebSocket(`${this.session.endpoint.wsBaseUrl}/v1/ws`, [
      "abyssal-v1",
      `bearer.${this.session.token}`,
    ]);
    this.#socket = socket;
    socket.onopen = () => {
      this.#attempt = 0;
      this.onState("connected");
    };
    socket.onmessage = (event) => {
      if (typeof event.data !== "string") return;
      try {
        this.onFrame(JSON.parse(event.data) as IncomingFrame);
      } catch {
        // Invalid relay frames never reach application state.
      }
    };
    socket.onerror = () => socket.close();
    socket.onclose = () => {
      this.#socket = null;
      this.onState("disconnected");
      if (!this.#manualClose) this.scheduleReconnect();
    };
  }

  send(frame: object): boolean {
    if (this.#socket?.readyState !== WebSocket.OPEN) return false;
    this.#socket.send(JSON.stringify(frame));
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
    usedPrekeyId: string,
  ): boolean {
    return this.send({
      type: "message_ack",
      chat_id: chatId,
      message_id: messageId,
      sender_username: senderUsername,
      state_revision: state.revision,
      identity_envelope_b64: bytesToBase64(state.envelope),
      identity_public_b64: bytesToBase64(state.identityPublicKey),
      prekey_id: state.prekeyId,
      used_prekey_id: usedPrekeyId,
    });
  }

  syncIdentityState(state: IdentityStateSnapshot): boolean {
    return this.send({
      type: "identity_state",
      state_revision: state.revision,
      identity_envelope_b64: bytesToBase64(state.envelope),
      identity_public_b64: bytesToBase64(state.identityPublicKey),
      prekey_id: state.prekeyId,
    });
  }

  close(): void {
    this.#manualClose = true;
    window.clearTimeout(this.#reconnectTimer);
    this.#socket?.close(1000, "client disconnect");
    this.#socket = null;
    this.onState("disconnected");
  }

  private scheduleReconnect(): void {
    const jitter = crypto.getRandomValues(new Uint16Array(1))[0] % 500;
    const delay = Math.min(15_000, 750 * 2 ** Math.min(this.#attempt++, 5)) + jitter;
    this.#reconnectTimer = window.setTimeout(() => this.connect(), delay);
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
        resolve(id);
      }
    };
    request.send(encrypted.slice().buffer);
  });
}

export async function downloadEncryptedAttachment(
  session: AccountSession,
  attachmentId: string,
): Promise<Uint8Array> {
  const response = await fetch(`${session.endpoint.apiBaseUrl}/v1/attachment/${encodeURIComponent(attachmentId)}`, {
    cache: "no-store",
    credentials: "omit",
    referrerPolicy: "no-referrer",
    headers: { Authorization: `Bearer ${session.token}` },
  });
  if (!response.ok) throw new Error("Attachment unavailable");
  return new Uint8Array(await response.arrayBuffer());
}

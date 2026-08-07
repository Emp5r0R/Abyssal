import initWasm, {
  conversationSafetyNumber as rustConversationSafetyNumber,
  opaqueClientFinishLogin,
  opaqueClientFinishRegistration,
  opaqueClientStart,
  WasmE2eeSession,
} from "../generated/abyssal_core/abyssal_core";

const ENCODER = new TextEncoder();
const DECODER = new TextDecoder("utf-8", { fatal: true });
const CHAT_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;
const USERNAME_PATTERN = /^[\x20-\x7e]{1,80}$/;
const MAX_PAYLOAD_BYTES = 220 * 1024 * 1024;

let wasmReady: Promise<unknown> | null = null;

export interface OpaqueStartState {
  registrationState: Uint8Array;
  registrationRequest: Uint8Array;
  loginState: Uint8Array;
  credentialRequest: Uint8Array;
}

export interface OpaqueRegistrationResult {
  registrationUpload: Uint8Array;
  exportKey: Uint8Array;
}

export interface OpaqueLoginResult {
  credentialFinalization: Uint8Array;
  exportKey: Uint8Array;
  sessionKey: Uint8Array;
}

export interface RecipientKey {
  username: string;
  publicKey: Uint8Array;
}

export interface RecipientEnvelope {
  username: string;
  wrappedKey: Uint8Array;
}

export interface EncryptedPayload {
  version: 4;
  messageId: string;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  signature: Uint8Array;
  envelopes: RecipientEnvelope[];
  stateRevision: number;
  identityEnvelope: Uint8Array;
}

export interface IdentityStateSnapshot {
  revision: number;
  envelope: Uint8Array;
}

interface RustOpaqueStart {
  registration_state: number[];
  registration_request: number[];
  login_state: number[];
  credential_request: number[];
}

interface RustRegistrationFinish {
  registration_upload: number[];
  export_key: number[];
}

interface RustLoginFinish {
  credential_finalization: number[];
  export_key: number[];
  session_key: number[];
}

interface RustEncryptedPayload {
  version: number;
  message_id: string;
  nonce: number[];
  ciphertext: number[];
  signature: number[];
  envelopes: Array<{ username: string; wrapped_key: number[] }>;
  state_revision: number;
  identity_envelope: number[];
}

interface RustE2eeDecryption {
  plaintext: number[];
  state_revision: number;
  identity_envelope: number[];
}

export async function initializeCrypto(): Promise<void> {
  wasmReady ??= initWasm();
  await wasmReady;
}

export async function startOpaque(password: string): Promise<OpaqueStartState> {
  await initializeCrypto();
  const passwordBytes = ENCODER.encode(password);
  try {
    const result = parseJson<RustOpaqueStart>(opaqueClientStart(passwordBytes));
    return {
      registrationState: bytes(result.registration_state),
      registrationRequest: bytes(result.registration_request),
      loginState: bytes(result.login_state),
      credentialRequest: bytes(result.credential_request),
    };
  } finally {
    passwordBytes.fill(0);
  }
}

export async function finishOpaqueRegistration(
  password: string,
  state: OpaqueStartState,
  response: Uint8Array,
): Promise<OpaqueRegistrationResult> {
  await initializeCrypto();
  const passwordBytes = ENCODER.encode(password);
  try {
    const result = parseJson<RustRegistrationFinish>(
      opaqueClientFinishRegistration(passwordBytes, state.registrationState, response),
    );
    return {
      registrationUpload: bytes(result.registration_upload),
      exportKey: bytes(result.export_key),
    };
  } finally {
    passwordBytes.fill(0);
    wipeOpaqueStart(state);
  }
}

export async function finishOpaqueLogin(
  password: string,
  state: OpaqueStartState,
  response: Uint8Array,
): Promise<OpaqueLoginResult> {
  await initializeCrypto();
  const passwordBytes = ENCODER.encode(password);
  try {
    const result = parseJson<RustLoginFinish>(
      opaqueClientFinishLogin(passwordBytes, state.loginState, response),
    );
    return {
      credentialFinalization: bytes(result.credential_finalization),
      exportKey: bytes(result.export_key),
      sessionKey: bytes(result.session_key),
    };
  } finally {
    passwordBytes.fill(0);
    wipeOpaqueStart(state);
  }
}

export function identityContext(nodeId: string, code: string): Uint8Array {
  const node = nodeId.trim();
  const credential = code.trim().toUpperCase();
  if (!node || node.length > 128 || !credential || credential.length > 128) {
    throw new Error("Identity unavailable");
  }
  return ENCODER.encode(`ABYSSAL_IDENTITY_V2:${node}:${credential}`);
}

export function conversationSafetyNumber(firstPublicKey: Uint8Array, secondPublicKey: Uint8Array): string {
  return rustConversationSafetyNumber(firstPublicKey, secondPublicKey);
}

export class InMemoryPayloadCipher {
  #session: WasmE2eeSession | null = null;
  #pendingState: IdentityStateSnapshot | null = null;

  createIdentity(exportKey: Uint8Array, context: Uint8Array): {
    publicKey: Uint8Array;
    envelope: Uint8Array;
  } {
    this.clear();
    const session = WasmE2eeSession.create(exportKey);
    this.#session = session;
    return {
      publicKey: session.publicKey(),
      envelope: session.sealIdentity(exportKey, context),
    };
  }

  recoverIdentity(
    exportKey: Uint8Array,
    context: Uint8Array,
    envelope: Uint8Array,
    expectedPublicKey: Uint8Array,
  ): void {
    this.clear();
    this.#session = WasmE2eeSession.recover(exportKey, context, envelope, expectedPublicKey);
  }

  publicKey(): Uint8Array {
    if (!this.#session) throw new Error("Identity unavailable");
    return this.#session.publicKey();
  }

  stateSnapshot(): IdentityStateSnapshot | null {
    if (!this.#pendingState) return null;
    return {
      revision: this.#pendingState.revision,
      envelope: this.#pendingState.envelope.slice(),
    };
  }

  encryptText(
    chatId: string,
    messageId: string,
    senderUsername: string,
    value: string,
    recipients: RecipientKey[],
  ): EncryptedPayload {
    const plain = ENCODER.encode(value);
    try {
      return this.encryptPayload(chatId, messageId, senderUsername, plain, recipients);
    } finally {
      plain.fill(0);
    }
  }

  decryptText(
    chatId: string,
    messageId: string,
    senderUsername: string,
    senderPublicKey: Uint8Array,
    payload: Pick<EncryptedPayload, "nonce" | "ciphertext" | "signature">,
    wrappedKey: Uint8Array,
    recipientUsername: string,
  ): string {
    const plain = this.decryptPayload(
      chatId,
      messageId,
      senderUsername,
      senderPublicKey,
      payload,
      wrappedKey,
      recipientUsername,
    );
    try {
      return DECODER.decode(plain);
    } finally {
      plain.fill(0);
    }
  }

  encryptBytes(
    chatId: string,
    messageId: string,
    senderUsername: string,
    value: Uint8Array,
    recipients: RecipientKey[],
  ): Uint8Array {
    const encrypted = this.encryptPayload(chatId, messageId, senderUsername, value, recipients);
    try {
      return ENCODER.encode(JSON.stringify(serializePayload(encrypted)));
    } finally {
      wipePayloadBytes(encrypted);
    }
  }

  decryptBytes(
    chatId: string,
    senderUsername: string,
    senderPublicKey: Uint8Array,
    serialized: Uint8Array,
    recipientUsername: string,
  ): Uint8Array {
    if (serialized.byteLength <= 0 || serialized.byteLength > MAX_PAYLOAD_BYTES + 64 * 1024) {
      throw new Error("Payload unavailable");
    }
    const parsed = parseJson<ReturnType<typeof serializePayload>>(DECODER.decode(serialized));
    const payload = deserializePayload(parsed);
    const envelope = payload.envelopes.find((item) => item.username === recipientUsername);
    if (!envelope) throw new Error("Payload unavailable");
    return this.decryptPayload(
      chatId,
      payload.messageId,
      senderUsername,
      senderPublicKey,
      payload,
      envelope.wrappedKey,
      recipientUsername,
    );
  }

  clear(): void {
    if (this.#pendingState) wipeBytes(this.#pendingState.envelope);
    this.#pendingState = null;
    this.#session?.free();
    this.#session = null;
  }

  private encryptPayload(
    chatId: string,
    messageId: string,
    senderUsername: string,
    plaintext: Uint8Array,
    recipients: RecipientKey[],
  ): EncryptedPayload {
    if (!this.#session) throw new Error("Payload cipher unavailable");
    normalizeContext(chatId, messageId, senderUsername);
    const seen = new Set<string>();
    const rustRecipients = recipients.map((recipient) => {
      if (
        !USERNAME_PATTERN.test(recipient.username) ||
        recipient.publicKey.byteLength !== 96 ||
        seen.has(recipient.username)
      ) {
        throw new Error("Recipient unavailable");
      }
      seen.add(recipient.username);
      return { username: recipient.username, public_key: [...recipient.publicKey] };
    });
    const result = parseJson<RustEncryptedPayload>(
      this.#session.encrypt(
        chatId,
        messageId,
        senderUsername,
        plaintext,
        JSON.stringify(rustRecipients),
      ),
    );
    if (
      result.version !== 4 ||
      result.message_id !== messageId ||
      !Number.isSafeInteger(result.state_revision) ||
      result.state_revision <= 0
    ) {
      throw new Error("Payload unavailable");
    }
    const identityEnvelope = bytes(result.identity_envelope);
    this.rememberState(result.state_revision, identityEnvelope);
    return {
      version: 4,
      messageId: result.message_id,
      nonce: bytes(result.nonce),
      ciphertext: bytes(result.ciphertext),
      signature: bytes(result.signature),
      envelopes: result.envelopes.map((envelope) => ({
        username: envelope.username,
        wrappedKey: bytes(envelope.wrapped_key),
      })),
      stateRevision: result.state_revision,
      identityEnvelope,
    };
  }

  private decryptPayload(
    chatId: string,
    messageId: string,
    senderUsername: string,
    senderPublicKey: Uint8Array,
    payload: Pick<EncryptedPayload, "nonce" | "ciphertext" | "signature">,
    wrappedKey: Uint8Array,
    recipientUsername: string,
  ): Uint8Array {
    if (!this.#session) throw new Error("Payload cipher unavailable");
    normalizeContext(chatId, messageId, senderUsername);
    const result = parseJson<RustE2eeDecryption>(
      this.#session.decrypt(
        chatId,
        messageId,
        senderUsername,
        senderPublicKey,
        payload.nonce,
        payload.ciphertext,
        payload.signature,
        wrappedKey,
        recipientUsername,
      ),
    );
    if (!Number.isSafeInteger(result.state_revision) || result.state_revision <= 0) {
      throw new Error("Payload unavailable");
    }
    const identityEnvelope = bytes(result.identity_envelope);
    this.rememberState(result.state_revision, identityEnvelope);
    wipeBytes(identityEnvelope);
    return bytes(result.plaintext);
  }

  private rememberState(revision: number, envelope: Uint8Array): void {
    if (this.#pendingState) wipeBytes(this.#pendingState.envelope);
    this.#pendingState = { revision, envelope: envelope.slice() };
  }
}

export function payloadToFrame(payload: EncryptedPayload): Record<string, unknown> {
  return {
    version: payload.version,
    message_id: payload.messageId,
    nonce_b64: bytesToBase64(payload.nonce),
    ciphertext_b64: bytesToBase64(payload.ciphertext),
    signature_b64: bytesToBase64(payload.signature),
    state_revision: payload.stateRevision,
    identity_envelope_b64: bytesToBase64(payload.identityEnvelope),
    envelopes: payload.envelopes.map((envelope) => ({
      recipient_username: envelope.username,
      wrapped_key_b64: bytesToBase64(envelope.wrappedKey),
    })),
  };
}

export function bytesToBase64(bytesValue: Uint8Array): string {
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytesValue.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytesValue.subarray(offset, offset + chunkSize));
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export function base64ToBytes(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) throw new Error("Payload unavailable");
  const standard = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = standard.padEnd(Math.ceil(standard.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

export function wipeBytes(bytesValue: Uint8Array): void {
  bytesValue.fill(0);
}

export function wipeOpaqueStart(state: OpaqueStartState): void {
  state.registrationState.fill(0);
  state.registrationRequest.fill(0);
  state.loginState.fill(0);
  state.credentialRequest.fill(0);
}

function normalizeContext(chatId: string, messageId: string, username: string): void {
  if (!CHAT_ID_PATTERN.test(chatId) || !CHAT_ID_PATTERN.test(messageId) || !USERNAME_PATTERN.test(username)) {
    throw new Error("Payload unavailable");
  }
}

function bytes(value: number[]): Uint8Array {
  if (!Array.isArray(value) || value.some((item) => !Number.isInteger(item) || item < 0 || item > 255)) {
    throw new Error("Payload unavailable");
  }
  return Uint8Array.from(value);
}

function parseJson<T>(value: string): T {
  try {
    return JSON.parse(value) as T;
  } catch {
    throw new Error("Payload unavailable");
  }
}

function serializePayload(payload: EncryptedPayload) {
  return {
    version: payload.version,
    message_id: payload.messageId,
    nonce_b64: bytesToBase64(payload.nonce),
    ciphertext_b64: bytesToBase64(payload.ciphertext),
    signature_b64: bytesToBase64(payload.signature),
    envelopes: payload.envelopes.map((envelope) => ({
      username: envelope.username,
      wrapped_key_b64: bytesToBase64(envelope.wrappedKey),
    })),
  };
}

function deserializePayload(value: ReturnType<typeof serializePayload>): EncryptedPayload {
  if (value.version !== 4 || !CHAT_ID_PATTERN.test(value.message_id) || !Array.isArray(value.envelopes)) {
    throw new Error("Payload unavailable");
  }
  return {
    version: 4,
    messageId: value.message_id,
    nonce: base64ToBytes(value.nonce_b64),
    ciphertext: base64ToBytes(value.ciphertext_b64),
    signature: base64ToBytes(value.signature_b64),
    envelopes: value.envelopes.map((envelope) => ({
      username: envelope.username,
      wrappedKey: base64ToBytes(envelope.wrapped_key_b64),
    })),
    stateRevision: 0,
    identityEnvelope: new Uint8Array(0),
  };
}

function wipePayloadBytes(payload: EncryptedPayload): void {
  payload.nonce.fill(0);
  payload.ciphertext.fill(0);
  payload.signature.fill(0);
  payload.identityEnvelope.fill(0);
  payload.envelopes.forEach((envelope) => envelope.wrappedKey.fill(0));
}

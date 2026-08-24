import initWasm, {
  attachmentEncryptedSize as rustAttachmentEncryptedSize,
  conversationSafetyNumber as rustConversationSafetyNumber,
  conversationVerificationToken as rustConversationVerificationToken,
  decryptAttachment as rustDecryptAttachment,
  decryptAttachmentChunk as rustDecryptAttachmentChunk,
  encryptAttachment as rustEncryptAttachment,
  encryptAttachmentChunk as rustEncryptAttachmentChunk,
  generateAttachmentKey as rustGenerateAttachmentKey,
  opaqueClientFinishLogin,
  opaqueClientFinishRegistration,
  opaqueClientStart,
  WasmE2eeSession,
} from "../generated/abyssal_core/abyssal_core";
import { MlsRoomManager } from "./mls";

const ENCODER = new TextEncoder();
const DECODER = new TextDecoder("utf-8", { fatal: true });
const CHAT_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;
const USERNAME_PATTERN = /^[\x20-\x7e]{1,80}$/;
const CHACHA20_POLY1305_TAG_BYTES = 16;
const PAYLOAD_PADDING_BUCKET_BYTES = 256;
const PAYLOAD_HEADER_BYTES = 5;
const MAX_PAYLOAD_BYTES = 1024 * 1024;
const MAX_PADDED_PAYLOAD_BYTES = Math.ceil(
  (MAX_PAYLOAD_BYTES + PAYLOAD_HEADER_BYTES) / PAYLOAD_PADDING_BUCKET_BYTES,
) * PAYLOAD_PADDING_BUCKET_BYTES;
export const MAX_PAYLOAD_CIPHERTEXT_BYTES = MAX_PADDED_PAYLOAD_BYTES + CHACHA20_POLY1305_TAG_BYTES;
const MAX_ATTACHMENT_PLAINTEXT_BYTES = 200 * 1024 * 1024;
export const IDENTITY_PUBLIC_KEY_BYTES = 608;
export const STATE_SIGNATURE_BYTES = 64;
const PREKEY_ID_PATTERN = /^[A-Za-z0-9_-]{1,32}$/;
export const PROTOCOL_VERSION = 9;
export const ATTACHMENT_CIPHER_VERSION = 2;
export const ATTACHMENT_KEY_BYTES = 32;
export const ATTACHMENT_CHUNK_PLAINTEXT_BYTES = 256 * 1024;
export const ATTACHMENT_CHUNK_RECORD_BYTES = 1 + 4 + 4 + 8 + 24 +
  ATTACHMENT_CHUNK_PLAINTEXT_BYTES + CHACHA20_POLY1305_TAG_BYTES;
const ATTACHMENT_BLOB_MIN_BYTES = ATTACHMENT_CHUNK_RECORD_BYTES;
const MAX_ATTACHMENT_BLOB_BYTES =
  Math.ceil(MAX_ATTACHMENT_PLAINTEXT_BYTES / ATTACHMENT_CHUNK_PLAINTEXT_BYTES) *
  ATTACHMENT_CHUNK_RECORD_BYTES;

let wasmReady: Promise<unknown> | null = null;

export class FatalCipherError extends Error {
  constructor() {
    super("Payload unavailable");
    this.name = "FatalCipherError";
  }
}

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
}

export interface RecipientKey {
  username: string;
  publicKey: Uint8Array;
  prekeyId: string;
}

export interface RecipientEnvelope {
  username: string;
  wrappedKey: Uint8Array;
  prekeyId: string;
  isPrekey: boolean;
  signature: Uint8Array;
}

export interface EncryptedPayload {
  version: number;
  messageId: string;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  envelopes: RecipientEnvelope[];
  stateRevision: number;
  identityEnvelope: Uint8Array;
  identityPublicKey: Uint8Array;
  prekeyId: string;
  stateSignature: Uint8Array;
}

export interface EncryptedAttachment {
  version: number;
  key: Uint8Array;
  blob: Uint8Array;
}

export interface IdentityStateSnapshot {
  revision: number;
  envelope: Uint8Array;
  identityPublicKey: Uint8Array;
  prekeyId: string;
  stateSignature: Uint8Array;
}

/** The generated WASM binding gains this method with protocol v9. Keep the
 * boundary local so the checked-in generated artifact can be regenerated
 * independently without weakening the v9 fail-closed contract. */
interface NativeE2eeSession extends WasmE2eeSession {
  requiresPrekey(peer: string): boolean;
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
}

interface RustAttachmentCiphertext {
  version: number;
  key: number[];
  blob: number[];
}

interface RustEncryptedPayload {
  version: number;
  message_id: string;
  nonce: number[];
  ciphertext: number[];
  envelopes: Array<{
    username: string;
    wrapped_key: number[];
    prekey_id: string;
    is_prekey: boolean;
    signature: number[];
  }>;
  state_revision: number;
  identity_envelope: number[];
  identity_public: number[];
  prekey_id: string;
  state_signature: number[];
}

interface RustE2eeDecryption {
  plaintext: number[];
  state_revision: number;
  identity_envelope: number[];
  identity_public: number[];
  prekey_id: string;
  state_signature: number[];
}

export async function initializeCrypto(): Promise<void> {
  wasmReady ??= initWasm();
  await wasmReady;
}

export async function startOpaque(password: Uint8Array): Promise<OpaqueStartState> {
  await initializeCrypto();
  const result = parseJson<RustOpaqueStart>(opaqueClientStart(password));
  return {
    registrationState: bytes(result.registration_state),
    registrationRequest: bytes(result.registration_request),
    loginState: bytes(result.login_state),
    credentialRequest: bytes(result.credential_request),
  };
}

export async function finishOpaqueRegistration(
  password: Uint8Array,
  state: OpaqueStartState,
  response: Uint8Array,
): Promise<OpaqueRegistrationResult> {
  await initializeCrypto();
  try {
    const result = parseJson<RustRegistrationFinish>(
      opaqueClientFinishRegistration(password, state.registrationState, response),
    );
    return {
      registrationUpload: bytes(result.registration_upload),
      exportKey: bytes(result.export_key),
    };
  } finally {
    wipeOpaqueStart(state);
  }
}

export async function finishOpaqueLogin(
  password: Uint8Array,
  state: OpaqueStartState,
  response: Uint8Array,
): Promise<OpaqueLoginResult> {
  await initializeCrypto();
  try {
    const result = parseJson<RustLoginFinish>(
      opaqueClientFinishLogin(password, state.loginState, response),
    );
    return {
      credentialFinalization: bytes(result.credential_finalization),
      exportKey: bytes(result.export_key),
    };
  } finally {
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
  if (firstPublicKey.byteLength !== IDENTITY_PUBLIC_KEY_BYTES ||
    secondPublicKey.byteLength !== IDENTITY_PUBLIC_KEY_BYTES) {
    throw new Error("Identity unavailable");
  }
  return rustConversationSafetyNumber(firstPublicKey, secondPublicKey);
}

export function conversationVerificationToken(
  nodeId: string,
  chatId: string,
  firstUsername: string,
  firstPublicKey: Uint8Array,
  secondUsername: string,
  secondPublicKey: Uint8Array,
): string {
  if (firstPublicKey.byteLength !== IDENTITY_PUBLIC_KEY_BYTES ||
    secondPublicKey.byteLength !== IDENTITY_PUBLIC_KEY_BYTES) {
    throw new Error("Identity unavailable");
  }
  return rustConversationVerificationToken(
    nodeId,
    chatId,
    firstUsername,
    firstPublicKey,
    secondUsername,
    secondPublicKey,
  );
}

export class InMemoryPayloadCipher {
  #session: WasmE2eeSession | null = null;
  #committedState: IdentityStateSnapshot | null = null;
  #pendingState: IdentityStateSnapshot | null = null;
  #pendingPreviousState: IdentityStateSnapshot | null = null;

  private nativeSession(): NativeE2eeSession {
    const session = this.#session as NativeE2eeSession | null;
    if (!session || typeof session.requiresPrekey !== "function") {
      throw new Error("Identity unavailable");
    }
    return session;
  }

  createIdentity(exportKey: Uint8Array, context: Uint8Array): {
    publicKey: Uint8Array;
    prekeyId: string;
    envelope: Uint8Array;
  } {
    this.clear();
    const session = WasmE2eeSession.create(exportKey);
    const native = session as NativeE2eeSession;
    let publicKey: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let envelope: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let prekeyId: string;
    try {
      publicKey = native.publicKey();
      prekeyId = native.prekeyId();
      if (publicKey.byteLength !== IDENTITY_PUBLIC_KEY_BYTES || !PREKEY_ID_PATTERN.test(prekeyId)) {
        throw new Error("Identity unavailable");
      }
      envelope = native.sealIdentity(exportKey, context);
      this.#session = native;
    } catch (error) {
      wipeBytes(publicKey);
      wipeBytes(envelope);
      try { native.free(); } catch { /* native handle is detached below */ }
      throw error;
    }
    return {
      publicKey,
      prekeyId,
      envelope,
    };
  }

  recoverIdentity(
    exportKey: Uint8Array,
    context: Uint8Array,
    envelope: Uint8Array,
    expectedPublicKey: Uint8Array,
  ): void {
    this.clear();
    if (expectedPublicKey.byteLength !== IDENTITY_PUBLIC_KEY_BYTES) throw new Error("Identity unavailable");
    const session = WasmE2eeSession.recover(exportKey, context, envelope, expectedPublicKey) as NativeE2eeSession;
    let actual: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    try {
      actual = session.publicKey();
      if (actual.byteLength !== IDENTITY_PUBLIC_KEY_BYTES || !constantTimeEqual(actual, expectedPublicKey) ||
        !PREKEY_ID_PATTERN.test(session.prekeyId())) {
        throw new Error("Identity unavailable");
      }
      this.#session = session;
    } catch (error) {
      wipeBytes(actual);
      try { session.free(); } catch { /* native handle is detached below */ }
      throw error;
    } finally {
      wipeBytes(actual);
    }
  }

  publicKey(): Uint8Array {
    if (!this.#session) throw new Error("Identity unavailable");
    const publicKey = this.#session.publicKey();
    if (publicKey.byteLength !== IDENTITY_PUBLIC_KEY_BYTES) {
      wipeBytes(publicKey);
      throw new Error("Identity unavailable");
    }
    return publicKey;
  }

  prekeyId(): string {
    if (!this.#session) throw new Error("Identity unavailable");
    const prekeyId = this.#session.prekeyId();
    if (!PREKEY_ID_PATTERN.test(prekeyId)) throw new Error("Identity unavailable");
    return prekeyId;
  }

  createMlsManager(username: string, nodeId: string): MlsRoomManager {
    const session = this.nativeSession();
    const identity = this.publicKey();
    try {
      return new MlsRoomManager(session, username, nodeId, identity);
    } finally {
      identity.fill(0);
    }
  }

  requiresPrekey(peer: string): boolean {
    if (!USERNAME_PATTERN.test(peer)) throw new Error("Recipient unavailable");
    const required = this.nativeSession().requiresPrekey(peer);
    if (typeof required !== "boolean") throw new Error("Identity unavailable");
    return required;
  }

  stateSnapshot(): IdentityStateSnapshot | null {
    return cloneState(this.#pendingState ?? this.#committedState);
  }

  commitOutbound(messageId: string, revision: number): void {
    const session = this.#session;
    const pending = this.#pendingState;
    if (!session || !pending || pending.revision !== revision) throw new Error("Identity unavailable");
    session.commitOutbound(messageId, toRevisionBigInt(revision));
    wipeState(this.#pendingPreviousState);
    this.#pendingPreviousState = null;
    wipeState(this.#committedState);
    this.#committedState = pending;
    this.#pendingState = null;
  }

  rollbackOutbound(messageId: string, revision: number): void {
    const session = this.#session;
    const pending = this.#pendingState;
    if (!session || !pending || pending.revision !== revision) throw new Error("Identity unavailable");
    session.rollbackOutbound(messageId, toRevisionBigInt(revision));
    wipeState(this.#pendingState);
    this.#pendingState = null;
    wipeState(this.#committedState);
    this.#committedState = this.#pendingPreviousState;
    this.#pendingPreviousState = null;
  }

  signAcknowledgement(
    chatId: string,
    messageId: string,
    originalSenderUsername: string,
    usedPrekeyId: string,
  ): Uint8Array {
    if (!this.#session) throw new Error("Identity unavailable");
    const signature = this.#session.signAcknowledgement(
      chatId,
      messageId,
      originalSenderUsername,
      usedPrekeyId,
    );
    if (signature.byteLength !== STATE_SIGNATURE_BYTES) {
      signature.fill(0);
      throw new Error("Payload unavailable");
    }
    return signature;
  }

  signRegistrationIdentityProof(
    nodeId: string,
    handshakeId: string,
    challenge: Uint8Array,
    registrationUpload: Uint8Array,
    identityPublic: Uint8Array,
    prekeyId: string,
    identityEnvelope: Uint8Array,
  ): Uint8Array {
    if (!this.#session) throw new Error("Identity unavailable");
    const signature = this.#session.signRegistrationIdentityProof(
      nodeId,
      handshakeId,
      challenge,
      registrationUpload,
      identityPublic,
      prekeyId,
      identityEnvelope,
    );
    if (signature.byteLength !== STATE_SIGNATURE_BYTES) {
      signature.fill(0);
      throw new Error("Identity proof rejected");
    }
    return signature;
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
    payload: Pick<EncryptedPayload, "version" | "identityPublicKey" | "nonce" | "ciphertext">,
    signature: Uint8Array,
    wrappedKey: Uint8Array,
    recipientPrekeyId: string,
    isPrekey: boolean,
    recipientUsername: string,
  ): string {
    const plain = this.decryptPayload(
      chatId,
      messageId,
      senderUsername,
      senderPublicKey,
      payload,
      signature,
      wrappedKey,
      recipientPrekeyId,
      isPrekey,
      recipientUsername,
    );
    try {
      return DECODER.decode(plain);
    } catch {
      // Native decryption has already advanced the ratchet by this point. A
      // plaintext wrapper failure therefore cannot be treated as a dropped
      // ciphertext: discard the identity before exposing another operation.
      this.throwFatalCipherError();
    } finally {
      plain.fill(0);
    }
  }

  encryptAttachment(
    chatId: string,
    messageId: string,
    senderUsername: string,
    mediaType: string,
    value: Uint8Array,
  ): EncryptedAttachment {
    if (!this.#session) throw new Error("Payload cipher unavailable");
    const result = parseJson<RustAttachmentCiphertext>(
      rustEncryptAttachment(chatId, messageId, senderUsername, mediaType, value),
    );
    const key = bytes(result.key);
    const blob = bytes(result.blob);
    if (
      result.version !== ATTACHMENT_CIPHER_VERSION ||
      key.byteLength !== ATTACHMENT_KEY_BYTES ||
      blob.byteLength < ATTACHMENT_BLOB_MIN_BYTES ||
      blob.byteLength > MAX_ATTACHMENT_BLOB_BYTES ||
      blob[0] !== ATTACHMENT_CIPHER_VERSION
    ) {
      key.fill(0);
      blob.fill(0);
      throw new Error("Payload unavailable");
    }
    return { version: result.version, key, blob };
  }

  generateAttachmentKey(): Uint8Array {
    if (!this.#session) throw new Error("Payload cipher unavailable");
    const key = rustGenerateAttachmentKey();
    if (key.byteLength !== ATTACHMENT_KEY_BYTES) {
      key.fill(0);
      throw new Error("Payload unavailable");
    }
    return key;
  }

  attachmentEncryptedSize(mediaType: string, plaintextBytes: number): number {
    if (!this.#session || !Number.isSafeInteger(plaintextBytes) || plaintextBytes <= 0) {
      throw new Error("Payload unavailable");
    }
    const size = rustAttachmentEncryptedSize(mediaType, BigInt(plaintextBytes));
    const result = Number(size);
    if (!Number.isSafeInteger(result) || result < ATTACHMENT_CHUNK_RECORD_BYTES) {
      throw new Error("Payload unavailable");
    }
    return result;
  }

  encryptAttachmentChunk(
    chatId: string,
    messageId: string,
    senderUsername: string,
    mediaType: string,
    key: Uint8Array,
    totalPlaintextBytes: number,
    chunkIndex: number,
    plaintext: Uint8Array,
  ): Uint8Array {
    if (!this.#session || key.byteLength !== ATTACHMENT_KEY_BYTES) {
      throw new Error("Payload unavailable");
    }
    const record = rustEncryptAttachmentChunk(
      chatId,
      messageId,
      senderUsername,
      mediaType,
      key,
      BigInt(totalPlaintextBytes),
      chunkIndex,
      plaintext,
    );
    if (record.byteLength !== ATTACHMENT_CHUNK_RECORD_BYTES ||
      record[0] !== ATTACHMENT_CIPHER_VERSION) {
      record.fill(0);
      throw new Error("Payload unavailable");
    }
    return record;
  }

  decryptAttachmentChunk(
    chatId: string,
    messageId: string,
    senderUsername: string,
    mediaType: string,
    key: Uint8Array,
    totalPlaintextBytes: number,
    chunkIndex: number,
    record: Uint8Array,
  ): Uint8Array {
    if (!this.#session || key.byteLength !== ATTACHMENT_KEY_BYTES ||
      record.byteLength !== ATTACHMENT_CHUNK_RECORD_BYTES) {
      throw new Error("Payload unavailable");
    }
    return rustDecryptAttachmentChunk(
      chatId,
      messageId,
      senderUsername,
      mediaType,
      key,
      BigInt(totalPlaintextBytes),
      chunkIndex,
      record,
    );
  }

  decryptAttachment(
    chatId: string,
    messageId: string,
    senderUsername: string,
    mediaType: string,
    key: Uint8Array,
    blob: Uint8Array,
  ): Uint8Array {
    if (
      !this.#session ||
      key.byteLength !== ATTACHMENT_KEY_BYTES ||
      blob.byteLength < ATTACHMENT_BLOB_MIN_BYTES ||
      blob.byteLength > MAX_ATTACHMENT_BLOB_BYTES ||
      blob[0] !== ATTACHMENT_CIPHER_VERSION
    ) {
      throw new Error("Payload unavailable");
    }
    return rustDecryptAttachment(chatId, messageId, senderUsername, mediaType, key, blob);
  }

  clear(): void {
    wipeState(this.#committedState);
    wipeState(this.#pendingState);
    wipeState(this.#pendingPreviousState);
    this.#committedState = null;
    this.#pendingState = null;
    this.#pendingPreviousState = null;
    const session = this.#session;
    this.#session = null;
    try {
      session?.free();
    } catch {
      // The native handle is detached above, so a cleanup failure cannot
      // leave this cipher reusable with partially released state.
    }
  }

  private encryptPayload(
    chatId: string,
    messageId: string,
    senderUsername: string,
    plaintext: Uint8Array,
    recipients: RecipientKey[],
  ): EncryptedPayload {
    if (!this.#session) throw new Error("Payload cipher unavailable");
    if (this.#pendingState) throw new Error("Identity unavailable");
    normalizeContext(chatId, messageId, senderUsername);
    const seen = new Set<string>();
    const rustRecipients: Array<{ username: string; public_key: number[]; prekey_id: string }> = [];
    try {
      recipients.forEach((recipient) => {
        if (
          !USERNAME_PATTERN.test(recipient.username) ||
          recipient.publicKey.byteLength !== IDENTITY_PUBLIC_KEY_BYTES ||
          !PREKEY_ID_PATTERN.test(recipient.prekeyId) ||
          seen.has(recipient.username)
        ) {
          throw new Error("Recipient unavailable");
        }
        seen.add(recipient.username);
        rustRecipients.push({
          username: recipient.username,
          public_key: [...recipient.publicKey],
          prekey_id: recipient.prekeyId,
        });
      });
      if (rustRecipients.length === 0) throw new Error("Recipient unavailable");
    } catch {
      rustRecipients.forEach((recipient) => recipient.public_key.fill(0));
      throw new Error("Recipient unavailable");
    }

    const session = this.#session;
    let rawResult: string;
    try {
      rawResult = session.encrypt(
        chatId,
        messageId,
        senderUsername,
        plaintext,
        JSON.stringify(rustRecipients),
      );
    } catch {
      wipeState(this.#pendingPreviousState);
      this.#pendingPreviousState = null;
      throw new Error("Payload unavailable");
    } finally {
      rustRecipients.forEach((recipient) => recipient.public_key.fill(0));
    }

    let result: RustEncryptedPayload;
    try {
      result = parseJson<RustEncryptedPayload>(rawResult);
    } catch {
      this.clear();
      throw new FatalCipherError();
    }
    let identityEnvelope: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let identityPublicKey: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let stateSignature: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let nonce: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let ciphertext: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    const envelopes: RecipientEnvelope[] = [];
    try {
      if (
        result.version !== PROTOCOL_VERSION ||
        result.message_id !== messageId ||
        !Number.isSafeInteger(result.state_revision) ||
        result.state_revision <= 0 ||
        !Array.isArray(result.envelopes)
      ) throw new Error("Payload unavailable");
      identityEnvelope = bytes(result.identity_envelope);
      identityPublicKey = bytes(result.identity_public);
      stateSignature = bytes(result.state_signature);
      if (
        identityPublicKey.byteLength !== IDENTITY_PUBLIC_KEY_BYTES ||
        stateSignature.byteLength !== STATE_SIGNATURE_BYTES ||
        !PREKEY_ID_PATTERN.test(result.prekey_id)
      ) throw new Error("Payload unavailable");
      nonce = bytes(result.nonce);
      ciphertext = bytes(result.ciphertext);
      if (nonce.byteLength !== 12 || !validPayloadCiphertext(ciphertext)) {
        throw new Error("Payload unavailable");
      }
      result.envelopes.forEach((envelope) => {
        if (
          typeof envelope.username !== "string" ||
          typeof envelope.prekey_id !== "string" ||
          typeof envelope.is_prekey !== "boolean" ||
          !USERNAME_PATTERN.test(envelope.username) ||
          (envelope.is_prekey
            ? !PREKEY_ID_PATTERN.test(envelope.prekey_id)
            : envelope.prekey_id !== "")
        ) throw new Error("Payload unavailable");
        const wrappedKey = bytes(envelope.wrapped_key);
        const signature = bytes(envelope.signature);
        if (wrappedKey.byteLength === 0 || signature.byteLength !== STATE_SIGNATURE_BYTES) {
          wipeBytes(wrappedKey);
          wipeBytes(signature);
          throw new Error("Payload unavailable");
        }
        envelopes.push({
          username: envelope.username,
          wrappedKey,
          prekeyId: envelope.prekey_id,
          isPrekey: envelope.is_prekey,
          signature,
        });
      });
      if (envelopes.length === 0) throw new Error("Payload unavailable");
      const payload: EncryptedPayload = {
        version: PROTOCOL_VERSION,
        messageId: result.message_id,
        nonce,
        ciphertext,
        envelopes,
        stateRevision: result.state_revision,
        identityEnvelope,
        identityPublicKey,
        prekeyId: result.prekey_id,
        stateSignature,
      };
      this.#pendingPreviousState = cloneState(this.#committedState);
      this.rememberPendingState(
        result.state_revision,
        identityEnvelope,
        identityPublicKey,
        result.prekey_id,
        stateSignature,
      );
      return payload;
    } catch {
      wipeBytes(identityEnvelope);
      wipeBytes(identityPublicKey);
      wipeBytes(stateSignature);
      wipeBytes(nonce);
      wipeBytes(ciphertext);
      envelopes.forEach((envelope) => {
        wipeBytes(envelope.wrappedKey);
        wipeBytes(envelope.signature);
      });
      wipeState(this.#pendingState);
      wipeState(this.#pendingPreviousState);
      this.#pendingState = null;
      this.#pendingPreviousState = null;
      const revision = outboundRevision(result);
      if (revision === null || !rollbackCoreAfterFailedOutbound(session, messageId, revision)) {
        this.clear();
        throw new FatalCipherError();
      }
      throw new Error("Payload unavailable");
    }
  }

  private decryptPayload(
    chatId: string,
    messageId: string,
    senderUsername: string,
    senderPublicKey: Uint8Array,
    payload: Pick<EncryptedPayload, "version" | "identityPublicKey" | "nonce" | "ciphertext">,
    signature: Uint8Array,
    wrappedKey: Uint8Array,
    recipientPrekeyId: string,
    isPrekey: boolean,
    recipientUsername: string,
  ): Uint8Array {
    if (!this.#session || senderPublicKey.byteLength !== IDENTITY_PUBLIC_KEY_BYTES ||
      payload.version !== PROTOCOL_VERSION || payload.identityPublicKey.byteLength !== IDENTITY_PUBLIC_KEY_BYTES ||
      payload.nonce.byteLength !== 12 || !validPayloadCiphertext(payload.ciphertext)) {
      throw new Error("Payload unavailable");
    }
    normalizeContext(chatId, messageId, senderUsername);
    const session = this.#session;
    let rawResult: string;
    try {
      rawResult = session.decrypt(
        chatId,
        messageId,
        senderUsername,
        senderPublicKey,
        payload.version,
        payload.identityPublicKey,
        payload.nonce,
        payload.ciphertext,
        signature,
        wrappedKey,
        recipientPrekeyId,
        isPrekey,
        recipientUsername,
      );
    } catch {
      // Authentication/decryption failures happen before the native wrapper
      // returns a state transition. Keep this identity usable so callers can
      // drop the malformed or unauthenticated frame normally.
      throw new Error("Payload unavailable");
    }

    let identityEnvelope: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let identityPublicKey: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let stateSignature: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let plaintext: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    try {
      const result = parseJson<RustE2eeDecryption>(rawResult);
      if (!Number.isSafeInteger(result.state_revision) || result.state_revision <= 0) {
        throw new Error("Payload unavailable");
      }
      identityEnvelope = bytes(result.identity_envelope);
      identityPublicKey = bytes(result.identity_public);
      stateSignature = bytes(result.state_signature);
      if (
        identityPublicKey.byteLength !== IDENTITY_PUBLIC_KEY_BYTES ||
        stateSignature.byteLength !== STATE_SIGNATURE_BYTES ||
        !PREKEY_ID_PATTERN.test(result.prekey_id)
      ) {
        throw new Error("Payload unavailable");
      }
      plaintext = bytes(result.plaintext);
      this.rememberCommittedState(
        result.state_revision,
        identityEnvelope,
        identityPublicKey,
        result.prekey_id,
        stateSignature,
      );
      wipeBytes(identityEnvelope);
      identityPublicKey.fill(0);
      stateSignature.fill(0);
      return plaintext;
    } catch {
      wipeBytes(identityEnvelope);
      wipeBytes(identityPublicKey);
      wipeBytes(stateSignature);
      wipeBytes(plaintext);
      this.throwFatalCipherError();
    }
  }

  private throwFatalCipherError(): never {
    try {
      this.clear();
    } catch {
      // Detach/wipe as much state as clear() can reach, then preserve the
      // fail-closed contract even if native cleanup itself reports an error.
    }
    throw new FatalCipherError();
  }

  private rememberPendingState(
    revision: number,
    envelope: Uint8Array,
    identityPublicKey: Uint8Array,
    prekeyId: string,
    stateSignature: Uint8Array,
  ): void {
    wipeState(this.#pendingState);
    this.#pendingState = {
      revision,
      envelope: envelope.slice(),
      identityPublicKey: identityPublicKey.slice(),
      prekeyId,
      stateSignature: stateSignature.slice(),
    };
  }

  private rememberCommittedState(
    revision: number,
    envelope: Uint8Array,
    identityPublicKey: Uint8Array,
    prekeyId: string,
    stateSignature: Uint8Array,
  ): void {
    wipeState(this.#committedState);
    wipeState(this.#pendingState);
    wipeState(this.#pendingPreviousState);
    this.#pendingState = null;
    this.#pendingPreviousState = null;
    this.#committedState = {
      revision,
      envelope: envelope.slice(),
      identityPublicKey: identityPublicKey.slice(),
      prekeyId,
      stateSignature: stateSignature.slice(),
    };
  }
}

export function base64NoPaddingLength(rawBytes: number): number {
  if (!Number.isSafeInteger(rawBytes) || rawBytes < 0) throw new Error("Payload unavailable");
  const groups = Math.floor(rawBytes / 3);
  return groups * 4 + (rawBytes % 3 === 0 ? 0 : rawBytes % 3 === 1 ? 2 : 3);
}

export function maxSerializedAttachmentBytes(mediaType: string): number {
  const plainLimit = mediaType.toUpperCase() === "IMAGE"
    ? 20 * 1024 * 1024
    : mediaType.toUpperCase() === "VIDEO"
      ? 100 * 1024 * 1024
      : MAX_ATTACHMENT_PLAINTEXT_BYTES;
  return Math.ceil(plainLimit / ATTACHMENT_CHUNK_PLAINTEXT_BYTES) *
    ATTACHMENT_CHUNK_RECORD_BYTES;
}

export function serializedAttachmentBytes(plaintextBytes: number): number {
  if (!Number.isSafeInteger(plaintextBytes) || plaintextBytes <= 0 ||
    plaintextBytes > MAX_ATTACHMENT_PLAINTEXT_BYTES) {
    throw new Error("Attachment unavailable");
  }
  return Math.ceil(plaintextBytes / ATTACHMENT_CHUNK_PLAINTEXT_BYTES) *
    ATTACHMENT_CHUNK_RECORD_BYTES;
}

export function payloadToFrame(payload: EncryptedPayload): Record<string, unknown> {
  if (
    payload.version !== PROTOCOL_VERSION ||
    !CHAT_ID_PATTERN.test(payload.messageId) ||
    payload.nonce.byteLength !== 12 ||
    !validPayloadCiphertext(payload.ciphertext) ||
    payload.identityPublicKey.byteLength !== IDENTITY_PUBLIC_KEY_BYTES ||
    !PREKEY_ID_PATTERN.test(payload.prekeyId) ||
    payload.stateSignature.byteLength !== STATE_SIGNATURE_BYTES
  ) {
    throw new Error("Payload unavailable");
  }
  if (payload.envelopes.length === 0 || payload.envelopes.some((envelope) =>
    !USERNAME_PATTERN.test(envelope.username) || envelope.wrappedKey.byteLength === 0 ||
    envelope.signature.byteLength !== STATE_SIGNATURE_BYTES ||
    (envelope.isPrekey ? !PREKEY_ID_PATTERN.test(envelope.prekeyId) : envelope.prekeyId !== ""))) {
    throw new Error("Payload unavailable");
  }
  return {
    version: payload.version,
    message_id: payload.messageId,
    nonce_b64: bytesToBase64(payload.nonce),
    ciphertext_b64: bytesToBase64(payload.ciphertext),
    state_revision: payload.stateRevision,
    identity_envelope_b64: bytesToBase64(payload.identityEnvelope),
    identity_public_b64: bytesToBase64(payload.identityPublicKey),
    prekey_id: payload.prekeyId,
    state_signature_b64: bytesToBase64(payload.stateSignature),
    envelopes: payload.envelopes.map((envelope) => ({
      recipient_username: envelope.username,
      wrapped_key_b64: bytesToBase64(envelope.wrappedKey),
      prekey_id: envelope.prekeyId,
      is_prekey: envelope.isPrekey,
      signature_b64: bytesToBase64(envelope.signature),
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

function cloneState(state: IdentityStateSnapshot | null): IdentityStateSnapshot | null {
  if (!state) return null;
  return {
    revision: state.revision,
    envelope: state.envelope.slice(),
    identityPublicKey: state.identityPublicKey.slice(),
    prekeyId: state.prekeyId,
    stateSignature: state.stateSignature.slice(),
  };
}

function wipeState(state: IdentityStateSnapshot | null): void {
  if (!state) return;
  wipeBytes(state.envelope);
  wipeBytes(state.identityPublicKey);
  wipeBytes(state.stateSignature);
}

function toRevisionBigInt(revision: number): bigint {
  if (!Number.isSafeInteger(revision) || revision <= 0) throw new Error("Identity unavailable");
  return BigInt(revision);
}

function validPayloadCiphertext(ciphertext: Uint8Array): boolean {
  return ciphertext.byteLength >= PAYLOAD_PADDING_BUCKET_BYTES + CHACHA20_POLY1305_TAG_BYTES &&
    ciphertext.byteLength <= MAX_PAYLOAD_CIPHERTEXT_BYTES &&
    (ciphertext.byteLength - CHACHA20_POLY1305_TAG_BYTES) % PAYLOAD_PADDING_BUCKET_BYTES === 0;
}

function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

function rollbackCoreAfterFailedOutbound(
  session: WasmE2eeSession,
  messageId: string,
  revision: number,
): boolean {
  try {
    if (Number.isSafeInteger(revision) && revision > 0) {
      session.rollbackOutbound(messageId, BigInt(revision));
      return true;
    }
  } catch {
    return false;
  }
  return false;
}

function outboundRevision(result: unknown): number | null {
  if (typeof result !== "object" || result === null || !("state_revision" in result)) return null;
  const revision = (result as { state_revision: unknown }).state_revision;
  return Number.isSafeInteger(revision) && (revision as number) > 0 ? revision as number : null;
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

export const MESSAGE_TRANSPORT_BUCKETS = [
  4096,
  16_384,
  65_536,
  262_144,
  1_048_576,
] as const;
export const CONTROL_TRANSPORT_BUCKETS = [
  ...MESSAGE_TRANSPORT_BUCKETS,
  4_194_304,
  16_777_216,
  17_825_792,
] as const;
export const LEGACY_RELAY_DOMAIN_MAX_BYTES = 1_048_576;
export const MLS_RELAY_DOMAIN_MAX_BYTES = 16_777_216;
export const CONTROL_TRANSPORT_MAX_BYTES = 17_825_792;

const MAX_BUCKET = MESSAGE_TRANSPORT_BUCKETS.at(-1)!;
const PROTOCOL_VERSION = 9;
const RANDOM_CHUNK_BYTES = 65_536;
const STRING_CHUNK_BYTES = 0x8000;
const FILLER_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const FILLER_PATTERN = /^[A-Za-z0-9_-]*$/u;

const OUTGOING_MESSAGE_KEYS = [
  "type", "chat_id", "version", "message_id", "nonce_b64", "ciphertext_b64",
  "state_revision", "identity_envelope_b64", "identity_public_b64", "prekey_id",
  "state_signature_b64", "envelopes", "directory_node_id", "directory_revision",
  "directory_digest",
] as const;

const INCOMING_MESSAGE_KEYS = [
  "type", "chat_id", "version", "message_id", "nonce_b64", "ciphertext_b64",
  "signature_b64", "wrapped_key_b64", "prekey_id", "is_prekey", "sender_username",
  "sender_public_key_b64", "identity_public_b64", "directory_node_id",
  "directory_revision", "directory_digest", "padding_bucket", "padding",
] as const;

const RECIPIENT_ENVELOPE_KEYS = [
  "recipient_username", "wrapped_key_b64", "prekey_id", "is_prekey", "signature_b64",
] as const;

export function padOutgoingMessageFrame(frame: object): string | null {
  if (!validOutgoingMessageFrame(frame)) return null;
  for (const bucket of MESSAGE_TRANSPORT_BUCKETS) {
    const empty = serializePaddedFrame(frame, bucket, "");
    if (empty === null) return null;
    const emptyBytes = utf8ByteLength(empty, bucket);
    if (emptyBytes === null || emptyBytes > bucket) continue;
    const padding = randomFiller(bucket - emptyBytes);
    if (padding === null) return null;
    const serialized = serializePaddedFrame(frame, bucket, padding);
    if (serialized !== null && utf8ByteLength(serialized, bucket) === bucket) return serialized;
    return null;
  }
  return null;
}

export function padOutgoingControlFrame(
  frame: object,
  domainLimit: number,
): string | null {
  if (!validControlFrame(frame) || !validDomainLimit(domainLimit)) return null;
  const inner = safeSerialize(frame);
  if (inner === null || utf8ByteLength(inner, domainLimit) === null) return null;
  const wireLimit = controlWireLimit(domainLimit);
  for (const bucket of CONTROL_TRANSPORT_BUCKETS) {
    if (bucket > wireLimit) break;
    const empty = serializePaddedFrame(frame, bucket, "");
    if (empty === null) return null;
    const emptyBytes = utf8ByteLength(empty, bucket);
    if (emptyBytes === null || emptyBytes > bucket) continue;
    const padding = randomFiller(bucket - emptyBytes, wireLimit);
    if (padding === null) return null;
    const serialized = serializePaddedFrame(frame, bucket, padding);
    if (serialized !== null && utf8ByteLength(serialized, bucket) === bucket) return serialized;
    return null;
  }
  return null;
}

/**
 * Validates relay message padding and removes transport-only fields in place.
 * Failure never mutates the supplied record.
 */
export function validateAndStripIncomingMessagePadding(
  text: string,
  frame: Record<string, unknown>,
): boolean {
  if (!validIncomingMessageFrame(frame)) return false;
  const bucket = frame.padding_bucket as number;
  const padding = frame.padding as string;
  if (!FILLER_PATTERN.test(padding) || padding.length > MAX_BUCKET) return false;

  const base = withoutPadding(frame);
  let canonicalBucket: number | null = null;
  let emptyBytes = 0;
  for (const candidate of MESSAGE_TRANSPORT_BUCKETS) {
    const empty = serializePaddedFrame(base, candidate, "");
    if (empty === null) return false;
    const bytes = utf8ByteLength(empty, candidate);
    if (bytes !== null && bytes <= candidate) {
      canonicalBucket = candidate;
      emptyBytes = bytes;
      break;
    }
  }
  if (canonicalBucket === null || bucket !== canonicalBucket) return false;
  if (padding.length !== canonicalBucket - emptyBytes) return false;
  if (utf8ByteLength(text, canonicalBucket) !== canonicalBucket) return false;

  const canonical = serializePaddedFrame(base, canonicalBucket, padding);
  if (canonical === null || utf8ByteLength(canonical, canonicalBucket) !== canonicalBucket) {
    return false;
  }
  delete frame.padding_bucket;
  delete frame.padding;
  return true;
}

/**
 * Validates the exact transport suffix on every non-message relay frame and
 * removes it only after the smallest bucket and raw UTF-8 length are proven.
 */
export function validateAndStripIncomingControlPadding(
  text: string,
  frame: Record<string, unknown>,
  domainLimit: number,
): boolean {
  if (!validDomainLimit(domainLimit) || !plainRecord(frame) ||
    typeof frame.type !== "string" || frame.type === "message" ||
    typeof frame.padding_bucket !== "number" ||
    !Number.isSafeInteger(frame.padding_bucket) ||
    typeof frame.padding !== "string") return false;
  const bucket = frame.padding_bucket;
  const padding = frame.padding;
  const wireLimit = controlWireLimit(domainLimit);
  if (!CONTROL_TRANSPORT_BUCKETS.some((candidate) => candidate === bucket) ||
    bucket > wireLimit || padding.length > wireLimit || !FILLER_PATTERN.test(padding)) return false;
  const suffix = controlSuffix(bucket, padding);
  if (!text.endsWith(suffix)) return false;

  const base = withoutPadding(frame);
  const inner = safeSerialize(base);
  if (inner === null || utf8ByteLength(inner, domainLimit) === null) return false;
  let canonicalBucket: number | null = null;
  let emptyBytes = 0;
  for (const candidate of CONTROL_TRANSPORT_BUCKETS) {
    if (candidate > wireLimit) break;
    const empty = serializePaddedFrame(base, candidate, "");
    if (empty === null) return false;
    const bytes = utf8ByteLength(empty, candidate);
    if (bytes !== null && bytes <= candidate) {
      canonicalBucket = candidate;
      emptyBytes = bytes;
      break;
    }
  }
  if (canonicalBucket === null || bucket !== canonicalBucket ||
    padding.length !== canonicalBucket - emptyBytes ||
    utf8ByteLength(text, canonicalBucket) !== canonicalBucket) return false;
  delete frame.padding_bucket;
  delete frame.padding;
  return true;
}

function validOutgoingMessageFrame(value: object): value is Record<string, unknown> {
  if (!plainRecord(value) || !exactKeys(value, OUTGOING_MESSAGE_KEYS)) return false;
  if (!commonMessageFieldsValid(value) ||
    !safePositiveInteger(value.state_revision) ||
    typeof value.identity_envelope_b64 !== "string" ||
    typeof value.identity_public_b64 !== "string" ||
    typeof value.prekey_id !== "string" ||
    typeof value.state_signature_b64 !== "string" ||
    typeof value.directory_node_id !== "string" ||
    !safePositiveInteger(value.directory_revision) ||
    typeof value.directory_digest !== "string" ||
    !Array.isArray(value.envelopes) || value.envelopes.length === 0) return false;
  return value.envelopes.every((envelope) =>
    plainRecord(envelope) &&
    exactKeys(envelope, RECIPIENT_ENVELOPE_KEYS) &&
    typeof envelope.recipient_username === "string" &&
    typeof envelope.wrapped_key_b64 === "string" &&
    typeof envelope.prekey_id === "string" &&
    typeof envelope.is_prekey === "boolean" &&
    typeof envelope.signature_b64 === "string");
}

function validIncomingMessageFrame(value: Record<string, unknown>): boolean {
  return exactKeys(value, INCOMING_MESSAGE_KEYS) &&
    commonMessageFieldsValid(value) &&
    typeof value.signature_b64 === "string" &&
    typeof value.wrapped_key_b64 === "string" &&
    typeof value.prekey_id === "string" &&
    typeof value.is_prekey === "boolean" &&
    typeof value.sender_username === "string" &&
    typeof value.sender_public_key_b64 === "string" &&
    typeof value.identity_public_b64 === "string" &&
    typeof value.directory_node_id === "string" &&
    safePositiveInteger(value.directory_revision) &&
    typeof value.directory_digest === "string" &&
    typeof value.padding_bucket === "number" &&
    MESSAGE_TRANSPORT_BUCKETS.some((bucket) => bucket === value.padding_bucket) &&
    typeof value.padding === "string";
}

function commonMessageFieldsValid(value: Record<string, unknown>): boolean {
  return value.type === "message" &&
    typeof value.chat_id === "string" &&
    value.version === PROTOCOL_VERSION &&
    typeof value.message_id === "string" &&
    typeof value.nonce_b64 === "string" &&
    typeof value.ciphertext_b64 === "string";
}

function safePositiveInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function withoutPadding(frame: Record<string, unknown>): Record<string, unknown> {
  const result = { ...frame };
  delete result.padding_bucket;
  delete result.padding;
  return result;
}

function serializePaddedFrame(
  frame: object,
  bucket: number,
  padding: string,
): string | null {
  try {
    const serialized = JSON.stringify({ ...frame, padding_bucket: bucket, padding });
    return typeof serialized === "string" ? serialized : null;
  } catch {
    return null;
  }
}

function randomFiller(length: number, max: number = MAX_BUCKET): string | null {
  if (!Number.isSafeInteger(length) || length < 0 || length > max) return null;
  const bytes = new Uint8Array(length);
  try {
    for (let offset = 0; offset < bytes.length; offset += RANDOM_CHUNK_BYTES) {
      crypto.getRandomValues(bytes.subarray(offset, Math.min(bytes.length, offset + RANDOM_CHUNK_BYTES)));
    }
    for (let index = 0; index < bytes.length; index += 1) {
      bytes[index] = FILLER_ALPHABET.charCodeAt(bytes[index] & 63);
    }
    let result = "";
    for (let offset = 0; offset < bytes.length; offset += STRING_CHUNK_BYTES) {
      result += String.fromCharCode(...bytes.subarray(offset, offset + STRING_CHUNK_BYTES));
    }
    return result;
  } catch {
    return null;
  } finally {
    bytes.fill(0);
  }
}

function validControlFrame(value: object): value is Record<string, unknown> {
  return plainRecord(value) &&
    typeof value.type === "string" &&
    value.type !== "message" &&
    !Object.hasOwn(value, "padding_bucket") &&
    !Object.hasOwn(value, "padding");
}

function validDomainLimit(value: number): boolean {
  return value === LEGACY_RELAY_DOMAIN_MAX_BYTES || value === MLS_RELAY_DOMAIN_MAX_BYTES;
}

function controlWireLimit(domainLimit: number): number {
  return domainLimit === LEGACY_RELAY_DOMAIN_MAX_BYTES
    ? LEGACY_RELAY_DOMAIN_MAX_BYTES
    : CONTROL_TRANSPORT_MAX_BYTES;
}

function controlSuffix(bucket: number, padding: string): string {
  return `,"padding_bucket":${bucket},"padding":"${padding}"}`;
}

function safeSerialize(value: object): string | null {
  try {
    const serialized = JSON.stringify(value);
    return typeof serialized === "string" ? serialized : null;
  } catch {
    return null;
  }
}

function utf8ByteLength(value: string, limit: number): number | null {
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
    if (bytes > limit) return null;
  }
  return bytes;
}

function exactKeys(
  value: Record<string, unknown>,
  expectedKeys: readonly string[],
): boolean {
  const actual = Object.keys(value);
  const expected = new Set(expectedKeys);
  return actual.length === expected.size && actual.every((key) => expected.has(key));
}

function plainRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

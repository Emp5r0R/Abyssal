import assert from "node:assert/strict";
import { createHash, randomFillSync, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  decryptAttachment,
  encryptAttachment,
  initSync,
  opaqueClientFinishRegistration,
  opaqueClientStart,
  WasmE2eeSession,
} from "../apps/web/src/generated/abyssal_core/abyssal_core.js";

initSync({
  module: readFileSync(new URL(
    "../apps/web/src/generated/abyssal_core/abyssal_core_bg.wasm",
    import.meta.url,
  )),
});

const baseUrl = process.env.ABYSSAL_TEST_BASE_URL;
const aliceCode = process.env.ABYSSAL_TEST_CODE_A;
const bobCode = process.env.ABYSSAL_TEST_CODE_B;
const buildSignatureB64 = process.env.ABYSSAL_TEST_BUILD_SIGNATURE_B64;
assert.ok(baseUrl, "ABYSSAL_TEST_BASE_URL is required");
assert.ok(aliceCode, "ABYSSAL_TEST_CODE_A is required");
assert.ok(bobCode, "ABYSSAL_TEST_CODE_B is required");
assert.match(buildSignatureB64 ?? "", /^[A-Za-z0-9_-]{86}$/);
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const RESULT_TIMEOUT_MS = 5_000;
const MAX_PENDING_RESULT_WAITERS = 256;
const IDENTITY_PUBLIC_BYTES_V9 = 64 + (16 * 32) + 32;
const MAX_DIRECTORY_REVISION = 65_536;
const MAX_DIRECTORY_USERS = 117;
const MAX_DIRECTORY_WAITERS = 4;
const MAX_NODE_ID_BYTES = 128;
const DIRECTORY_DIGEST_BYTES = 32;
const DIRECTORY_TRANSCRIPT_DOMAIN = "ABYSSAL_DIRECTORY_CHECKPOINT_V2";
const USERNAME_PATTERN = /^[A-Za-z0-9_-]{1,80}$/u;
const NODE_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/u;
const PREKEY_ID_PATTERN = /^[A-Za-z0-9_-]{1,32}$/u;
const MESSAGE_TRANSPORT_BUCKETS = [4096, 16_384, 65_536, 262_144, 1_048_576];
const CONTROL_TRANSPORT_BUCKETS = [
  ...MESSAGE_TRANSPORT_BUCKETS,
  4_194_304,
  16_777_216,
  17_825_792,
];
const LEGACY_RELAY_DOMAIN_MAX_BYTES = 1_048_576;
const MLS_RELAY_DOMAIN_MAX_BYTES = 16_777_216;
const CONTROL_TRANSPORT_MAX_BYTES = 17_825_792;
const MESSAGE_PADDING_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const MESSAGE_PADDING_PATTERN = /^[A-Za-z0-9_-]*$/u;
const OUTGOING_MESSAGE_KEYS = [
  "type", "chat_id", "version", "message_id", "nonce_b64", "ciphertext_b64",
  "state_revision", "identity_envelope_b64", "identity_public_b64", "prekey_id",
  "state_signature_b64", "envelopes", "directory_node_id", "directory_revision",
  "directory_digest",
];
const INCOMING_MESSAGE_KEYS = [
  "type", "chat_id", "version", "message_id", "nonce_b64", "ciphertext_b64",
  "signature_b64", "wrapped_key_b64", "prekey_id", "is_prekey", "sender_username",
  "sender_public_key_b64", "identity_public_b64", "directory_node_id",
  "directory_revision", "directory_digest", "padding_bucket", "padding",
];

const encode = (value) => Buffer.from(value).toString("base64url");
const decode = (value) => new Uint8Array(Buffer.from(value, "base64url"));

const pendingResultWaiters = new Map();
const releasedPrekeysAwaitingReuse = new Map();
const directoryTrackers = new WeakMap();
const rawFrameText = new WeakMap();
const mlsTrackers = new WeakMap();

const MLS_PROTOCOL_VERSION = 10;
const MLS_MAX_ROSTER = 117;
const MLS_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/u;
const MLS_USERNAME_PATTERN = /^[A-Za-z0-9_-]{1,80}$/u;

class AmbiguousRelayResult extends Error {}

function exactKeys(value, expected) {
  assert.deepEqual(Object.keys(value).sort(), [...expected].sort());
}

function randomMessagePadding(length) {
  assert.ok(Number.isSafeInteger(length) && length >= 0);
  assert.ok(length <= MESSAGE_TRANSPORT_BUCKETS.at(-1));
  const bytes = Buffer.allocUnsafe(length);
  try {
    randomFillSync(bytes);
    for (let index = 0; index < bytes.length; index += 1) {
      bytes[index] = MESSAGE_PADDING_ALPHABET.charCodeAt(bytes[index] & 63);
    }
    return bytes.toString("ascii");
  } finally {
    bytes.fill(0);
  }
}

function padOutgoingMessageFrame(frame) {
  assert.ok(frame && typeof frame === "object" && !Array.isArray(frame));
  exactKeys(frame, OUTGOING_MESSAGE_KEYS);
  assert.equal(frame.type, "message");
  assert.equal(frame.version, 9);
  for (const bucket of MESSAGE_TRANSPORT_BUCKETS) {
    const empty = JSON.stringify({ ...frame, padding_bucket: bucket, padding: "" });
    const emptyBytes = Buffer.byteLength(empty, "utf8");
    if (emptyBytes > bucket) continue;
    const serialized = JSON.stringify({
      ...frame,
      padding_bucket: bucket,
      padding: randomMessagePadding(bucket - emptyBytes),
    });
    assert.equal(Buffer.byteLength(serialized, "utf8"), bucket);
    assert.equal(JSON.stringify(JSON.parse(serialized)), serialized);
    return serialized;
  }
  throw new Error("encrypted message exceeds the largest transport bucket");
}

function validateIncomingMessagePadding(frame) {
  const raw = rawFrameText.get(frame);
  assert.equal(typeof raw, "string", "raw relay message frame is unavailable");
  exactKeys(frame, INCOMING_MESSAGE_KEYS);
  assert.equal(frame.type, "message");
  assert.equal(frame.version, 9);
  assert.ok(MESSAGE_TRANSPORT_BUCKETS.includes(frame.padding_bucket));
  assert.equal(typeof frame.padding, "string");
  assert.match(frame.padding, MESSAGE_PADDING_PATTERN);

  const { padding_bucket: receivedBucket, padding: receivedPadding, ...base } = frame;
  let canonical;
  let emptyBytes;
  for (const bucket of MESSAGE_TRANSPORT_BUCKETS) {
    const empty = JSON.stringify({ ...base, padding_bucket: bucket, padding: "" });
    const bytes = Buffer.byteLength(empty, "utf8");
    if (bytes <= bucket) {
      canonical = bucket;
      emptyBytes = bytes;
      break;
    }
  }
  assert.equal(receivedBucket, canonical);
  assert.equal(receivedPadding.length, canonical - emptyBytes);
  assert.equal(Buffer.byteLength(raw, "utf8"), canonical);
  assert.equal(raw, JSON.stringify(frame), "relay message JSON must be canonical");
  delete frame.padding_bucket;
  delete frame.padding;
  return canonical;
}

function controlDomainLimit(type) {
  return type.startsWith("mls_")
    ? MLS_RELAY_DOMAIN_MAX_BYTES
    : LEGACY_RELAY_DOMAIN_MAX_BYTES;
}

function controlWireLimit(domainLimit) {
  return domainLimit === LEGACY_RELAY_DOMAIN_MAX_BYTES
    ? LEGACY_RELAY_DOMAIN_MAX_BYTES
    : CONTROL_TRANSPORT_MAX_BYTES;
}

function controlSuffix(bucket, padding) {
  return `,"padding_bucket":${bucket},"padding":"${padding}"}`;
}

function padOutgoingControlFrame(frame) {
  assert.ok(frame && typeof frame === "object" && !Array.isArray(frame));
  assert.equal(typeof frame.type, "string");
  assert.notEqual(frame.type, "message");
  assert.equal("padding_bucket" in frame, false);
  assert.equal("padding" in frame, false);
  const inner = JSON.stringify(frame);
  const domainLimit = controlDomainLimit(frame.type);
  assert.ok(Buffer.byteLength(inner, "utf8") <= domainLimit);
  const prefix = inner.slice(0, -1);
  const wireLimit = controlWireLimit(domainLimit);
  for (const bucket of CONTROL_TRANSPORT_BUCKETS) {
    if (bucket > wireLimit) break;
    const emptyBytes = Buffer.byteLength(prefix, "utf8") + controlSuffix(bucket, "").length;
    if (emptyBytes > bucket) continue;
    const padding = randomControlPadding(bucket - emptyBytes, wireLimit);
    const serialized = prefix + controlSuffix(bucket, padding);
    assert.equal(Buffer.byteLength(serialized, "utf8"), bucket);
    return serialized;
  }
  throw new Error("control frame exceeds transport buckets");
}

function randomControlPadding(length, max) {
  assert.ok(Number.isSafeInteger(length) && length >= 0 && length <= max);
  const bytes = Buffer.allocUnsafe(length);
  try {
    randomFillSync(bytes);
    for (let index = 0; index < bytes.length; index += 1) {
      bytes[index] = MESSAGE_PADDING_ALPHABET.charCodeAt(bytes[index] & 63);
    }
    return bytes.toString("ascii");
  } finally {
    bytes.fill(0);
  }
}

function parseIncomingRelayFrame(raw) {
  const frame = JSON.parse(raw);
  assert.ok(frame && typeof frame === "object" && !Array.isArray(frame));
  assert.equal(typeof frame.type, "string");
  if (frame.type === "message") {
    rawFrameText.set(frame, raw);
    return frame;
  }
  const domainLimit = controlDomainLimit(frame.type);
  const wireLimit = controlWireLimit(domainLimit);
  assert.ok(CONTROL_TRANSPORT_BUCKETS.includes(frame.padding_bucket));
  assert.ok(frame.padding_bucket <= wireLimit);
  assert.equal(typeof frame.padding, "string");
  assert.match(frame.padding, MESSAGE_PADDING_PATTERN);
  const suffix = controlSuffix(frame.padding_bucket, frame.padding);
  assert.ok(raw.endsWith(suffix));
  const { padding_bucket: bucket, padding, ...base } = frame;
  const inner = JSON.stringify(base);
  assert.ok(Buffer.byteLength(inner, "utf8") <= domainLimit);
  const prefix = inner.slice(0, -1);
  const canonical = CONTROL_TRANSPORT_BUCKETS.find((candidate) =>
    candidate <= wireLimit &&
    Buffer.byteLength(prefix, "utf8") + controlSuffix(candidate, "").length <= candidate
  );
  assert.equal(bucket, canonical);
  const emptyBytes = Buffer.byteLength(prefix, "utf8") + controlSuffix(canonical, "").length;
  assert.equal(padding.length, canonical - emptyBytes);
  assert.equal(Buffer.byteLength(raw, "utf8"), canonical);
  delete frame.padding_bucket;
  delete frame.padding;
  return frame;
}

function sendControlFrame(socket, frame) {
  socket.send(padOutgoingControlFrame(frame));
}

function assertCanonicalBytes(value, size, label) {
  assert.equal(typeof value, "string", `${label} must be a string`);
  const bytes = decode(value);
  try {
    assert.equal(bytes.byteLength, size, `${label} must decode to ${size} bytes`);
    assert.equal(encode(bytes), value, `${label} must be canonical base64url`);
  } finally {
    bytes.fill(0);
  }
}

function writeU32(hash, value) {
  const bytes = Buffer.allocUnsafe(4);
  bytes.writeUInt32BE(value, 0);
  hash.update(bytes);
  bytes.fill(0);
}

function writeU64(hash, value) {
  const bytes = Buffer.allocUnsafe(8);
  bytes.writeBigUInt64BE(BigInt(value), 0);
  hash.update(bytes);
  bytes.fill(0);
}

function directoryDigestV2(nodeId, revision, users) {
  const entries = users.map((user) => {
    const identity = decode(user.identity_public_b64);
    try {
      assert.equal(identity.byteLength, IDENTITY_PUBLIC_BYTES_V9);
      assert.equal(encode(identity), user.identity_public_b64);
      return {
        username: user.username,
        identity: identity.slice(0, 64),
      };
    } finally {
      identity.fill(0);
    }
  });
  entries.sort((left, right) => left.username < right.username ? -1 : left.username > right.username ? 1 : 0);
  const hash = createHash("sha256");
  hash.update(DIRECTORY_TRANSCRIPT_DOMAIN);
  writeU32(hash, Buffer.byteLength(nodeId));
  hash.update(nodeId);
  writeU64(hash, revision);
  writeU32(hash, entries.length);
  try {
    for (const entry of entries) {
      writeU32(hash, Buffer.byteLength(entry.username));
      hash.update(entry.username);
      hash.update(entry.identity);
    }
    return encode(hash.digest());
  } finally {
    entries.forEach((entry) => entry.identity.fill(0));
  }
}

function parseDirectoryPresence(frame, expectedNodeId) {
  assert.ok(frame && typeof frame === "object" && !Array.isArray(frame));
  exactKeys(frame, ["type", "users"]);
  assert.equal(frame.type, "presence");
  assert.ok(Array.isArray(frame.users));
  assert.ok(frame.users.length >= 1 && frame.users.length <= MAX_DIRECTORY_USERS);
  const usernames = new Set();
  const first = frame.users[0];
  const users = frame.users;
  for (const user of users) {
    assert.ok(user && typeof user === "object" && !Array.isArray(user));
    exactKeys(user, [
      "connected",
      "directory_digest",
      "directory_node_id",
      "directory_revision",
      "identity_prekey_id",
      "identity_public_b64",
      "username",
    ]);
    assert.match(user.username, USERNAME_PATTERN);
    const usernameKey = user.username.toLowerCase();
    assert.equal(usernames.has(usernameKey), false, "presence usernames must be unique");
    usernames.add(usernameKey);
    assert.equal(typeof user.connected, "boolean");
    assert.match(user.directory_node_id, NODE_ID_PATTERN);
    assert.equal(user.directory_node_id, expectedNodeId);
    assert.ok(Number.isSafeInteger(user.directory_revision));
    assert.ok(user.directory_revision >= 1 && user.directory_revision <= MAX_DIRECTORY_REVISION);
    assertCanonicalBytes(user.directory_digest, DIRECTORY_DIGEST_BYTES, "directory_digest");
    assert.match(user.identity_prekey_id, PREKEY_ID_PATTERN);
    assertCanonicalBytes(user.identity_public_b64, IDENTITY_PUBLIC_BYTES_V9, "identity_public_b64");
    assert.equal(user.directory_node_id, first.directory_node_id);
    assert.equal(user.directory_revision, first.directory_revision);
    assert.equal(user.directory_digest, first.directory_digest);
  }
  assert.equal(directoryDigestV2(first.directory_node_id, first.directory_revision, users), first.directory_digest);
  return {
    directory_node_id: first.directory_node_id,
    directory_revision: first.directory_revision,
    directory_digest: first.directory_digest,
  };
}

function installDirectoryTracker(socket, expectedNodeId) {
  assert.match(expectedNodeId, NODE_ID_PATTERN);
  const tracker = {
    expectedNodeId,
    latest: null,
    error: null,
    waiters: new Set(),
  };
  const fail = (error) => {
    if (!tracker.error) tracker.error = error;
    for (const waiter of tracker.waiters) waiter.reject(tracker.error);
    tracker.waiters.clear();
  };
  const onMessage = (event) => {
    let frame;
    try {
      frame = parseIncomingRelayFrame(String(event.data));
    } catch {
      return;
    }
    if (frame?.type !== "presence") return;
    try {
      const stamp = parseDirectoryPresence(frame, expectedNodeId);
      if (tracker.latest && (
        stamp.directory_node_id !== tracker.latest.directory_node_id ||
        stamp.directory_revision < tracker.latest.directory_revision ||
        (stamp.directory_revision === tracker.latest.directory_revision &&
          stamp.directory_digest !== tracker.latest.directory_digest)
      )) throw new Error("directory presence regressed or conflicted");
      tracker.latest = stamp;
      for (const waiter of tracker.waiters) waiter.resolve({ ...stamp });
      tracker.waiters.clear();
    } catch (error) {
      fail(error instanceof Error ? error : new Error("invalid directory presence"));
    }
  };
  socket.addEventListener("message", onMessage);
  socket.addEventListener("error", () => fail(new Error("directory tracker socket error")));
  socket.addEventListener("close", () => fail(new Error("directory tracker socket closed")));
  directoryTrackers.set(socket, tracker);
}

function installMlsTracker(socket) {
  const tracker = { queue: [], waiters: [], closed: false };
  const fail = (error) => {
    tracker.closed = true;
    for (const waiter of tracker.waiters.splice(0)) waiter.reject(error);
  };
  const onMessage = (event) => {
    let frame;
    try {
      frame = parseIncomingRelayFrame(String(event.data));
    } catch {
      return;
    }
    if (!frame || typeof frame !== "object" || Array.isArray(frame) ||
      typeof frame.type !== "string" || !frame.type.startsWith("mls_")) return;
    rawFrameText.set(frame, String(event.data));
    for (let index = tracker.waiters.length - 1; index >= 0; index -= 1) {
      const waiter = tracker.waiters[index];
      let matched = false;
      try { matched = waiter.predicate(frame); } catch (error) {
        tracker.waiters.splice(index, 1);
        waiter.reject(error instanceof Error ? error : new Error("invalid MLS frame"));
        continue;
      }
      if (matched) {
        tracker.waiters.splice(index, 1);
        waiter.resolve(frame);
        return;
      }
    }
    tracker.queue.push(frame);
    if (tracker.queue.length > 256) tracker.queue.shift();
  };
  socket.addEventListener("message", onMessage);
  socket.addEventListener("error", () => fail(new Error("MLS tracker socket error")));
  socket.addEventListener("close", () => fail(new Error("MLS tracker socket closed")));
  mlsTrackers.set(socket, tracker);
}

function waitForMlsFrame(socket, predicate, timeoutMs = RESULT_TIMEOUT_MS) {
  const tracker = mlsTrackers.get(socket);
  assert.ok(tracker, "MLS tracker must be installed before waiting");
  const queued = tracker.queue.findIndex((frame) => {
    try { return predicate(frame); } catch { return false; }
  });
  if (queued >= 0) return Promise.resolve(tracker.queue.splice(queued, 1)[0]);
  if (tracker.closed) return Promise.reject(new Error("MLS tracker socket closed"));
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      const index = tracker.waiters.indexOf(waiter);
      if (index >= 0) tracker.waiters.splice(index, 1);
      reject(new Error("Expected MLS relay frame timed out"));
    }, timeoutMs);
    const waiter = {
      predicate,
      resolve: (frame) => { clearTimeout(timer); resolve(frame); },
      reject: (error) => { clearTimeout(timer); reject(error); },
    };
    tracker.waiters.push(waiter);
  });
}

function waitForNoMlsFrame(socket, predicate, timeoutMs = 350) {
  const tracker = mlsTrackers.get(socket);
  assert.ok(tracker, "MLS tracker must be installed before waiting");
  const queued = tracker.queue.findIndex((frame) => {
    try { return predicate(frame); } catch { return false; }
  });
  if (queued >= 0) return Promise.reject(new Error("unexpected MLS frame"));
  return new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, timeoutMs);
    const waiter = {
      predicate,
      resolve: (frame) => { clearTimeout(timer); reject(new Error(`unexpected MLS frame ${frame.type}`)); },
      reject: (error) => { clearTimeout(timer); reject(error); },
    };
    tracker.waiters.push(waiter);
  });
}

function waitForSocketClose(socket, timeoutMs = RESULT_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    let sawError = false;
    const cleanup = () => {
      clearTimeout(timer);
      socket.removeEventListener("close", onClose);
      socket.removeEventListener("error", onError);
    };
    const onClose = (event) => {
      cleanup();
      resolve(event);
    };
    // Undici may emit `error` before the subsequent `close` when the peer
    // terminates a rejected frame. The assertion still requires that close.
    const onError = () => { sawError = true; };
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error(`Expected WebSocket close timed out${sawError ? " after error" : ""}`));
    }, timeoutMs);
    socket.addEventListener("close", onClose, { once: true });
    socket.addEventListener("error", onError, { once: true });
  });
}

function waitForDirectoryStamp(socket) {
  const tracker = directoryTrackers.get(socket);
  assert.ok(tracker, "directory tracker must be installed before waiting");
  if (tracker.error) return Promise.reject(tracker.error);
  if (tracker.latest) return Promise.resolve({ ...tracker.latest });
  if (tracker.waiters.size >= MAX_DIRECTORY_WAITERS) {
    return Promise.reject(new Error("directory tracker waiter limit"));
  }
  return new Promise((resolve, reject) => tracker.waiters.add({ resolve, reject }));
}

function latestDirectoryStamp(socket) {
  const tracker = directoryTrackers.get(socket);
  assert.ok(tracker?.latest, "directory stamp unavailable");
  return { ...tracker.latest };
}

function assertDirectoryStamp(value, stamp) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.equal(value.directory_node_id, stamp.directory_node_id);
  assert.equal(value.directory_revision, stamp.directory_revision);
  assert.equal(value.directory_digest, stamp.directory_digest);
}

function installResultWaiter(socket, expectedType, messageId) {
  const key = `${expectedType}:${messageId}`;
  if (pendingResultWaiters.size >= MAX_PENDING_RESULT_WAITERS || pendingResultWaiters.has(key)) {
    throw new Error(`Result waiter limit or duplicate waiter for ${key}`);
  }
  let settled = false;
  let timer;
  let resolvePromise;
  let rejectPromise;
  const cleanup = () => {
    clearTimeout(timer);
    socket.removeEventListener("message", onMessage);
    socket.removeEventListener("error", onError);
    socket.removeEventListener("close", onClose);
    if (pendingResultWaiters.get(key) === waiter) pendingResultWaiters.delete(key);
  };
  const settle = (outcome, error) => {
    if (settled) return;
    settled = true;
    cleanup();
    if (error) rejectPromise(error);
    else resolvePromise(outcome);
  };
  const failAmbiguous = (reason) => {
    const error = new AmbiguousRelayResult(`${expectedType} ${messageId}: ${reason}`);
    settle(undefined, error);
    try {
      socket.close(1002, "ambiguous relay result");
    } catch {
      // The socket is already closed; the result remains ambiguous.
    }
  };
  const onMessage = (event) => {
    let frame;
    try {
      frame = parseIncomingRelayFrame(String(event.data));
    } catch {
      failAmbiguous("malformed result frame");
      return;
    }
    if (!frame || typeof frame !== "object" || Array.isArray(frame)) {
      failAmbiguous("malformed result frame");
      return;
    }
    if (frame.type !== "message_result" && frame.type !== "ack_result") {
      if (typeof frame.type === "string" && frame.type.endsWith("_result")) {
        failAmbiguous(`unknown result type ${frame.type}`);
      }
      return;
    }
    if (frame.type !== expectedType) return;
    const keys = Object.keys(frame).sort().join(",");
    if (
      keys !== "accepted,message_id,type" ||
      typeof frame.message_id !== "string" ||
      typeof frame.accepted !== "boolean"
    ) {
      failAmbiguous("malformed result");
      return;
    }
    if (frame.message_id !== messageId) {
      if (pendingResultWaiters.has(`${frame.type}:${frame.message_id}`)) return;
      failAmbiguous(`unknown message ID ${String(frame.message_id)}`);
      return;
    }
    settle(frame.accepted ? "ACCEPTED" : "REJECTED");
  };
  const onError = () => failAmbiguous("socket error");
  const onClose = () => failAmbiguous("socket disconnected");
  const promise = new Promise((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });
  const waiter = { cancel: () => settle("NOT_SENT") };
  pendingResultWaiters.set(key, waiter);
  timer = setTimeout(() => failAmbiguous("result timeout"), RESULT_TIMEOUT_MS);
  socket.addEventListener("message", onMessage);
  socket.addEventListener("error", onError);
  socket.addEventListener("close", onClose);
  return { promise, cancel: waiter.cancel };
}

async function selfCheckResultWaiterCorrelation() {
  const listeners = new Map();
  const socket = {
    addEventListener(type, listener) {
      const entries = listeners.get(type) ?? new Set();
      entries.add(listener);
      listeners.set(type, entries);
    },
    removeEventListener(type, listener) {
      listeners.get(type)?.delete(listener);
    },
    dispatch(type, event) {
      for (const listener of listeners.get(type) ?? []) listener(event);
    },
    close() {},
  };
  const first = installResultWaiter(socket, "message_result", "self-first");
  const second = installResultWaiter(socket, "message_result", "self-second");
  socket.dispatch("message", {
    data: padOutgoingControlFrame({
      type: "message_result",
      message_id: "self-second",
      accepted: true,
    }),
  });
  assert.equal(await second.promise, "ACCEPTED");
  socket.dispatch("message", {
    data: padOutgoingControlFrame({
      type: "message_result",
      message_id: "self-first",
      accepted: true,
    }),
  });
  assert.equal(await first.promise, "ACCEPTED");
  assert.equal(pendingResultWaiters.size, 0);
}

await selfCheckResultWaiterCorrelation();

function waitForFrame(socket, predicate) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error("Expected relay frame timed out"));
    }, 5_000);
    const cleanup = () => {
      clearTimeout(timeout);
      socket.removeEventListener("message", onMessage);
      socket.removeEventListener("error", onError);
      socket.removeEventListener("close", onClose);
    };
    const onMessage = (event) => {
      const raw = String(event.data);
      let frame;
      try {
        frame = parseIncomingRelayFrame(raw);
      } catch {
        return;
      }
      if (!predicate(frame)) return;
      if (frame && typeof frame === "object" && !Array.isArray(frame)) {
        rawFrameText.set(frame, raw);
      }
      cleanup();
      resolve(frame);
    };
    const onError = () => {
      cleanup();
      reject(new Error("WebSocket failed while waiting for relay frame"));
    };
    const onClose = () => {
      cleanup();
      reject(new Error("WebSocket closed while waiting for relay frame"));
    };
    socket.addEventListener("message", onMessage);
    socket.addEventListener("error", onError);
    socket.addEventListener("close", onClose);
  });
}

async function register(code, password) {
  const passwordBytes = encoder.encode(password);
  let opaque;
  let identity;
  let context = new Uint8Array(0);
  let challenge = new Uint8Array(0);
  let exportKey = new Uint8Array(0);
  let registrationUpload = new Uint8Array(0);
  let identityPublic = new Uint8Array(0);
  let identityEnvelope = new Uint8Array(0);
  let identityProof = new Uint8Array(0);
  let response = new Uint8Array(0);
  let registrationState = new Uint8Array(0);
  let finished;
  let account;
  try {
    opaque = JSON.parse(opaqueClientStart(passwordBytes));
    const startRequest = {
      code,
      registration_request_b64: encode(opaque.registration_request),
      credential_request_b64: encode(opaque.credential_request),
    };
    assert.equal(JSON.stringify(startRequest).includes(password), false);
    const startResponse = await fetch(`${baseUrl}/v2/account/start`, {
      method: "POST",
      cache: "no-store",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(startRequest),
    });
    assert.equal(startResponse.status, 200);
    assert.match(startResponse.headers.get("cache-control") ?? "", /no-store/);
    const start = await startResponse.json();
    assert.equal(start.mode, "registration");
    assert.equal(typeof start.node_id, "string");
    assert.equal(typeof start.handshake_id, "string");
    assert.equal(typeof start.challenge_b64, "string");
    challenge = decode(start.challenge_b64);
    assert.equal(challenge.byteLength, 32);

    response = decode(start.response_b64);
    registrationState = new Uint8Array(opaque.registration_state);
    finished = JSON.parse(opaqueClientFinishRegistration(
      passwordBytes,
      registrationState,
      response,
    ));
    exportKey = new Uint8Array(finished.export_key);
    registrationUpload = new Uint8Array(finished.registration_upload);
    identity = WasmE2eeSession.create(exportKey);
    context = encoder.encode(`ABYSSAL_IDENTITY_V2:${start.node_id}:${code.toUpperCase()}`);
    identityPublic = identity.publicKey();
    assert.equal(identityPublic.byteLength, IDENTITY_PUBLIC_BYTES_V9);
    const identityPrekeyId = identity.prekeyId();
    identityEnvelope = identity.sealIdentity(exportKey, context);
    identityProof = identity.signRegistrationIdentityProof(
      start.node_id,
      start.handshake_id,
      challenge,
      registrationUpload,
      identityPublic,
      identityPrekeyId,
      identityEnvelope,
    );
    assert.equal(identityProof.byteLength, 64);
    const finishBody = {
      handshake_id: start.handshake_id,
      registration_upload_b64: encode(registrationUpload),
      identity_public_b64: encode(identityPublic),
      identity_prekey_id: identityPrekeyId,
      identity_envelope_b64: encode(identityEnvelope),
      identity_proof_b64: encode(identityProof),
    };
    assert.equal(JSON.stringify(finishBody).includes(password), false);
    const finishResponse = await fetch(`${baseUrl}/v2/account/finish`, {
      method: "POST",
      cache: "no-store",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(finishBody),
    });
    assert.equal(finishResponse.status, 200);
    account = await finishResponse.json();
    assert.equal(account.accepted, true);
    assert.ok(account.token);
    assert.ok(account.username);
    assert.equal(account.identity_public_b64, encode(identityPublic));
    assert.equal(account.identity_prekey_id, identityPrekeyId);
    return { ...account, identity };
  } catch (error) {
    identity?.free();
    throw error;
  } finally {
    passwordBytes.fill(0);
    context.fill(0);
    challenge.fill(0);
    response.fill(0);
    registrationState.fill(0);
    exportKey.fill(0);
    registrationUpload.fill(0);
    identityPublic.fill(0);
    identityEnvelope.fill(0);
    identityProof.fill(0);
    finished?.export_key?.fill?.(0);
    finished?.registration_upload?.fill?.(0);
    if (opaque) {
      opaque.registration_state.fill(0);
      opaque.registration_request.fill(0);
      opaque.login_state.fill(0);
      opaque.credential_request.fill(0);
    }
  }
}

async function opaqueStartStatus(code, password) {
  const passwordBytes = encoder.encode(password);
  const opaque = JSON.parse(opaqueClientStart(passwordBytes));
  passwordBytes.fill(0);
  const response = await fetch(`${baseUrl}/v2/account/start`, {
    method: "POST",
    cache: "no-store",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      code,
      registration_request_b64: encode(opaque.registration_request),
      credential_request_b64: encode(opaque.credential_request),
    }),
  });
  opaque.registration_state.fill(0);
  opaque.registration_request.fill(0);
  opaque.login_state.fill(0);
  opaque.credential_request.fill(0);
  return response.status;
}

async function requestWsTicket(account) {
  const response = await fetch(`${baseUrl}/v1/ws-ticket`, {
    method: "POST",
    cache: "no-store",
    credentials: "omit",
    referrerPolicy: "no-referrer",
    headers: {
      authorization: `Bearer ${account.token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      platform: "web",
      version: "2.2.0",
      build_signature_b64: buildSignatureB64,
    }),
  });
  assert.equal(response.status, 200);
  assert.match(response.headers.get("cache-control") ?? "", /no-store/);
  const payload = await response.json();
  assert.deepEqual(Object.keys(payload).sort(), ["expires_in_sec", "ticket"]);
  assert.match(payload.ticket, /^[A-Za-z0-9_-]{43}$/);
  assert.ok(Number.isInteger(payload.expires_in_sec));
  assert.ok(payload.expires_in_sec >= 1 && payload.expires_in_sec <= 30);
  return payload.ticket;
}

async function expectBuildAdmissionRejected(account) {
  const response = await fetch(`${baseUrl}/v1/ws-ticket`, {
    method: "POST",
    cache: "no-store",
    credentials: "omit",
    referrerPolicy: "no-referrer",
    headers: {
      authorization: `Bearer ${account.token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      platform: "web",
      version: "2.0.0",
      build_signature_b64: buildSignatureB64,
    }),
  });
  assert.equal(response.status, 426);
  assert.equal(await response.text(), "");
}

function connectWithTicket(ticket, expectedNodeId) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(
      `${baseUrl.replace(/^http/, "ws")}/v1/ws`,
      ["abyssal-v2", `ticket.${ticket}`],
    );
    const timeout = setTimeout(() => reject(new Error("WebSocket connection timed out")), 5_000);
    socket.addEventListener("open", () => {
      clearTimeout(timeout);
      installDirectoryTracker(socket, expectedNodeId);
      installMlsTracker(socket);
      resolve(socket);
    }, { once: true });
    socket.addEventListener("error", (event) => {
      clearTimeout(timeout);
      const detail = event?.error instanceof Error
        ? event.error.message
        : typeof event?.message === "string" && event.message.length > 0
          ? event.message
          : "unknown upgrade error";
      reject(new Error(`WebSocket connection failed: ${detail}`));
    }, { once: true });
  });
}

async function connect(account) {
  return connectWithTicket(await requestWsTicket(account), account.node_id);
}

function expectWebSocketRejected(protocols) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(
      `${baseUrl.replace(/^http/, "ws")}/v1/ws`,
      protocols,
    );
    const timeout = setTimeout(() => {
      socket.close();
      reject(new Error("Expected WebSocket rejection timed out"));
    }, 5_000);
    let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      socket.removeEventListener("open", onOpen);
      socket.removeEventListener("error", onError);
      socket.removeEventListener("close", onClose);
      if (error) reject(error);
      else resolve();
    };
    const onOpen = () => {
      socket.close();
      finish(new Error("WebSocket unexpectedly accepted"));
    };
    const onError = () => finish();
    const onClose = () => finish();
    socket.addEventListener("open", onOpen, { once: true });
    socket.addEventListener("error", onError, { once: true });
    socket.addEventListener("close", onClose, { once: true });
  });
}

async function requestPrekeyLease(socket, chatId, messageId, recipientUsername) {
  const response = waitForFrame(
    socket,
    (frame) => frame.type === "prekey_lease" &&
      frame.chat_id === chatId &&
      frame.message_id === messageId &&
      frame.recipient_username === recipientUsername,
  );
  sendControlFrame(socket, {
    type: "prekey_lease",
    chat_id: chatId,
    message_id: messageId,
    recipient_username: recipientUsername,
  });
  const lease = await response;
  assert.deepEqual(Object.keys(lease).sort(), [
    "chat_id",
    "expires_at_ms",
    "message_id",
    "prekey_id",
    "recipient_public_key_b64",
    "recipient_username",
    "type",
  ]);
  assert.match(lease.prekey_id, /^[A-Za-z0-9_-]{1,32}$/);
  assert.ok(Number.isSafeInteger(lease.expires_at_ms));
  assert.ok(lease.expires_at_ms > Date.now());
  const releaseKey = `${chatId}:${recipientUsername}`;
  const expectedReleasedPrekey = releasedPrekeysAwaitingReuse.get(releaseKey);
  if (expectedReleasedPrekey !== undefined) {
    assert.equal(lease.prekey_id, expectedReleasedPrekey);
    releasedPrekeysAwaitingReuse.delete(releaseKey);
  }
  const recipientPublic = decode(lease.recipient_public_key_b64);
  assert.equal(recipientPublic.byteLength, IDENTITY_PUBLIC_BYTES_V9);
  return { ...lease, recipientPublic };
}

function releaseUnusedPrekeyLease(socket, lease) {
  sendControlFrame(socket, {
    type: "prekey_lease_release",
    chat_id: lease.chat_id,
    message_id: lease.message_id,
    recipient_username: lease.recipient_username,
    prekey_id: lease.prekey_id,
  });
  releasedPrekeysAwaitingReuse.set(
    `${lease.chat_id}:${lease.recipient_username}`,
    lease.prekey_id,
  );
}

function stageEncryptedFrame(
  sender,
  recipient,
  chatId,
  messageId,
  plaintextText,
  recipientPublic,
  recipientPrekeyId,
  directoryStamp,
) {
  const plaintextPayload = JSON.parse(plaintextText);
  assertDirectoryStamp(plaintextPayload, directoryStamp);
  const plaintext = encoder.encode(plaintextText);
  let payload;
  try {
    payload = JSON.parse(sender.identity.encrypt(
      chatId,
      messageId,
      sender.username,
      plaintext,
      JSON.stringify([{
        username: recipient.username,
        public_key: [...recipientPublic],
        prekey_id: recipientPrekeyId,
      }]),
    ));
  } finally {
    plaintext.fill(0);
    recipientPublic.fill(0);
  }
  assert.equal(payload.message_id, messageId);
  const frame = {
    type: "message",
    chat_id: chatId,
    version: payload.version,
    message_id: payload.message_id,
    nonce_b64: encode(payload.nonce),
    ciphertext_b64: encode(payload.ciphertext),
    state_revision: payload.state_revision,
    identity_envelope_b64: encode(payload.identity_envelope),
    identity_public_b64: encode(payload.identity_public),
    prekey_id: payload.prekey_id,
    state_signature_b64: encode(payload.state_signature),
    directory_node_id: directoryStamp.directory_node_id,
    directory_revision: directoryStamp.directory_revision,
    directory_digest: directoryStamp.directory_digest,
    envelopes: payload.envelopes.map((envelope) => ({
      recipient_username: envelope.username,
      wrapped_key_b64: encode(envelope.wrapped_key),
      prekey_id: envelope.prekey_id,
      is_prekey: envelope.is_prekey,
      signature_b64: encode(envelope.signature),
    })),
  };
  return {
    frame,
    messageId,
    stateRevision: payload.state_revision,
    plaintextPayload,
    wipe: () => {
      for (const field of [
        payload.nonce,
        payload.ciphertext,
        payload.identity_envelope,
        payload.identity_public,
        payload.state_signature,
      ]) field?.fill?.(0);
      for (const envelope of payload.envelopes ?? []) {
        for (const field of [envelope.wrapped_key, envelope.signature]) field?.fill?.(0);
      }
    },
  };
}

async function sendEncryptedMessage(
  sender,
  recipient,
  socket,
  chatId,
  plaintextText,
  directoryStamp,
  options = {},
) {
  const messageId = options.messageId ?? randomUUID();
  const mutate = options.mutate;
  const requiresPrekey = sender.identity.requiresPrekey(recipient.username);
  let lease;
  let recipientPublic;
  let recipientPrekeyId;
  if (requiresPrekey) {
    lease = await requestPrekeyLease(socket, chatId, messageId, recipient.username);
    recipientPublic = lease.recipientPublic;
    recipientPrekeyId = lease.prekey_id;
    const expectedRecipientPublic = recipient.identity.publicKey();
    try {
      assert.deepEqual(recipientPublic, expectedRecipientPublic);
    } finally {
      expectedRecipientPublic.fill(0);
    }
  } else {
    recipientPublic = recipient.identity.publicKey();
    recipientPrekeyId = recipient.identity.prekeyId();
  }
  let staged;
  let waiter;
  try {
    staged = stageEncryptedFrame(
      sender,
      recipient,
      chatId,
      messageId,
      plaintextText,
      recipientPublic,
      recipientPrekeyId,
      directoryStamp,
    );
    assert.equal(staged.frame.envelopes.length, 1);
    assert.equal(staged.frame.envelopes[0].is_prekey, requiresPrekey);
    assert.equal(
      staged.frame.envelopes[0].prekey_id,
      requiresPrekey ? lease.prekey_id : "",
    );
    assertDirectoryStamp(staged.frame, directoryStamp);
    if (mutate) mutate(staged.frame);
    const serialized = padOutgoingMessageFrame(staged.frame);
    assert.equal(serialized.includes(plaintextText), false);
    let outcome = "NOT_SENT";
    try {
      // Install the correlated result sink before handing the frame to the socket.
      waiter = installResultWaiter(socket, "message_result", staged.messageId);
      socket.send(serialized);
      outcome = await waiter.promise;
    } catch (error) {
      if (waiter && !(error instanceof AmbiguousRelayResult)) waiter.cancel();
      if (error instanceof AmbiguousRelayResult) throw error;
      outcome = waiter ? await waiter.promise : "NOT_SENT";
    }
    if (outcome === "ACCEPTED") {
      sender.identity.commitOutbound(staged.messageId, BigInt(staged.stateRevision));
    } else if (outcome === "REJECTED" || outcome === "NOT_SENT") {
      sender.identity.rollbackOutbound(staged.messageId, BigInt(staged.stateRevision));
      if (lease) releaseUnusedPrekeyLease(socket, lease);
    } else {
      throw new AmbiguousRelayResult(`unexpected message result ${outcome}`);
    }
    return outcome;
  } catch (error) {
    if (lease && !staged) releaseUnusedPrekeyLease(socket, lease);
    throw error;
  } finally {
    recipientPublic.fill(0);
    lease?.recipientPublic?.fill?.(0);
    staged?.wipe();
  }
}

function decryptFrame(recipient, frame, directoryStamp) {
  validateIncomingMessagePadding(frame);
  assertDirectoryStamp(frame, directoryStamp);
  const senderPublicKey = decode(frame.sender_public_key_b64);
  const identityPublicInput = decode(frame.identity_public_b64);
  const nonce = decode(frame.nonce_b64);
  const ciphertext = decode(frame.ciphertext_b64);
  const signature = decode(frame.signature_b64);
  const wrappedKey = decode(frame.wrapped_key_b64);
  let decrypted;
  try {
    decrypted = JSON.parse(recipient.identity.decrypt(
      frame.chat_id,
      frame.message_id,
      frame.sender_username,
      senderPublicKey,
      frame.version,
      identityPublicInput,
      nonce,
      ciphertext,
      signature,
      wrappedKey,
      frame.prekey_id,
      frame.is_prekey,
      recipient.username,
    ));
  } finally {
    senderPublicKey.fill(0);
    identityPublicInput.fill(0);
    nonce.fill(0);
    ciphertext.fill(0);
    signature.fill(0);
    wrappedKey.fill(0);
  }
  const plaintext = new Uint8Array(decrypted.plaintext);
  const text = decoder.decode(plaintext);
  plaintext.fill(0);
  decrypted.plaintext.fill?.(0);
  const identityEnvelope = new Uint8Array(decrypted.identity_envelope);
  const identityPublic = new Uint8Array(decrypted.identity_public);
  const stateSignature = new Uint8Array(decrypted.state_signature);
  decrypted.identity_envelope.fill?.(0);
  decrypted.identity_public.fill?.(0);
  decrypted.state_signature.fill?.(0);
  const payload = JSON.parse(text);
  assertDirectoryStamp(payload, directoryStamp);
  return {
    text,
    payload,
    stateRevision: decrypted.state_revision,
    identityEnvelope,
    identityPublic,
    prekeyId: decrypted.prekey_id,
    stateSignature,
  };
}

async function acknowledgeFrame(recipient, socket, frame, decrypted) {
  const ackSignature = recipient.identity.signAcknowledgement(
    frame.chat_id,
    frame.message_id,
    frame.sender_username,
    frame.prekey_id,
  );
  let waiter;
  try {
    const acknowledgement = {
      type: "message_ack",
      chat_id: frame.chat_id,
      message_id: frame.message_id,
      sender_username: frame.sender_username,
      state_revision: decrypted.stateRevision,
      identity_envelope_b64: encode(decrypted.identityEnvelope),
      identity_public_b64: encode(decrypted.identityPublic),
      prekey_id: decrypted.prekeyId,
      state_signature_b64: encode(decrypted.stateSignature),
      ack_signature_b64: encode(ackSignature),
      used_prekey_id: frame.prekey_id,
    };
    exactKeys(acknowledgement, [
      "ack_signature_b64",
      "chat_id",
      "identity_envelope_b64",
      "identity_public_b64",
      "message_id",
      "prekey_id",
      "sender_username",
      "state_revision",
      "state_signature_b64",
      "type",
      "used_prekey_id",
    ]);
    assert.equal("directory_node_id" in acknowledgement, false);
    assert.equal("directory_revision" in acknowledgement, false);
    assert.equal("directory_digest" in acknowledgement, false);
    // The ACK result waiter must exist before the acknowledgement is sent.
    waiter = installResultWaiter(socket, "ack_result", frame.message_id);
    try {
      sendControlFrame(socket, acknowledgement);
    } catch {
      waiter.cancel();
    }
    const outcome = await waiter.promise;
    assert.equal(outcome, "ACCEPTED");
    return outcome;
  } finally {
    ackSignature.fill(0);
    decrypted.identityEnvelope.fill(0);
    decrypted.identityPublic.fill(0);
    decrypted.stateSignature.fill(0);
  }
}

function readMlsRoomInfo(handle) {
  const info = handle.roomInfo();
  let groupId = new Uint8Array(0);
  let membershipDigest = new Uint8Array(0);
  try {
    groupId = info.groupId;
    membershipDigest = info.membershipDigest;
    return {
      roomId: info.roomId,
      groupId,
      epoch: info.epoch,
      memberCount: info.memberCount,
      revision: info.revision,
      membershipDigest,
    };
  } catch (error) {
    groupId.fill(0);
    membershipDigest.fill(0);
    throw error;
  } finally {
    info.free();
  }
}

function readMlsCommit(commit) {
  const result = {
    authenticatedData: commit.authenticatedData,
    commit: commit.commit,
    fromEpoch: commit.fromEpoch,
    fromMembershipDigest: commit.fromMembershipDigest,
    groupId: commit.groupId,
    membershipDigest: commit.membershipDigest,
    messageId: commit.messageId,
    revision: commit.revision,
    rosterJson: commit.rosterJson,
    stateEnvelope: commit.stateEnvelope,
    toEpoch: commit.toEpoch,
    welcome: commit.welcome,
  };
  commit.free();
  return result;
}

function wipeMlsCommit(commit) {
  for (const field of [
    commit.authenticatedData,
    commit.commit,
    commit.fromMembershipDigest,
    commit.groupId,
    commit.membershipDigest,
    commit.stateEnvelope,
    commit.welcome,
  ]) field?.fill?.(0);
}

function mlsRosterJson(roster) {
  const identities = [];
  try {
    for (const member of roster) {
      exactKeys(member, ["username", "stable_identity_b64"]);
      assert.match(member.username, MLS_USERNAME_PATTERN);
      const identity = decode(member.stable_identity_b64);
      assert.equal(identity.byteLength, 64);
      identities.push(identity);
    }
    return JSON.stringify(roster.map((member, index) => ({
      username: member.username,
      stable_identity: [...identities[index]],
    })));
  } finally {
    identities.forEach((identity) => identity.fill(0));
  }
}

function mlsRosterFromNative(rosterJson) {
  const roster = JSON.parse(rosterJson);
  assert.ok(Array.isArray(roster));
  assert.ok(roster.length > 0 && roster.length <= MLS_MAX_ROSTER);
  const seen = new Set();
  return roster.map((member) => {
    assert.ok(member && typeof member === "object" && !Array.isArray(member));
    exactKeys(member, ["username", "stable_identity"]);
    assert.match(member.username, MLS_USERNAME_PATTERN);
    const username = member.username.toLowerCase();
    assert.equal(seen.has(username), false);
    seen.add(username);
    assert.ok(Array.isArray(member.stable_identity));
    assert.equal(member.stable_identity.length, 64);
    assert.ok(member.stable_identity.every((value) => Number.isInteger(value) && value >= 0 && value <= 255));
    const stableIdentity = Uint8Array.from(member.stable_identity);
    try {
      return { username: member.username, stable_identity_b64: encode(stableIdentity) };
    } finally {
      stableIdentity.fill(0);
    }
  });
}

function assertMlsRoomWire(room, expectedRoomId, expectedOwner) {
  exactKeys(room, [
    "room_id", "owner_username", "group_id_b64", "active", "synchronized", "epoch", "revision",
    "membership_digest_b64", "roster", "recovery_snapshot", "policy",
  ]);
  assert.equal(room.room_id, expectedRoomId);
  assert.equal(room.owner_username, expectedOwner);
  assert.equal(typeof room.active, "boolean");
  assert.equal(typeof room.synchronized, "boolean");
  assert.match(room.group_id_b64, /^[A-Za-z0-9_-]{43}$/u);
  assert.match(room.epoch, /^(?:0|[1-9][0-9]*)$/u);
  assert.match(room.revision, /^(?:0|[1-9][0-9]*)$/u);
  assert.ok(Array.isArray(room.roster));
  assert.ok(room.roster.length <= MLS_MAX_ROSTER);
  if (room.roster.length === 0) {
    assert.equal(room.active, false);
    assert.equal(room.synchronized, false);
    assert.equal(room.epoch, "0");
    assert.equal(room.revision, "0");
    assert.equal(room.membership_digest_b64, "");
  } else {
    assertCanonicalBytes(room.membership_digest_b64, 32, "MLS membership digest");
  }
  const usernames = new Set();
  for (const member of room.roster) {
    exactKeys(member, ["username", "stable_identity_b64"]);
    assert.match(member.username, MLS_USERNAME_PATTERN);
    assert.equal(usernames.has(member.username.toLowerCase()), false);
    usernames.add(member.username.toLowerCase());
    assertCanonicalBytes(member.stable_identity_b64, 64, "MLS stable identity");
  }
  assert.ok(room.recovery_snapshot && typeof room.recovery_snapshot === "object");
  exactKeys(room.recovery_snapshot, ["active", "epoch", "revision", "membership_digest_b64", "state_envelope_b64", "roster"]);
  assert.equal(room.recovery_snapshot.active, room.active);
  assert.match(room.recovery_snapshot.epoch, /^(?:0|[1-9][0-9]*)$/u);
  assert.match(room.recovery_snapshot.revision, /^(?:0|[1-9][0-9]*)$/u);
  assert.ok(Array.isArray(room.recovery_snapshot.roster));
  assert.ok(room.recovery_snapshot.roster.length <= MLS_MAX_ROSTER);
  if (room.recovery_snapshot.active) {
    assertCanonicalBytes(room.recovery_snapshot.membership_digest_b64, 32, "MLS recovery digest");
    assert.ok(room.recovery_snapshot.roster.length > 0);
  } else {
    assert.equal(room.recovery_snapshot.epoch, "0");
    assert.equal(room.recovery_snapshot.revision, "0");
    assert.equal(room.recovery_snapshot.membership_digest_b64, "");
    assert.deepEqual(room.recovery_snapshot.roster, []);
  }
  const recoveryNames = new Set();
  for (const member of room.recovery_snapshot.roster) {
    exactKeys(member, ["username", "stable_identity_b64"]);
    assert.match(member.username, MLS_USERNAME_PATTERN);
    assert.equal(recoveryNames.has(member.username.toLowerCase()), false);
    recoveryNames.add(member.username.toLowerCase());
    assertCanonicalBytes(member.stable_identity_b64, 64, "MLS recovery identity");
  }
  if (room.synchronized) {
    assert.equal(room.active, true);
    assert.equal(room.recovery_snapshot.epoch, room.epoch);
    assert.equal(room.recovery_snapshot.revision, room.revision);
    assert.equal(room.recovery_snapshot.membership_digest_b64, room.membership_digest_b64);
    assert.deepEqual(
      room.recovery_snapshot.roster.map((member) => [member.username.toLowerCase(), member.stable_identity_b64]).sort(),
      room.roster.map((member) => [member.username.toLowerCase(), member.stable_identity_b64]).sort(),
    );
  }
  assert.ok(room.recovery_snapshot.state_envelope_b64.length > 0);
  assert.ok(room.policy && typeof room.policy === "object");
  exactKeys(room.policy, [
    "self_destruct_timer_sec", "overall_expiry_sec", "allow_images", "allow_videos", "allow_files",
    "enforce_text_absolute_expiry", "image_read_timer_sec", "image_overall_expiry_sec",
    "enforce_image_absolute_expiry", "video_read_timer_sec", "video_overall_expiry_sec",
    "enforce_video_absolute_expiry", "file_read_timer_sec", "file_overall_expiry_sec",
    "enforce_file_absolute_expiry",
  ]);
}

async function sendMlsRoomTransaction(socket, frame) {
  const result = waitForMlsFrame(
    socket,
    (candidate) => candidate.type === "mls_room_result" &&
      candidate.room_id === frame.room_id && candidate.message_id === frame.message_id,
  );
  sendControlFrame(socket, frame);
  const outcome = await result;
  exactKeys(outcome, ["type", "protocol_version", "room_id", "message_id", "revision", "accepted"]);
  assert.equal(outcome.protocol_version, MLS_PROTOCOL_VERSION);
  assert.equal(outcome.revision, frame.revision);
  assert.equal(typeof outcome.accepted, "boolean");
  return outcome.accepted ? "ACCEPTED" : "REJECTED";
}

async function sendMlsSnapshot(socket, frame) {
  const result = waitForMlsFrame(
    socket,
    (candidate) => candidate.type === "mls_snapshot_result" &&
      candidate.room_id === frame.room_id && candidate.message_id === frame.message_id,
  );
  sendControlFrame(socket, frame);
  const outcome = await result;
  exactKeys(outcome, ["type", "protocol_version", "room_id", "message_id", "revision", "accepted"]);
  assert.equal(outcome.protocol_version, MLS_PROTOCOL_VERSION);
  assert.equal(outcome.revision, frame.revision);
  assert.equal(typeof outcome.accepted, "boolean");
  return outcome.accepted ? "ACCEPTED" : "REJECTED";
}

function mlsApplicationAad(roomId, messageId, sender) {
  const fields = [
    encoder.encode("ABYSSAL-MLS-V10-APPLICATION"),
    encoder.encode(roomId),
    encoder.encode(messageId),
    encoder.encode(sender),
  ];
  const output = new Uint8Array(fields.reduce((size, field) => size + 4 + field.byteLength, 0));
  const view = new DataView(output.buffer);
  let offset = 0;
  for (const field of fields) {
    view.setUint32(offset, field.byteLength, false);
    offset += 4;
    output.set(field, offset);
    offset += field.byteLength;
    field.fill(0);
  }
  return output;
}

function mlsNative(stage, operation) {
  try {
    return operation();
  } catch (error) {
    throw new Error(`MLS native ${stage} failed: ${String(error)}`);
  }
}

async function runMlsIntegration(alice, bob, aliceSocket, bobSocket) {
  let aliceRoom;
  let bobRoom;
  let alicePostDelete;
  let oversizedSocket;
  let replacementBobSocket;
  let aliceStable = new Uint8Array(0);
  let bobStable = new Uint8Array(0);
  let groupId = new Uint8Array(0);
  let nodeContext = new Uint8Array(0);
  let initialDigest = new Uint8Array(0);
  let initialState = new Uint8Array(0);
  try {
    // A non-canonical frame above the legacy parser ceiling must be rejected
    // before JSON allocation. Use a disposable authenticated socket so the
    // two lifecycle sockets remain valid for the rest of this test.
    const bobDisconnected = waitForFrame(
      aliceSocket,
      (frame) => frame.type === "presence" && frame.users.some(
        (user) => user.username === bob.username && user.connected === false,
      ),
    );
    bobSocket.close();
    await bobDisconnected;
    oversizedSocket = await connect(bob);
    const oversizedDisconnected = waitForFrame(
      aliceSocket,
      (frame) => frame.type === "presence" && frame.users.some(
        (user) => user.username === bob.username && user.connected === false,
      ),
    );
    const oversizedClose = waitForSocketClose(oversizedSocket);
    oversizedSocket.send("x".repeat(1_048_577));
    await oversizedClose;
    await oversizedDisconnected;
    oversizedSocket = null;
    replacementBobSocket = await connect(bob);
    bobSocket = replacementBobSocket;

    const [aliceCatalog, bobCatalog] = await Promise.all([
      waitForMlsFrame(aliceSocket, (frame) => frame.type === "mls_rooms"),
      waitForMlsFrame(bobSocket, (frame) => frame.type === "mls_rooms"),
    ]);
    for (const catalog of [aliceCatalog, bobCatalog]) {
      exactKeys(catalog, ["type", "protocol_version", "rooms"]);
      assert.equal(catalog.protocol_version, MLS_PROTOCOL_VERSION);
      assert.deepEqual(catalog.rooms, [], "fresh relay must not create a default MLS room");
    }

    const roomId = `room_${randomUUID().replaceAll("-", "")}`;
    assert.match(roomId, MLS_ID_PATTERN);
    const policy = {
      self_destruct_timer_sec: "5", overall_expiry_sec: "0", allow_images: true,
      allow_videos: true, allow_files: true, enforce_text_absolute_expiry: false,
      image_read_timer_sec: "5", image_overall_expiry_sec: "0", enforce_image_absolute_expiry: false,
      video_read_timer_sec: "5", video_overall_expiry_sec: "0", enforce_video_absolute_expiry: false,
      file_read_timer_sec: "5", file_overall_expiry_sec: "0", enforce_file_absolute_expiry: false,
    };
    const policyKeys = Object.keys(policy);
    assert.equal(policyKeys.length, 15);
    aliceStable = alice.identity.publicKey().slice(0, 64);
    bobStable = bob.identity.publicKey().slice(0, 64);
    groupId = new Uint8Array(32);
    randomFillSync(groupId);
    nodeContext = encoder.encode(`ABYSSAL-MLS-V10-NODE:${alice.node_id}`);
    aliceRoom = mlsNative("create room", () => alice.identity.mlsCreateRoom(roomId, alice.username, nodeContext, groupId));
    const createdInfo = readMlsRoomInfo(aliceRoom);
    assert.equal(createdInfo.epoch, 0n);
    assert.equal(createdInfo.revision, 0n);
    assert.equal(createdInfo.memberCount, 1);
    assert.deepEqual(createdInfo.groupId, groupId);
    initialDigest = createdInfo.membershipDigest.slice();
    initialState = mlsNative("seal initial room", () => aliceRoom.sealState());
    createdInfo.groupId.fill(0);
    createdInfo.membershipDigest.fill(0);
    const createFrame = {
      type: "mls_create_room", protocol_version: MLS_PROTOCOL_VERSION, room_id: roomId,
      group_id_b64: encode(groupId), epoch: "0", revision: "0",
      membership_digest_b64: encode(initialDigest), stable_identity_b64: encode(aliceStable),
      state_envelope_b64: encode(initialState), policy,
    };
    exactKeys(createFrame, [
      "type", "protocol_version", "room_id", "group_id_b64", "epoch", "revision",
      "membership_digest_b64", "stable_identity_b64", "state_envelope_b64", "policy",
    ]);
    const created = waitForMlsFrame(aliceSocket, (frame) => frame.type === "mls_room_created" && frame.room?.room_id === roomId);
    sendControlFrame(aliceSocket, createFrame);
    const createdFrame = await created;
    exactKeys(createdFrame, ["type", "protocol_version", "room"]);
    assert.equal(createdFrame.protocol_version, MLS_PROTOCOL_VERSION);
    assertMlsRoomWire(createdFrame.room, roomId, alice.username);

    const discoveredOnBob = waitForMlsFrame(bobSocket, (frame) => frame.type === "mls_room_discovered" && frame.room_id === roomId);
    sendControlFrame(bobSocket, {
      type: "mls_discover_room",
      protocol_version: MLS_PROTOCOL_VERSION,
      room_id: roomId,
    });
    const discoveredFrame = await discoveredOnBob;
    exactKeys(discoveredFrame, ["type", "protocol_version", "room_id", "group_id_b64", "owner_username"]);
    assert.equal(discoveredFrame.protocol_version, MLS_PROTOCOL_VERSION);
    assert.equal(discoveredFrame.owner_username, alice.username);
    assert.deepEqual(decode(discoveredFrame.group_id_b64), groupId);

    bobRoom = mlsNative("pending join", () => bob.identity.mlsPendingJoin(roomId, bob.username, nodeContext, groupId));
    const bobKeyPackage = mlsNative("create key package", () => bobRoom.keyPackage());
    const bobPendingState = mlsNative("seal pending join", () => bobRoom.sealState());
    const joinRequestId = randomUUID();
    const joinFrame = {
      type: "mls_join_request", protocol_version: MLS_PROTOCOL_VERSION, room_id: roomId,
      request_id: joinRequestId, stable_identity_b64: encode(bobStable),
      key_package_b64: encode(bobKeyPackage), state_envelope_b64: encode(bobPendingState),
    };
    const joinRequested = waitForMlsFrame(aliceSocket, (frame) => frame.type === "mls_join_requested" && frame.request_id === joinRequestId);
    sendControlFrame(bobSocket, joinFrame);
    const joinRequestedFrame = await joinRequested;
    exactKeys(joinRequestedFrame, ["type", "protocol_version", "room_id", "request_id", "username", "stable_identity_b64", "key_package_b64"]);
    assert.equal(joinRequestedFrame.protocol_version, MLS_PROTOCOL_VERSION);
    assert.equal(joinRequestedFrame.username, bob.username);
    assert.equal(joinRequestedFrame.stable_identity_b64, encode(bobStable));
    assert.equal(joinRequestedFrame.key_package_b64, encode(bobKeyPackage));

    // A non-owner rejection is dropped by the relay; the pending request remains
    // available to the owner and the exact valid commit below still succeeds.
    sendControlFrame(bobSocket, {
      type: "mls_join_reject",
      protocol_version: MLS_PROTOCOL_VERSION,
      room_id: roomId,
      request_id: joinRequestId,
    });
    const invalidMembership = {
      type: "mls_membership_commit", protocol_version: MLS_PROTOCOL_VERSION, room_id: roomId,
      message_id: randomUUID(), request_id: randomUUID(), from_epoch: "0", to_epoch: "1",
      revision: "1", group_id_b64: encode(groupId), from_membership_digest_b64: encode(initialDigest),
      membership_digest_b64: encode(initialDigest), roster: [{ username: alice.username, stable_identity_b64: encode(aliceStable) }],
      control_b64: encode(new Uint8Array([1])), welcome_b64: encode(new Uint8Array([1])),
      authenticated_data_b64: encode(new Uint8Array([1])), state_envelope_b64: encode(initialState),
    };
    const invalidOutcome = await sendMlsRoomTransaction(aliceSocket, invalidMembership);
    assert.equal(invalidOutcome, "REJECTED", "mismatched membership request must not mutate room authority");

    const membershipMessageId = randomUUID();
    const commitWrapper = mlsNative("add member", () => aliceRoom.addMember(bobKeyPackage, bob.username, bobStable, membershipMessageId));
    const commit = readMlsCommit(commitWrapper);
    let commitRoster;
    try {
      commitRoster = mlsRosterFromNative(commit.rosterJson);
      assert.equal(commit.messageId, membershipMessageId);
      assert.equal(commit.fromEpoch, 0n);
      assert.equal(commit.toEpoch, 1n);
      assert.equal(commit.revision, 1n);
      assert.equal(commitRoster.length, 2);
      assert.deepEqual(commit.groupId, groupId);
      assert.deepEqual(commit.fromMembershipDigest, initialDigest);
      assert.notDeepEqual(commit.membershipDigest, initialDigest);
      assert.ok(commit.commit.byteLength > 0);
      assert.ok(commit.welcome.byteLength > 0);
      const membershipFrame = {
        type: "mls_membership_commit", protocol_version: MLS_PROTOCOL_VERSION, room_id: roomId,
        message_id: membershipMessageId, request_id: joinRequestId,
        from_epoch: commit.fromEpoch.toString(), to_epoch: commit.toEpoch.toString(), revision: commit.revision.toString(),
        group_id_b64: encode(commit.groupId), from_membership_digest_b64: encode(commit.fromMembershipDigest),
        membership_digest_b64: encode(commit.membershipDigest), roster: commitRoster,
        control_b64: encode(commit.commit), welcome_b64: encode(commit.welcome),
        authenticated_data_b64: encode(commit.authenticatedData), state_envelope_b64: encode(commit.stateEnvelope),
      };
      const membershipOnBob = waitForMlsFrame(bobSocket, (frame) => frame.type === "mls_membership" && frame.message_id === membershipMessageId);
      assert.equal(await sendMlsRoomTransaction(aliceSocket, membershipFrame), "ACCEPTED");
      mlsNative("commit added member", () => aliceRoom.commitOutbound(membershipMessageId, commit.revision));
      const membershipFrameOnBob = await membershipOnBob;
      exactKeys(membershipFrameOnBob, [
        "type", "protocol_version", "room_id", "message_id", "from_epoch", "to_epoch", "revision",
        "from_membership_digest_b64", "group_id_b64", "membership_digest_b64", "roster", "control_b64",
        "welcome_b64", "authenticated_data_b64",
      ]);
      assert.equal(membershipFrameOnBob.protocol_version, MLS_PROTOCOL_VERSION);
      assert.equal(membershipFrameOnBob.welcome_b64, encode(commit.welcome));
      assert.equal(membershipFrameOnBob.control_b64, "");
      assert.deepEqual(membershipFrameOnBob.roster, commitRoster);

      const expectedMembersJson = mlsRosterJson(commitRoster);
      const bobMembershipDigest = decode(membershipFrameOnBob.membership_digest_b64);
      const bobWelcome = decode(membershipFrameOnBob.welcome_b64);
      const bobInfo = mlsNative("join Welcome", () => bobRoom.joinWelcome(bobWelcome, expectedMembersJson, bobMembershipDigest));
      const bobState = mlsNative("seal joined room", () => bobRoom.sealState());
      assert.equal(bobInfo.epoch, 1n);
      assert.equal(bobInfo.revision, 0n);
      assert.equal(bobInfo.memberCount, 2);
      const joinSnapshot = {
        type: "mls_state_snapshot", protocol_version: MLS_PROTOCOL_VERSION, room_id: roomId,
        message_id: membershipMessageId, epoch: bobInfo.epoch.toString(), revision: bobInfo.revision.toString(),
        membership_digest_b64: encode(bobMembershipDigest), state_envelope_b64: encode(bobState),
      };
      assert.equal(await sendMlsSnapshot(bobSocket, joinSnapshot), "ACCEPTED");
      bobInfo.groupId.fill(0);
      bobInfo.membershipDigest.fill(0);
      bobMembershipDigest.fill(0);
      bobWelcome.fill(0);
      bobState.fill(0);
    } finally {
      wipeMlsCommit(commit);
      bobKeyPackage.fill(0);
      bobPendingState.fill(0);
    }

    const probeMessageId = randomUUID();
    const probePlaintext = encoder.encode("MLS local state probe");
    const probeAad = mlsApplicationAad(roomId, probeMessageId, alice.username);
    let probeEncrypted;
    let probeDecrypted;
    try {
      probeEncrypted = mlsNative("encrypt local probe", () => aliceRoom.encryptApplication(probeMessageId, probePlaintext, probeAad));
      probeDecrypted = mlsNative("decrypt local probe", () => bobRoom.decryptApplication(
        probeEncrypted.ciphertext,
        probeEncrypted.epoch,
        probeMessageId,
        probeEncrypted.authenticatedData,
      ));
      assert.deepEqual(probeDecrypted.plaintext, probePlaintext);
      mlsNative("rollback local probe recipient", () => bobRoom.rollbackOutbound(probeMessageId, probeDecrypted.revision));
      mlsNative("rollback local probe sender", () => aliceRoom.rollbackOutbound(probeMessageId, probeEncrypted.revision));
    } finally {
      probePlaintext.fill(0);
      probeAad.fill(0);
      for (const field of [
        probeEncrypted?.authenticatedData, probeEncrypted?.ciphertext, probeEncrypted?.groupId,
        probeEncrypted?.membershipDigest, probeEncrypted?.stateEnvelope, probeDecrypted?.authenticatedData,
        probeDecrypted?.groupId, probeDecrypted?.membershipDigest, probeDecrypted?.plaintext,
        probeDecrypted?.stateEnvelope,
      ]) field?.fill?.(0);
      probeEncrypted?.free?.();
      probeDecrypted?.free?.();
    }

    const sendAliceApplicationFrame = async (plaintext, messageId) => {
      const aad = mlsApplicationAad(roomId, messageId, alice.username);
      const nativePlaintext = plaintext.slice();
      let wrapper;
      let encrypted;
      try {
        wrapper = mlsNative("encrypt application", () => aliceRoom.encryptApplication(messageId, nativePlaintext, aad));
        encrypted = {
          authenticatedData: wrapper.authenticatedData,
          ciphertext: wrapper.ciphertext,
          epoch: wrapper.epoch,
          groupId: wrapper.groupId,
          membershipDigest: wrapper.membershipDigest,
          messageId: wrapper.messageId,
          revision: wrapper.revision,
          stateEnvelope: wrapper.stateEnvelope,
        };
      } finally {
        nativePlaintext.fill(0);
        aad.fill(0);
        wrapper?.free();
      }
      try {
        const frame = {
          type: "mls_application", protocol_version: MLS_PROTOCOL_VERSION, room_id: roomId,
          message_id: encrypted.messageId, group_id_b64: encode(encrypted.groupId), epoch: encrypted.epoch.toString(),
          revision: encrypted.revision.toString(), membership_digest_b64: encode(encrypted.membershipDigest),
          ciphertext_b64: encode(encrypted.ciphertext), authenticated_data_b64: encode(encrypted.authenticatedData),
          state_envelope_b64: encode(encrypted.stateEnvelope),
        };
        exactKeys(frame, [
          "type", "protocol_version", "room_id", "message_id", "group_id_b64", "epoch", "revision",
          "membership_digest_b64", "ciphertext_b64", "authenticated_data_b64", "state_envelope_b64",
        ]);
        assert.equal(await sendMlsRoomTransaction(aliceSocket, frame), "ACCEPTED");
        mlsNative("commit application", () => aliceRoom.commitOutbound(messageId, encrypted.revision));
        return frame;
      } finally {
        for (const field of [
          encrypted.authenticatedData, encrypted.ciphertext, encrypted.groupId,
          encrypted.membershipDigest, encrypted.stateEnvelope,
        ]) field.fill(0);
      }
    };

    const processBobApplication = async (received, plaintext, expectedFrame) => {
      exactKeys(received, [
        "type", "protocol_version", "room_id", "message_id", "sender_username", "epoch", "revision",
        "membership_digest_b64", "ciphertext_b64", "authenticated_data_b64",
      ]);
      assert.equal(received.protocol_version, MLS_PROTOCOL_VERSION);
      assert.equal(received.room_id, roomId);
      assert.equal(received.sender_username, alice.username);
      assert.equal(received.message_id, expectedFrame.message_id);
      assert.equal(received.epoch, expectedFrame.epoch);
      assert.equal(received.membership_digest_b64, expectedFrame.membership_digest_b64);
      assert.equal(received.ciphertext_b64, expectedFrame.ciphertext_b64);
      assert.equal(received.authenticated_data_b64, expectedFrame.authenticated_data_b64);
      const receiveAad = decode(received.authenticated_data_b64);
      const receivedCiphertext = decode(received.ciphertext_b64);
      let decrypted;
      try {
        decrypted = mlsNative("decrypt application", () => bobRoom.decryptApplication(
          receivedCiphertext,
          BigInt(received.epoch),
          received.message_id,
          receiveAad,
        ));
        assert.deepEqual(decrypted.plaintext, plaintext);
        assert.equal(decrypted.messageId, received.message_id);
        assert.deepEqual(decrypted.groupId, groupId);
        assert.equal(encode(decrypted.membershipDigest), received.membership_digest_b64);
        const snapshot = {
          type: "mls_state_snapshot", protocol_version: MLS_PROTOCOL_VERSION, room_id: roomId,
          message_id: received.message_id, epoch: decrypted.epoch.toString(), revision: decrypted.revision.toString(),
          membership_digest_b64: encode(decrypted.membershipDigest), state_envelope_b64: encode(decrypted.stateEnvelope),
        };
        assert.equal(await sendMlsSnapshot(bobSocket, snapshot), "ACCEPTED");
        mlsNative("commit received application", () => bobRoom.commitOutbound(received.message_id, decrypted.revision));
        return snapshot;
      } finally {
        receiveAad.fill(0);
        receivedCiphertext.fill(0);
        for (const field of [
          decrypted?.plaintext, decrypted?.groupId, decrypted?.membershipDigest,
          decrypted?.stateEnvelope, decrypted?.authenticatedData,
        ]) field?.fill?.(0);
        decrypted?.free?.();
      }
    };

    const sendAliceApplication = async (plaintext, messageId) => {
      const applicationOnBob = waitForMlsFrame(
        bobSocket,
        (candidate) => candidate.type === "mls_application" && candidate.message_id === messageId,
      );
      const frame = await sendAliceApplicationFrame(plaintext, messageId);
      await processBobApplication(await applicationOnBob, plaintext, frame);
      return frame;
    };

    const firstMessageId = randomUUID();
    const firstPlaintext = encoder.encode(JSON.stringify({ kind: "text", content: "MLS application secret", id: firstMessageId }));
    let firstFrame;
    try {
      firstFrame = await sendAliceApplication(firstPlaintext, firstMessageId);
      assert.equal(JSON.stringify(firstFrame).includes("MLS application secret"), false);
      const noDuplicateDelivery = waitForNoMlsFrame(
        bobSocket,
        (candidate) => candidate.type === "mls_application" &&
          candidate.message_id === firstMessageId,
      );
      const replayResult = await sendMlsRoomTransaction(aliceSocket, firstFrame);
      assert.equal(replayResult, "ACCEPTED", "exact MLS replay must return its terminal result");
      await noDuplicateDelivery;
    } finally {
      firstPlaintext.fill(0);
    }

    const bobOffline = waitForFrame(
      aliceSocket,
      (frame) => frame.type === "presence" && frame.users.some(
        (user) => user.username === bob.username && user.connected === false,
      ),
    );
    bobSocket.close();
    await bobOffline;

    const offlineAId = randomUUID();
    const offlineBId = randomUUID();
    const offlineAPlaintext = encoder.encode(JSON.stringify({ kind: "text", content: "MLS offline A", id: offlineAId }));
    const offlineBPlaintext = encoder.encode(JSON.stringify({ kind: "text", content: "MLS offline B", id: offlineBId }));
    let offlineAFrame;
    let offlineBFrame;
    try {
      offlineAFrame = await sendAliceApplicationFrame(offlineAPlaintext, offlineAId);
      offlineBFrame = await sendAliceApplicationFrame(offlineBPlaintext, offlineBId);

      replacementBobSocket = await connect(bob);
      bobSocket = replacementBobSocket;
      const recoveryCatalog = await waitForMlsFrame(bobSocket, (candidate) => candidate.type === "mls_rooms");
      const recoveredRoom = recoveryCatalog.rooms.find((room) => room.room_id === roomId);
      assert.ok(recoveredRoom, "offline MLS room missing from recovery catalog");
      assertMlsRoomWire(recoveredRoom, roomId, alice.username);
      assert.equal(recoveredRoom.active, true);
      assert.equal(recoveredRoom.synchronized, false);
      assert.equal(recoveredRoom.recovery_snapshot.revision, recoveredRoom.revision);

      const receivedA = await waitForMlsFrame(
        bobSocket,
        (candidate) => candidate.type === "mls_application" && candidate.message_id === offlineAId,
      );
      const receivedB = await waitForMlsFrame(
        bobSocket,
        (candidate) => candidate.type === "mls_application" && candidate.message_id === offlineBId,
      );
      await processBobApplication(receivedA, offlineAPlaintext, offlineAFrame);
      await waitForNoMlsFrame(
        bobSocket,
        (candidate) => candidate.type === "mls_application" && candidate.message_id === offlineAId,
      );

      let replayAad = decode(receivedA.authenticated_data_b64);
      let replayCiphertext = decode(receivedA.ciphertext_b64);
      try {
        assert.throws(
          () => mlsNative("replay application", () => bobRoom.decryptApplication(
            replayCiphertext,
            BigInt(receivedA.epoch),
            receivedA.message_id,
            replayAad,
          )),
          /Payload unavailable/u,
        );
      } finally {
        replayAad.fill(0);
        replayCiphertext.fill(0);
        replayAad = new Uint8Array(0);
        replayCiphertext = new Uint8Array(0);
      }

      await processBobApplication(receivedB, offlineBPlaintext, offlineBFrame);
      const synchronizedCatalog = await waitForMlsFrame(
        bobSocket,
        (candidate) => candidate.type === "mls_rooms" && candidate.rooms.some(
          (room) => room.room_id === roomId && room.synchronized === true,
        ),
      );
      assertMlsRoomWire(
        synchronizedCatalog.rooms.find((room) => room.room_id === roomId),
        roomId,
        alice.username,
      );

      const bobAgainOffline = waitForFrame(
        aliceSocket,
        (frame) => frame.type === "presence" && frame.users.some(
          (user) => user.username === bob.username && user.connected === false,
        ),
      );
      bobSocket.close();
      await bobAgainOffline;
      replacementBobSocket = await connect(bob);
      bobSocket = replacementBobSocket;
      const cleanCatalog = await waitForMlsFrame(bobSocket, (candidate) => candidate.type === "mls_rooms");
      const cleanRoom = cleanCatalog.rooms.find((room) => room.room_id === roomId);
      assert.ok(cleanRoom, "acknowledged MLS room missing after reconnect");
      assertMlsRoomWire(cleanRoom, roomId, alice.username);
      assert.equal(cleanRoom.synchronized, true);
      await waitForNoMlsFrame(
        bobSocket,
        (candidate) => candidate.type === "mls_application" &&
          (candidate.message_id === offlineAId || candidate.message_id === offlineBId),
      );
    } finally {
      offlineAPlaintext.fill(0);
      offlineBPlaintext.fill(0);
    }

    const attachmentMessageId = randomUUID();
    const attachmentPlaintext = new Uint8Array([9, 8, 7, 6]);
    const encryptedAttachment = JSON.parse(encryptAttachment(roomId, attachmentMessageId, alice.username, "FILE", attachmentPlaintext));
    const attachmentKey = new Uint8Array(encryptedAttachment.key);
    const attachmentBlob = new Uint8Array(encryptedAttachment.blob);
    try {
      const uploadResponse = await fetch(
        `${baseUrl}/v1/attachment?chat_id=${encodeURIComponent(roomId)}&message_id=${encodeURIComponent(attachmentMessageId)}&media_type=FILE`,
        { method: "POST", headers: { authorization: `Bearer ${alice.token}` }, body: attachmentBlob },
      );
      assert.equal(uploadResponse.status, 200);
      const upload = await uploadResponse.json();
      assert.equal(upload.accepted, true);
      const staged = await fetch(`${baseUrl}/v1/attachment/${encodeURIComponent(upload.attachment_id)}`, { headers: { authorization: `Bearer ${bob.token}` } });
      assert.equal(staged.status, 404, "staged MLS attachment must not be downloadable");
      const keyB64 = encode(attachmentKey);
      const metadata = encoder.encode(JSON.stringify({
        kind: "attachment", id: attachmentMessageId, attachment_id: upload.attachment_id,
        name: "fixture.bin", media_type: "FILE", mime_type: "application/octet-stream",
        size_bytes: attachmentPlaintext.byteLength, attachment_key_b64: keyB64,
      }));
      const frame = await sendAliceApplication(metadata, attachmentMessageId);
      assert.equal(JSON.stringify(frame).includes(keyB64), false, "attachment key must stay inside E2EE application ciphertext");
      const downloaded = await fetch(`${baseUrl}/v1/attachment/${encodeURIComponent(upload.attachment_id)}`, { headers: { authorization: `Bearer ${bob.token}` } });
      assert.equal(downloaded.status, 200);
      const downloadedBytes = new Uint8Array(await downloaded.arrayBuffer());
      assert.ok(downloadedBytes.byteLength > 0);
      assert.deepEqual(downloadedBytes, attachmentBlob);
      assert.deepEqual(decryptAttachment(roomId, attachmentMessageId, alice.username, "FILE", attachmentKey, downloadedBytes), attachmentPlaintext);
      downloadedBytes.fill(0);

      const leaveRequestId = randomUUID();
      const leaveRequested = waitForMlsFrame(aliceSocket, (candidate) => candidate.type === "mls_leave_requested" && candidate.request_id === leaveRequestId);
      const leavePending = waitForMlsFrame(bobSocket, (candidate) => candidate.type === "mls_leave_pending" && candidate.request_id === leaveRequestId);
      sendControlFrame(bobSocket, {
        type: "mls_leave_request",
        protocol_version: MLS_PROTOCOL_VERSION,
        room_id: roomId,
        request_id: leaveRequestId,
      });
      const [leaveRequestedFrame] = await Promise.all([leaveRequested, leavePending]);
      exactKeys(leaveRequestedFrame, ["type", "protocol_version", "room_id", "request_id", "username", "stable_identity_b64"]);
      assert.equal(leaveRequestedFrame.username, bob.username);
      assert.equal(leaveRequestedFrame.stable_identity_b64, encode(bobStable));

      const leaveMessageId = randomUUID();
      const removeWrapper = mlsNative("remove member", () => aliceRoom.removeMember(bob.username, bobStable, leaveMessageId));
      const removal = readMlsCommit(removeWrapper);
      try {
        const removalRoster = mlsRosterFromNative(removal.rosterJson);
        assert.equal(removalRoster.length, 1);
        assert.equal(removal.toEpoch, 2n);
        const removalFrame = {
          type: "mls_membership_commit", protocol_version: MLS_PROTOCOL_VERSION, room_id: roomId,
          message_id: leaveMessageId, request_id: leaveRequestId,
          from_epoch: removal.fromEpoch.toString(), to_epoch: removal.toEpoch.toString(), revision: removal.revision.toString(),
          group_id_b64: encode(removal.groupId), from_membership_digest_b64: encode(removal.fromMembershipDigest),
          membership_digest_b64: encode(removal.membershipDigest), roster: removalRoster,
          control_b64: encode(removal.commit), welcome_b64: "",
          authenticated_data_b64: encode(removal.authenticatedData), state_envelope_b64: encode(removal.stateEnvelope),
        };
        const leftOnBob = waitForMlsFrame(bobSocket, (candidate) => candidate.type === "mls_left" && candidate.room_id === roomId);
        assert.equal(await sendMlsRoomTransaction(aliceSocket, removalFrame), "ACCEPTED");
        mlsNative("commit member removal", () => aliceRoom.commitOutbound(leaveMessageId, removal.revision));
        await leftOnBob;
        const removedDownload = await fetch(`${baseUrl}/v1/attachment/${encodeURIComponent(upload.attachment_id)}`, { headers: { authorization: `Bearer ${bob.token}` } });
        assert.equal(removedDownload.status, 403, "removed member must lose MLS attachment access");
        bobRoom.free();
        bobRoom = null;

        // With no Bob roster entry, the next valid application has no Bob delivery.
        const afterLeaveId = randomUUID();
        const afterLeavePlaintext = encoder.encode("post-leave application");
        const afterLeaveAad = mlsApplicationAad(roomId, afterLeaveId, alice.username);
        let afterLeaveWrapper;
        try {
          afterLeaveWrapper = mlsNative("encrypt post-leave application", () => aliceRoom.encryptApplication(afterLeaveId, afterLeavePlaintext, afterLeaveAad));
          const afterLeaveFrame = {
            type: "mls_application", protocol_version: MLS_PROTOCOL_VERSION, room_id: roomId,
            message_id: afterLeaveWrapper.messageId, group_id_b64: encode(afterLeaveWrapper.groupId), epoch: afterLeaveWrapper.epoch.toString(),
            revision: afterLeaveWrapper.revision.toString(), membership_digest_b64: encode(afterLeaveWrapper.membershipDigest),
            ciphertext_b64: encode(afterLeaveWrapper.ciphertext), authenticated_data_b64: encode(afterLeaveWrapper.authenticatedData),
            state_envelope_b64: encode(afterLeaveWrapper.stateEnvelope),
          };
          assert.equal(await sendMlsRoomTransaction(aliceSocket, afterLeaveFrame), "ACCEPTED");
          mlsNative("commit post-leave application", () => aliceRoom.commitOutbound(afterLeaveId, afterLeaveWrapper.revision));
          await waitForNoMlsFrame(bobSocket, (candidate) => candidate.type === "mls_application" && candidate.message_id === afterLeaveId);
        } finally {
          afterLeavePlaintext.fill(0);
          afterLeaveAad.fill(0);
          afterLeaveWrapper?.authenticatedData?.fill?.(0);
          afterLeaveWrapper?.ciphertext?.fill?.(0);
          afterLeaveWrapper?.groupId?.fill?.(0);
          afterLeaveWrapper?.membershipDigest?.fill?.(0);
          afterLeaveWrapper?.stateEnvelope?.fill?.(0);
          afterLeaveWrapper?.free?.();
        }
      } finally {
        attachmentPlaintext.fill(0);
        attachmentKey.fill(0);
        attachmentBlob.fill(0);
        for (const field of [encryptedAttachment.key, encryptedAttachment.blob]) field?.fill?.(0);
      }
    } finally {
      // The room is owner-controlled; deletion must remove it for every later catalog.
      const deleted = waitForMlsFrame(aliceSocket, (candidate) => candidate.type === "mls_room_deleted" && candidate.room_id === roomId);
      sendControlFrame(aliceSocket, {
        type: "mls_delete_room",
        protocol_version: MLS_PROTOCOL_VERSION,
        room_id: roomId,
      });
      await deleted;
      aliceSocket.close();
      await new Promise((resolve) => setTimeout(resolve, 100));
      let lastConnectError;
      for (let attempt = 0; attempt < 10; attempt += 1) {
        try {
          alicePostDelete = await connect(alice);
          lastConnectError = undefined;
          break;
        } catch (error) {
          lastConnectError = error;
          await new Promise((resolve) => setTimeout(resolve, 100));
        }
      }
      if (!alicePostDelete) throw lastConnectError ?? new Error("post-delete reconnect failed");
      const postDeleteCatalog = await waitForMlsFrame(alicePostDelete, (candidate) => candidate.type === "mls_rooms");
      assert.equal(postDeleteCatalog.protocol_version, MLS_PROTOCOL_VERSION);
      assert.equal(postDeleteCatalog.rooms.some((room) => room.room_id === roomId), false);
      alicePostDelete.close();
    }
  } finally {
    alicePostDelete?.close();
    oversizedSocket?.close();
    replacementBobSocket?.close();
    aliceRoom?.free();
    bobRoom?.free();
    aliceStable.fill(0);
    bobStable.fill(0);
    groupId.fill(0);
    nodeContext.fill(0);
    initialDigest.fill(0);
    initialState.fill(0);
  }
}

const alice = await register(aliceCode, "alice-password");
const bob = await register(bobCode, "bob-password");
assert.equal(await opaqueStartStatus(aliceCode, "alice-password"), 409);
assert.equal(await opaqueStartStatus(aliceCode, "other-password"), 409);

await expectBuildAdmissionRejected(alice);
const aliceTicket = await requestWsTicket(alice);
await expectWebSocketRejected(["abyssal-v2", `bearer.${alice.token}`]);
let aliceSocket = await connectWithTicket(aliceTicket, alice.node_id);
await expectWebSocketRejected(["abyssal-v2", `ticket.${aliceTicket}`]);
let bobSocket = await connect(bob);
let bobReconnect;
try {
  const [aliceDirectoryStamp, bobDirectoryStamp] = await Promise.all([
    waitForDirectoryStamp(aliceSocket),
    waitForDirectoryStamp(bobSocket),
  ]);
  assert.deepEqual(aliceDirectoryStamp, bobDirectoryStamp);
  assert.equal(aliceDirectoryStamp.directory_node_id, alice.node_id);
  assert.equal(aliceDirectoryStamp.directory_revision, 2);
  const directoryStamp = aliceDirectoryStamp;
  const aliceDirect = waitForFrame(
    aliceSocket,
    (frame) => frame.type === "direct_opened" && frame.direct.peer_username === bob.username,
  );
  const bobDirect = waitForFrame(
    bobSocket,
    (frame) => frame.type === "direct_opened" && frame.direct.peer_username === alice.username,
  );
  sendControlFrame(aliceSocket, { type: "open_direct", peer_username: bob.username });
  const [aliceOpened, bobOpened] = await Promise.all([aliceDirect, bobDirect]);
  assert.equal(aliceOpened.direct.id, bobOpened.direct.id);
  assert.match(aliceOpened.direct.id, /^dm_[a-f0-9]{32}$/);

  sendControlFrame(aliceSocket, { type: "join", chat_id: aliceOpened.direct.id });
  sendControlFrame(bobSocket, { type: "join", chat_id: aliceOpened.direct.id });

  // Empty directory evidence is a deliberately rejected first-contact frame.
  // Its staged ratchet must roll back and its lease must be released. The
  // rejected transaction ID remains terminal, so the corrected send uses a
  // fresh ID while proving the released one-time prekey is reusable.
  const missingStampMessageId = randomUUID();
  const missingStampPlaintext = JSON.stringify({
    kind: "text",
    id: missingStampMessageId,
    sender: alice.username,
    content: "missing directory stamp",
    ...directoryStamp,
  });
  const missingStampOutcome = await sendEncryptedMessage(
    alice,
    bob,
    aliceSocket,
    aliceOpened.direct.id,
    missingStampPlaintext,
    directoryStamp,
    {
      messageId: missingStampMessageId,
      mutate: (frame) => {
        frame.directory_node_id = "";
        frame.directory_revision = 0;
        frame.directory_digest = "";
      },
    },
  );
  assert.equal(missingStampOutcome, "REJECTED");
  assert.equal(releasedPrekeysAwaitingReuse.size, 1);
  const missingStampRetryMessageId = randomUUID();
  const missingStampRetryPlaintext = JSON.stringify({
    kind: "text",
    id: missingStampRetryMessageId,
    sender: alice.username,
    content: "missing directory stamp",
    ...directoryStamp,
  });
  const missingStampRetryDelivered = waitForFrame(
    bobSocket,
    (frame) => frame.type === "message" && frame.message_id === missingStampRetryMessageId,
  );
  const missingStampRetryOutcome = await sendEncryptedMessage(
    alice,
    bob,
    aliceSocket,
    aliceOpened.direct.id,
    missingStampRetryPlaintext,
    latestDirectoryStamp(aliceSocket),
    { messageId: missingStampRetryMessageId },
  );
  assert.equal(missingStampRetryOutcome, "ACCEPTED");
  const missingStampRetryFrame = await missingStampRetryDelivered;
  const missingStampRetryPlain = decryptFrame(
    bob,
    missingStampRetryFrame,
    latestDirectoryStamp(bobSocket),
  );
  assert.equal(missingStampRetryPlain.payload.content, "missing directory stamp");
  await acknowledgeFrame(bob, bobSocket, missingStampRetryFrame, missingStampRetryPlain);
  assert.equal(releasedPrekeysAwaitingReuse.size, 0);

  // Exercise the attachment relay before the first E2EE message on this direct
  // with the same stateless XChaCha blob and context-bound decrypt path used by
  // the web client, rather than a hand-built ciphertext fixture.
  const attachmentMessageId = randomUUID();
  const attachmentPlaintext = new Uint8Array([1, 2, 3, 4]);
  const encryptedAttachment = JSON.parse(encryptAttachment(
    aliceOpened.direct.id,
    attachmentMessageId,
    alice.username,
    "FILE",
    attachmentPlaintext,
  ));
  const attachmentKey = new Uint8Array(encryptedAttachment.key);
  const attachmentBytes = new Uint8Array(encryptedAttachment.blob);
  assert.ok(attachmentBytes.byteLength > attachmentPlaintext.byteLength);
  const uploadResponse = await fetch(
    `${baseUrl}/v1/attachment?chat_id=${encodeURIComponent(aliceOpened.direct.id)}&message_id=${encodeURIComponent(attachmentMessageId)}&media_type=FILE`,
    {
      method: "POST",
      headers: { authorization: `Bearer ${alice.token}` },
      body: attachmentBytes,
    },
  );
  assert.equal(uploadResponse.status, 200);
  const upload = await uploadResponse.json();
  assert.equal(upload.accepted, true);
  assert.match(String(upload.attachment_id), /^[0-9a-f-]{36}$/);

  const stagedOwnerDownload = await fetch(
    `${baseUrl}/v1/attachment/${encodeURIComponent(upload.attachment_id)}`,
    { headers: { authorization: `Bearer ${alice.token}` } },
  );
  assert.equal(stagedOwnerDownload.status, 404);
  const downloadResponse = await fetch(
    `${baseUrl}/v1/attachment/${encodeURIComponent(upload.attachment_id)}`,
    { headers: { authorization: `Bearer ${bob.token}` } },
  );
  assert.equal(downloadResponse.status, 404);

  const acceptAttachmentMetadata = async ({
    messageId,
    attachmentId,
    encrypted,
    key,
    oneTime,
    deleteAfterDownload,
  }) => {
    const metadataPlaintext = JSON.stringify({
      kind: "attachment",
      id: messageId,
      sender: alice.username,
      timestamp_ms: Date.now(),
      self_destruct_sec: 5,
      absolute_expiry_sec: 0,
      ...latestDirectoryStamp(aliceSocket),
      attachment_id: attachmentId,
      name: "fixture.bin",
      media_type: "FILE",
      mime_type: "application/octet-stream",
      size_bytes: attachmentPlaintext.byteLength,
      attachment_cipher_version: encrypted.version,
      attachment_key_b64: encode(key),
      one_time: oneTime,
      delete_after_download: deleteAfterDownload,
    });
    const delivered = waitForFrame(
      bobSocket,
      (frame) => frame.type === "message" && frame.message_id === messageId,
    );
    const outcome = await sendEncryptedMessage(
      alice,
      bob,
      aliceSocket,
      aliceOpened.direct.id,
      metadataPlaintext,
      latestDirectoryStamp(aliceSocket),
      { messageId },
    );
    assert.equal(outcome, "ACCEPTED");
    const frame = await delivered;
    const plain = decryptFrame(bob, frame, latestDirectoryStamp(bobSocket));
    assert.equal(plain.payload.kind, "attachment");
    assert.equal(plain.payload.attachment_id, attachmentId);
    assert.equal(plain.payload.attachment_key_b64, encode(key));
    await acknowledgeFrame(bob, bobSocket, frame, plain);
  };

  await acceptAttachmentMetadata({
    messageId: attachmentMessageId,
    attachmentId: upload.attachment_id,
    encrypted: encryptedAttachment,
    key: attachmentKey,
    oneTime: false,
    deleteAfterDownload: false,
  });

  const admittedDownload = await fetch(
    `${baseUrl}/v1/attachment/${encodeURIComponent(upload.attachment_id)}`,
    { headers: { authorization: `Bearer ${bob.token}` } },
  );
  assert.equal(admittedDownload.status, 200);
  assert.equal(admittedDownload.headers.get("x-abyssal-attachment-claim"), null);
  assert.equal(admittedDownload.headers.get("content-length"), String(attachmentBytes.byteLength));
  assert.ok(Number(admittedDownload.headers.get("content-length")) > 0);
  const downloadedAttachmentBytes = new Uint8Array(await admittedDownload.arrayBuffer());
  assert.ok(downloadedAttachmentBytes.byteLength > 0);
  assert.deepEqual(downloadedAttachmentBytes, attachmentBytes);
  assert.deepEqual(
    decryptAttachment(
      aliceOpened.direct.id,
      attachmentMessageId,
      alice.username,
      "FILE",
      attachmentKey,
      downloadedAttachmentBytes,
    ),
    attachmentPlaintext,
  );
  downloadedAttachmentBytes.fill(0);

  const oneTimeMessageId = randomUUID();
  const oneTimeEncryptedAttachment = JSON.parse(encryptAttachment(
    aliceOpened.direct.id,
    oneTimeMessageId,
    alice.username,
    "FILE",
    attachmentPlaintext,
  ));
  const oneTimeAttachmentKey = new Uint8Array(oneTimeEncryptedAttachment.key);
  const oneTimeAttachmentBytes = new Uint8Array(oneTimeEncryptedAttachment.blob);
  const oneTimeUploadResponse = await fetch(
    `${baseUrl}/v1/attachment?chat_id=${encodeURIComponent(aliceOpened.direct.id)}&message_id=${encodeURIComponent(oneTimeMessageId)}&media_type=FILE&one_time=true&delete_after_download=true`,
    {
      method: "POST",
      headers: { authorization: `Bearer ${alice.token}` },
      body: oneTimeAttachmentBytes,
    },
  );
  assert.equal(oneTimeUploadResponse.status, 200);
  const oneTimeUpload = await oneTimeUploadResponse.json();
  assert.equal(oneTimeUpload.accepted, true);
  await acceptAttachmentMetadata({
    messageId: oneTimeMessageId,
    attachmentId: oneTimeUpload.attachment_id,
    encrypted: oneTimeEncryptedAttachment,
    key: oneTimeAttachmentKey,
    oneTime: true,
    deleteAfterDownload: true,
  });
  const oneTimeDownloadUrl = `${baseUrl}/v1/attachment/${encodeURIComponent(oneTimeUpload.attachment_id)}`;
  const firstOneTimeDownload = await fetch(oneTimeDownloadUrl, {
    headers: { authorization: `Bearer ${bob.token}` },
  });
  assert.equal(firstOneTimeDownload.status, 200);
  assert.equal(firstOneTimeDownload.headers.get("content-length"), String(oneTimeAttachmentBytes.byteLength));
  assert.ok(Number(firstOneTimeDownload.headers.get("content-length")) > 0);
  const attachmentClaim = firstOneTimeDownload.headers.get("x-abyssal-attachment-claim");
  assert.match(attachmentClaim ?? "", /^[0-9a-f-]{36}$/);
  const firstOneTimeBytes = new Uint8Array(await firstOneTimeDownload.arrayBuffer());
  assert.ok(firstOneTimeBytes.byteLength > 0);
  assert.deepEqual(firstOneTimeBytes, oneTimeAttachmentBytes);
  assert.deepEqual(
    decryptAttachment(
      aliceOpened.direct.id,
      oneTimeMessageId,
      alice.username,
      "FILE",
      oneTimeAttachmentKey,
      firstOneTimeBytes,
    ),
    attachmentPlaintext,
  );
  firstOneTimeBytes.fill(0);
  const invalidClaimCompletion = await fetch(`${oneTimeDownloadUrl}/complete`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${bob.token}`,
      "x-abyssal-attachment-claim": randomUUID(),
    },
  });
  assert.equal(invalidClaimCompletion.status, 404);
  const invalidTokenCompletion = await fetch(`${oneTimeDownloadUrl}/complete`, {
    method: "POST",
    headers: {
      authorization: "Bearer invalid-token",
      "x-abyssal-attachment-claim": attachmentClaim,
    },
  });
  assert.equal(invalidTokenCompletion.status, 401);
  const wrongUserCompletion = await fetch(`${oneTimeDownloadUrl}/complete`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${alice.token}`,
      "x-abyssal-attachment-claim": attachmentClaim,
    },
  });
  assert.equal(wrongUserCompletion.status, 403);
  const completeOneTime = await fetch(`${oneTimeDownloadUrl}/complete`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${bob.token}`,
      "x-abyssal-attachment-claim": attachmentClaim,
    },
  });
  assert.equal(completeOneTime.status, 204);
  const secondOneTimeDownload = await fetch(oneTimeDownloadUrl, {
    headers: { authorization: `Bearer ${bob.token}` },
  });
  assert.equal(secondOneTimeDownload.status, 404);

  const releasableMessageId = randomUUID();
  const releasableEncryptedAttachment = JSON.parse(encryptAttachment(
    aliceOpened.direct.id,
    releasableMessageId,
    alice.username,
    "FILE",
    attachmentPlaintext,
  ));
  const releasableAttachmentKey = new Uint8Array(releasableEncryptedAttachment.key);
  const releasableAttachmentBytes = new Uint8Array(releasableEncryptedAttachment.blob);
  const releasableUploadResponse = await fetch(
    `${baseUrl}/v1/attachment?chat_id=${encodeURIComponent(aliceOpened.direct.id)}&message_id=${encodeURIComponent(releasableMessageId)}&media_type=FILE&one_time=true&delete_after_download=true`,
    {
      method: "POST",
      headers: { authorization: `Bearer ${alice.token}` },
      body: releasableAttachmentBytes,
    },
  );
  assert.equal(releasableUploadResponse.status, 200);
  const releasableUpload = await releasableUploadResponse.json();
  await acceptAttachmentMetadata({
    messageId: releasableMessageId,
    attachmentId: releasableUpload.attachment_id,
    encrypted: releasableEncryptedAttachment,
    key: releasableAttachmentKey,
    oneTime: true,
    deleteAfterDownload: true,
  });
  const releasableUrl = `${baseUrl}/v1/attachment/${encodeURIComponent(releasableUpload.attachment_id)}`;
  const interruptedDownload = await fetch(releasableUrl, {
    headers: { authorization: `Bearer ${bob.token}` },
  });
  assert.equal(interruptedDownload.status, 200);
  const interruptedClaim = interruptedDownload.headers.get("x-abyssal-attachment-claim");
  assert.match(interruptedClaim ?? "", /^[0-9a-f-]{36}$/);
  assert.ok(interruptedDownload.body);
  const interruptedReader = interruptedDownload.body.getReader();
  const interruptedChunk = await interruptedReader.read();
  assert.ok(interruptedChunk.value?.byteLength);
  await interruptedReader.cancel();
  const releaseResponse = await fetch(`${releasableUrl}/claim`, {
    method: "DELETE",
    headers: {
      authorization: `Bearer ${bob.token}`,
      "x-abyssal-attachment-claim": interruptedClaim,
    },
  });
  assert.equal(releaseResponse.status, 204);
  const retryDownload = await fetch(releasableUrl, {
    headers: { authorization: `Bearer ${bob.token}` },
  });
  assert.equal(retryDownload.status, 200);
  assert.equal(retryDownload.headers.get("content-length"), String(releasableAttachmentBytes.byteLength));
  assert.ok(Number(retryDownload.headers.get("content-length")) > 0);
  const retryClaim = retryDownload.headers.get("x-abyssal-attachment-claim");
  assert.match(retryClaim ?? "", /^[0-9a-f-]{36}$/);
  assert.deepEqual(new Uint8Array(await retryDownload.arrayBuffer()), releasableAttachmentBytes);
  const completeRetry = await fetch(`${releasableUrl}/complete`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${bob.token}`,
      "x-abyssal-attachment-claim": retryClaim,
    },
  });
  assert.equal(completeRetry.status, 204);
  const retryGone = await fetch(releasableUrl, {
    headers: { authorization: `Bearer ${bob.token}` },
  });
  assert.equal(retryGone.status, 404);

  // A stale, otherwise well-formed checkpoint must reject before fanout. The
  // ratchet rolls back, but the terminal receipt reserves that message ID, so
  // the corrected send uses a fresh ID.
  const staleMessageId = randomUUID();
  const stalePlaintext = JSON.stringify({
    kind: "text",
    id: staleMessageId,
    sender: alice.username,
    content: "stale directory stamp",
    ...directoryStamp,
  });
  const staleOutcome = await sendEncryptedMessage(
    alice,
    bob,
    aliceSocket,
    aliceOpened.direct.id,
    stalePlaintext,
    directoryStamp,
    {
      messageId: staleMessageId,
      mutate: (frame) => { frame.directory_revision = directoryStamp.directory_revision - 1; },
    },
  );
  assert.equal(staleOutcome, "REJECTED");
  const staleRetryMessageId = randomUUID();
  const staleRetryPlaintext = JSON.stringify({
    kind: "text",
    id: staleRetryMessageId,
    sender: alice.username,
    content: "stale directory stamp",
    ...directoryStamp,
  });
  const staleRetryDelivered = waitForFrame(
    bobSocket,
    (frame) => frame.type === "message" && frame.message_id === staleRetryMessageId,
  );
  const staleRetryOutcome = await sendEncryptedMessage(
    alice,
    bob,
    aliceSocket,
    aliceOpened.direct.id,
    staleRetryPlaintext,
    latestDirectoryStamp(aliceSocket),
    { messageId: staleRetryMessageId },
  );
  assert.equal(staleRetryOutcome, "ACCEPTED");
  const staleRetryFrame = await staleRetryDelivered;
  const staleRetryPlain = decryptFrame(
    bob,
    staleRetryFrame,
    latestDirectoryStamp(bobSocket),
  );
  assert.equal(staleRetryPlain.payload.content, "stale directory stamp");
  await acknowledgeFrame(bob, bobSocket, staleRetryFrame, staleRetryPlain);

  attachmentPlaintext.fill(0);
  attachmentKey.fill(0);
  attachmentBytes.fill(0);
  oneTimeAttachmentKey.fill(0);
  oneTimeAttachmentBytes.fill(0);
  releasableAttachmentKey.fill(0);
  releasableAttachmentBytes.fill(0);
  encryptedAttachment.key.fill?.(0);
  encryptedAttachment.blob.fill?.(0);
  oneTimeEncryptedAttachment.key.fill?.(0);
  oneTimeEncryptedAttachment.blob.fill?.(0);
  releasableEncryptedAttachment.key.fill?.(0);
  releasableEncryptedAttachment.blob.fill?.(0);

  const textMessageId = randomUUID();
  const textPlaintext = JSON.stringify({
    kind: "text",
    id: textMessageId,
    sender: alice.username,
    content: "live secret",
    ...directoryStamp,
  });
  const delivered = waitForFrame(
    bobSocket,
    (frame) => frame.type === "message" && frame.message_id === textMessageId,
  );
  const liveOutcome = await sendEncryptedMessage(
    alice,
    bob,
    aliceSocket,
    aliceOpened.direct.id,
    textPlaintext,
    latestDirectoryStamp(aliceSocket),
    { messageId: textMessageId },
  );
  assert.equal(liveOutcome, "ACCEPTED");
  const deliveredFrame = await delivered;
  const deliveredPlain = decryptFrame(bob, deliveredFrame, latestDirectoryStamp(bobSocket));
  assert.equal(deliveredPlain.payload.content, "live secret");
  await acknowledgeFrame(bob, bobSocket, deliveredFrame, deliveredPlain);

  const controlMessageId = randomUUID();
  const controlPlaintext = JSON.stringify({
    kind: "read_receipt",
    id: controlMessageId,
    message_id: textMessageId,
    sender: bob.username,
    ...latestDirectoryStamp(bobSocket),
  });
  const controlDelivered = waitForFrame(
    aliceSocket,
    (frame) => frame.type === "message" && frame.message_id === controlMessageId,
  );
  const controlOutcome = await sendEncryptedMessage(
    bob,
    alice,
    bobSocket,
    aliceOpened.direct.id,
    controlPlaintext,
    latestDirectoryStamp(bobSocket),
    { messageId: controlMessageId },
  );
  assert.equal(controlOutcome, "ACCEPTED");
  const controlFrame = await controlDelivered;
  const controlPlain = decryptFrame(alice, controlFrame, latestDirectoryStamp(aliceSocket));
  assert.equal(controlPlain.payload.kind, "read_receipt");
  assert.equal(controlPlain.payload.message_id, textMessageId);
  await acknowledgeFrame(alice, aliceSocket, controlFrame, controlPlain);

  const bobDisconnected = waitForFrame(
    aliceSocket,
    (frame) => frame.type === "presence" && frame.users.some(
      (user) => user.username === bob.username && user.connected === false,
    ),
  );
  bobSocket.close();
  await bobDisconnected;
  const offlineMessageId = randomUUID();
  const offlinePlaintext = JSON.stringify({
    kind: "text",
    id: offlineMessageId,
    sender: alice.username,
    content: "offline secret",
    ...directoryStamp,
  });
  const offlineOutcome = await sendEncryptedMessage(
    alice,
    bob,
    aliceSocket,
    aliceOpened.direct.id,
    offlinePlaintext,
    latestDirectoryStamp(aliceSocket),
    { messageId: offlineMessageId },
  );
  assert.equal(offlineOutcome, "ACCEPTED");

  bobReconnect = await connect(bob);
  const bobReconnectStamp = await waitForDirectoryStamp(bobReconnect);
  assert.deepEqual(bobReconnectStamp, directoryStamp);
  const replayed = waitForFrame(
    bobReconnect,
    (frame) => frame.type === "message" && frame.message_id === offlineMessageId,
  );
  sendControlFrame(bobReconnect, { type: "join", chat_id: aliceOpened.direct.id });
  const replayedFrame = await replayed;
  const replayedPlain = decryptFrame(bob, replayedFrame, bobReconnectStamp);
  assert.equal(replayedPlain.payload.content, "offline secret");
  await acknowledgeFrame(bob, bobReconnect, replayedFrame, replayedPlain);

  const unauthorizedUploadMessageId = randomUUID();
  const unauthorizedUpload = await fetch(
    `${baseUrl}/v1/attachment?chat_id=dm_guessed&message_id=${encodeURIComponent(unauthorizedUploadMessageId)}&media_type=FILE`,
    {
      method: "POST",
      headers: { authorization: `Bearer ${alice.token}` },
      body: new Uint8Array([1, 2, 3]),
    },
  );
  assert.equal(unauthorizedUpload.status, 403);

  const aliceDisconnected = waitForFrame(
    bobReconnect,
    (frame) => frame.type === "presence" && frame.users.some(
      (user) => user.username === alice.username && user.connected === false,
    ),
  );
  aliceSocket.close();
  await aliceDisconnected;
  aliceSocket = await connect(alice);
  await waitForDirectoryStamp(aliceSocket);
  await runMlsIntegration(alice, bob, aliceSocket, bobReconnect);
} finally {
  aliceSocket.close();
  bobSocket.close();
  bobReconnect?.close();
  alice.identity.free();
  bob.identity.free();
}

assert.equal(releasedPrekeysAwaitingReuse.size, 0);

console.log(
  "relay integration passed: OPAQUE auth, v9 E2EE DM, v10 MLS rooms, offline recovery/replay, and access control",
);

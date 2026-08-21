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
assert.ok(baseUrl, "ABYSSAL_TEST_BASE_URL is required");
assert.ok(aliceCode, "ABYSSAL_TEST_CODE_A is required");
assert.ok(bobCode, "ABYSSAL_TEST_CODE_B is required");
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
      frame = JSON.parse(String(event.data));
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
      frame = JSON.parse(String(event.data));
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
    data: JSON.stringify({ type: "message_result", message_id: "self-second", accepted: true }),
  });
  assert.equal(await second.promise, "ACCEPTED");
  socket.dispatch("message", {
    data: JSON.stringify({ type: "message_result", message_id: "self-first", accepted: true }),
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
        frame = JSON.parse(raw);
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
    headers: { authorization: `Bearer ${account.token}` },
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

function connectWithTicket(ticket, expectedNodeId) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(
      `${baseUrl.replace(/^http/, "ws")}/v1/ws`,
      ["abyssal-v1", `ticket.${ticket}`],
    );
    const timeout = setTimeout(() => reject(new Error("WebSocket connection timed out")), 5_000);
    socket.addEventListener("open", () => {
      clearTimeout(timeout);
      installDirectoryTracker(socket, expectedNodeId);
      resolve(socket);
    }, { once: true });
    socket.addEventListener("error", () => {
      clearTimeout(timeout);
      reject(new Error("WebSocket connection failed"));
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
  socket.send(JSON.stringify({
    type: "prekey_lease",
    chat_id: chatId,
    message_id: messageId,
    recipient_username: recipientUsername,
  }));
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
  socket.send(JSON.stringify({
    type: "prekey_lease_release",
    chat_id: lease.chat_id,
    message_id: lease.message_id,
    recipient_username: lease.recipient_username,
    prekey_id: lease.prekey_id,
  }));
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
      socket.send(JSON.stringify(acknowledgement));
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

const alice = await register(aliceCode, "alice-password");
const bob = await register(bobCode, "bob-password");
assert.equal(await opaqueStartStatus(aliceCode, "alice-password"), 409);
assert.equal(await opaqueStartStatus(aliceCode, "other-password"), 409);

const aliceTicket = await requestWsTicket(alice);
await expectWebSocketRejected(["abyssal-v1", `bearer.${alice.token}`]);
const aliceSocket = await connectWithTicket(aliceTicket, alice.node_id);
await expectWebSocketRejected(["abyssal-v1", `ticket.${aliceTicket}`]);
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
  aliceSocket.send(JSON.stringify({ type: "open_direct", peer_username: bob.username }));
  const [aliceOpened, bobOpened] = await Promise.all([aliceDirect, bobDirect]);
  assert.equal(aliceOpened.direct.id, bobOpened.direct.id);
  assert.match(aliceOpened.direct.id, /^dm_[a-f0-9]{32}$/);

  aliceSocket.send(JSON.stringify({ type: "join", chat_id: aliceOpened.direct.id }));
  bobSocket.send(JSON.stringify({ type: "join", chat_id: aliceOpened.direct.id }));

  // Empty directory evidence is a deliberately rejected first-contact frame.
  // Its staged ratchet must roll back and its lease must be released for the
  // exact valid retry below to reuse.
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
  const missingStampRetryDelivered = waitForFrame(
    bobSocket,
    (frame) => frame.type === "message" && frame.message_id === missingStampMessageId,
  );
  const missingStampRetryOutcome = await sendEncryptedMessage(
    alice,
    bob,
    aliceSocket,
    aliceOpened.direct.id,
    missingStampPlaintext,
    latestDirectoryStamp(aliceSocket),
    { messageId: missingStampMessageId },
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
  // same message ID then succeeds after the native ratchet rollback.
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
  const staleRetryDelivered = waitForFrame(
    bobSocket,
    (frame) => frame.type === "message" && frame.message_id === staleMessageId,
  );
  const staleRetryOutcome = await sendEncryptedMessage(
    alice,
    bob,
    aliceSocket,
    aliceOpened.direct.id,
    stalePlaintext,
    latestDirectoryStamp(aliceSocket),
    { messageId: staleMessageId },
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
  bobReconnect.send(JSON.stringify({ type: "join", chat_id: aliceOpened.direct.id }));
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
} finally {
  aliceSocket.close();
  bobSocket.close();
  bobReconnect?.close();
  alice.identity.free();
  bob.identity.free();
}

assert.equal(releasedPrekeysAwaitingReuse.size, 0);

console.log("relay integration passed: OPAQUE auth, E2EE DM, offline replay, and access control");

import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import {
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

const encode = (value) => Buffer.from(value).toString("base64url");
const decode = (value) => new Uint8Array(Buffer.from(value, "base64url"));

async function register(code, password) {
  const passwordBytes = encoder.encode(password);
  const opaque = JSON.parse(opaqueClientStart(passwordBytes));
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

  const finished = JSON.parse(opaqueClientFinishRegistration(
    passwordBytes,
    new Uint8Array(opaque.registration_state),
    decode(start.response_b64),
  ));
  const identity = WasmE2eeSession.create(new Uint8Array(finished.export_key));
  const context = encoder.encode(`ABYSSAL_IDENTITY_V1:${start.node_id}:${code.toUpperCase()}`);
  const identityPublic = identity.publicKey();
  const identityEnvelope = identity.sealIdentity(new Uint8Array(finished.export_key), context);
  const finishResponse = await fetch(`${baseUrl}/v2/account/finish`, {
    method: "POST",
    cache: "no-store",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      handshake_id: start.handshake_id,
      registration_upload_b64: encode(finished.registration_upload),
      identity_public_b64: encode(identityPublic),
      identity_envelope_b64: encode(identityEnvelope),
    }),
  });
  assert.equal(finishResponse.status, 200);
  const account = await finishResponse.json();
  assert.equal(account.accepted, true);
  assert.ok(account.token);
  assert.ok(account.username);
  assert.equal(account.identity_public_b64, encode(identityPublic));

  passwordBytes.fill(0);
  context.fill(0);
  identityEnvelope.fill(0);
  opaque.registration_state.fill(0);
  opaque.registration_request.fill(0);
  opaque.login_state.fill(0);
  opaque.credential_request.fill(0);
  finished.export_key.fill(0);
  finished.registration_upload.fill(0);
  return { ...account, identity };
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

function connect(token) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(
      `${baseUrl.replace(/^http/, "ws")}/v1/ws`,
      ["abyssal-v1", `bearer.${token}`],
    );
    const timeout = setTimeout(() => reject(new Error("WebSocket connection timed out")), 5_000);
    socket.addEventListener("open", () => {
      clearTimeout(timeout);
      resolve(socket);
    }, { once: true });
    socket.addEventListener("error", () => {
      clearTimeout(timeout);
      reject(new Error("WebSocket connection failed"));
    }, { once: true });
  });
}

function waitForFrame(socket, predicate) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      socket.removeEventListener("message", onMessage);
      reject(new Error("Expected relay frame timed out"));
    }, 5_000);
    const onMessage = (event) => {
      const frame = JSON.parse(String(event.data));
      if (!predicate(frame)) return;
      clearTimeout(timeout);
      socket.removeEventListener("message", onMessage);
      resolve(frame);
    };
    socket.addEventListener("message", onMessage);
  });
}

function encryptedFrame(sender, recipient, chatId, text) {
  const messageId = randomUUID();
  const payload = JSON.parse(sender.identity.encrypt(
    chatId,
    messageId,
    sender.username,
    encoder.encode(text),
    JSON.stringify([{
      username: recipient.username,
      public_key: [...recipient.identity.publicKey()],
    }]),
  ));
  return {
    type: "message",
    chat_id: chatId,
    version: payload.version,
    message_id: payload.message_id,
    nonce_b64: encode(payload.nonce),
    ciphertext_b64: encode(payload.ciphertext),
    signature_b64: encode(payload.signature),
    envelopes: payload.envelopes.map((envelope) => ({
      recipient_username: envelope.username,
      wrapped_key_b64: encode(envelope.wrapped_key),
    })),
  };
}

function decryptFrame(recipient, frame) {
  return decoder.decode(recipient.identity.decrypt(
    frame.chat_id,
    frame.message_id,
    frame.sender_username,
    decode(frame.sender_public_key_b64),
    decode(frame.nonce_b64),
    decode(frame.ciphertext_b64),
    decode(frame.signature_b64),
    decode(frame.wrapped_key_b64),
    recipient.username,
  ));
}

const alice = await register(aliceCode, "alice-password");
const bob = await register(bobCode, "bob-password");
assert.equal(await opaqueStartStatus(aliceCode, "alice-password"), 409);
assert.equal(await opaqueStartStatus(aliceCode, "other-password"), 409);

const aliceSocket = await connect(alice.token);
let bobSocket = await connect(bob.token);
let bobReconnect;
try {
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
  const delivered = waitForFrame(
    bobSocket,
    (frame) => frame.type === "message" && frame.chat_id === aliceOpened.direct.id,
  );
  aliceSocket.send(JSON.stringify(encryptedFrame(alice, bob, aliceOpened.direct.id, "live secret")));
  assert.equal(decryptFrame(bob, await delivered), "live secret");

  const bobDisconnected = waitForFrame(
    aliceSocket,
    (frame) => frame.type === "presence" && frame.users.some(
      (user) => user.username === bob.username && user.connected === false,
    ),
  );
  bobSocket.close();
  await bobDisconnected;
  aliceSocket.send(JSON.stringify(encryptedFrame(alice, bob, aliceOpened.direct.id, "offline secret")));

  bobReconnect = await connect(bob.token);
  const replayed = waitForFrame(
    bobReconnect,
    (frame) => frame.type === "message" && frame.chat_id === aliceOpened.direct.id,
  );
  bobReconnect.send(JSON.stringify({ type: "join", chat_id: aliceOpened.direct.id }));
  assert.equal(decryptFrame(bob, await replayed), "offline secret");

  const unauthorizedUpload = await fetch(`${baseUrl}/v1/attachment?chat_id=dm_guessed&media_type=FILE`, {
    method: "POST",
    headers: { authorization: `Bearer ${alice.token}` },
    body: new Uint8Array([1, 2, 3]),
  });
  assert.equal(unauthorizedUpload.status, 403);
} finally {
  aliceSocket.close();
  bobSocket.close();
  bobReconnect?.close();
  alice.identity.free();
  bob.identity.free();
}

console.log("relay integration passed: OPAQUE auth, E2EE DM, offline replay, and access control");

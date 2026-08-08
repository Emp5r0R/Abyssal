import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
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
  const context = encoder.encode(`ABYSSAL_IDENTITY_V2:${start.node_id}:${code.toUpperCase()}`);
  const identityPublic = identity.publicKey();
  const identityPrekeyId = identity.prekeyId();
  const identityEnvelope = identity.sealIdentity(new Uint8Array(finished.export_key), context);
  const finishResponse = await fetch(`${baseUrl}/v2/account/finish`, {
    method: "POST",
    cache: "no-store",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      handshake_id: start.handshake_id,
      registration_upload_b64: encode(finished.registration_upload),
      identity_public_b64: encode(identityPublic),
      identity_prekey_id: identityPrekeyId,
      identity_envelope_b64: encode(identityEnvelope),
    }),
  });
  assert.equal(finishResponse.status, 200);
  const account = await finishResponse.json();
  assert.equal(account.accepted, true);
  assert.ok(account.token);
  assert.ok(account.username);
  assert.equal(account.identity_public_b64, encode(identityPublic));
  assert.equal(account.identity_prekey_id, identityPrekeyId);

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
      prekey_id: recipient.identity.prekeyId(),
    }]),
  ));
  return {
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
    envelopes: payload.envelopes.map((envelope) => ({
      recipient_username: envelope.username,
      wrapped_key_b64: encode(envelope.wrapped_key),
      prekey_id: envelope.prekey_id,
      is_prekey: envelope.is_prekey,
      signature_b64: encode(envelope.signature),
    })),
  };
}

function decryptFrame(recipient, frame) {
  const decrypted = JSON.parse(recipient.identity.decrypt(
    frame.chat_id,
    frame.message_id,
    frame.sender_username,
    decode(frame.sender_public_key_b64),
    frame.version,
    decode(frame.identity_public_b64),
    decode(frame.nonce_b64),
    decode(frame.ciphertext_b64),
    decode(frame.signature_b64),
    decode(frame.wrapped_key_b64),
    frame.prekey_id,
    frame.is_prekey,
    recipient.username,
  ));
  return {
    text: decoder.decode(new Uint8Array(decrypted.plaintext)),
    stateRevision: decrypted.state_revision,
    identityEnvelope: new Uint8Array(decrypted.identity_envelope),
    identityPublic: new Uint8Array(decrypted.identity_public),
    prekeyId: decrypted.prekey_id,
  };
}

function acknowledgeFrame(socket, frame, decrypted) {
  socket.send(JSON.stringify({
    type: "message_ack",
    chat_id: frame.chat_id,
    message_id: frame.message_id,
    sender_username: frame.sender_username,
    state_revision: decrypted.stateRevision,
    identity_envelope_b64: encode(decrypted.identityEnvelope),
    identity_public_b64: encode(decrypted.identityPublic),
    prekey_id: decrypted.prekeyId,
    used_prekey_id: frame.prekey_id,
  }));
  decrypted.identityEnvelope.fill(0);
  decrypted.identityPublic.fill(0);
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
    `${baseUrl}/v1/attachment?chat_id=${encodeURIComponent(aliceOpened.direct.id)}&media_type=FILE`,
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

  const downloadResponse = await fetch(
    `${baseUrl}/v1/attachment/${encodeURIComponent(upload.attachment_id)}`,
    { headers: { authorization: `Bearer ${bob.token}` } },
  );
  assert.equal(downloadResponse.status, 200);
  assert.equal(downloadResponse.headers.get("x-abyssal-attachment-claim"), null);
  assert.equal(downloadResponse.headers.get("content-length"), String(attachmentBytes.byteLength));
  assert.ok(Number(downloadResponse.headers.get("content-length")) > 0);
  const downloadedAttachmentBytes = new Uint8Array(await downloadResponse.arrayBuffer());
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

  const oneTimeUploadResponse = await fetch(
    `${baseUrl}/v1/attachment?chat_id=${encodeURIComponent(aliceOpened.direct.id)}&media_type=FILE&one_time=true&delete_after_download=true`,
    {
      method: "POST",
      headers: { authorization: `Bearer ${alice.token}` },
      body: attachmentBytes,
    },
  );
  assert.equal(oneTimeUploadResponse.status, 200);
  const oneTimeUpload = await oneTimeUploadResponse.json();
  assert.equal(oneTimeUpload.accepted, true);
  const oneTimeDownloadUrl = `${baseUrl}/v1/attachment/${encodeURIComponent(oneTimeUpload.attachment_id)}`;
  const firstOneTimeDownload = await fetch(oneTimeDownloadUrl, {
    headers: { authorization: `Bearer ${bob.token}` },
  });
  assert.equal(firstOneTimeDownload.status, 200);
  assert.equal(firstOneTimeDownload.headers.get("content-length"), String(attachmentBytes.byteLength));
  assert.ok(Number(firstOneTimeDownload.headers.get("content-length")) > 0);
  const attachmentClaim = firstOneTimeDownload.headers.get("x-abyssal-attachment-claim");
  assert.match(attachmentClaim ?? "", /^[0-9a-f-]{36}$/);
  const firstOneTimeBytes = new Uint8Array(await firstOneTimeDownload.arrayBuffer());
  assert.ok(firstOneTimeBytes.byteLength > 0);
  assert.deepEqual(firstOneTimeBytes, attachmentBytes);
  assert.deepEqual(
    decryptAttachment(
      aliceOpened.direct.id,
      attachmentMessageId,
      alice.username,
      "FILE",
      attachmentKey,
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

  const releasableUploadResponse = await fetch(
    `${baseUrl}/v1/attachment?chat_id=${encodeURIComponent(aliceOpened.direct.id)}&media_type=FILE&one_time=true&delete_after_download=true`,
    {
      method: "POST",
      headers: { authorization: `Bearer ${alice.token}` },
      body: attachmentBytes,
    },
  );
  assert.equal(releasableUploadResponse.status, 200);
  const releasableUpload = await releasableUploadResponse.json();
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
  assert.equal(retryDownload.headers.get("content-length"), String(attachmentBytes.byteLength));
  assert.ok(Number(retryDownload.headers.get("content-length")) > 0);
  const retryClaim = retryDownload.headers.get("x-abyssal-attachment-claim");
  assert.match(retryClaim ?? "", /^[0-9a-f-]{36}$/);
  assert.deepEqual(new Uint8Array(await retryDownload.arrayBuffer()), attachmentBytes);
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

  attachmentPlaintext.fill(0);
  attachmentKey.fill(0);
  attachmentBytes.fill(0);

  const delivered = waitForFrame(
    bobSocket,
    (frame) => frame.type === "message" && frame.chat_id === aliceOpened.direct.id,
  );
  aliceSocket.send(JSON.stringify(encryptedFrame(alice, bob, aliceOpened.direct.id, "live secret")));
  const deliveredFrame = await delivered;
  const deliveredPlain = decryptFrame(bob, deliveredFrame);
  assert.equal(deliveredPlain.text, "live secret");
  acknowledgeFrame(bobSocket, deliveredFrame, deliveredPlain);

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
  const replayedFrame = await replayed;
  const replayedPlain = decryptFrame(bob, replayedFrame);
  assert.equal(replayedPlain.text, "offline secret");
  acknowledgeFrame(bobReconnect, replayedFrame, replayedPlain);

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

import assert from "node:assert/strict";

const baseUrl = process.env.ABYSSAL_TEST_BASE_URL;
assert.ok(baseUrl, "ABYSSAL_TEST_BASE_URL is required");

async function enter(code, password) {
  const response = await fetch(`${baseUrl}/v1/account/enter`, {
    method: "POST",
    cache: "no-store",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ code, password }),
  });
  assert.equal(response.status, 200);
  assert.match(response.headers.get("cache-control") ?? "", /no-store/);
  const body = await response.json();
  assert.equal(body.accepted, true);
  assert.ok(body.token);
  assert.ok(body.username);
  return body;
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

const alice = await enter("ABYS-ALICE-0001", "alice-password");
const bob = await enter("ABYS-BOB-000002", "bob-password");

const concurrentLogin = await fetch(`${baseUrl}/v1/account/enter`, {
  method: "POST",
  cache: "no-store",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ code: "ABYS-ALICE-0001", password: "alice-password" }),
});
assert.equal(concurrentLogin.status, 409);

const duplicate = await fetch(`${baseUrl}/v1/account/create`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ code: "ABYS-ALICE-0001", password: "other-password" }),
});
assert.equal(duplicate.status, 409);

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
  aliceSocket.send(JSON.stringify({
    type: "message",
    chat_id: aliceOpened.direct.id,
    payload_b64: "Y2lwaGVydGV4dA==",
  }));
  const message = await delivered;
  assert.equal(message.sender_username, alice.username);
  assert.equal(message.payload_b64, "Y2lwaGVydGV4dA==");

  const bobDisconnected = waitForFrame(
    aliceSocket,
    (frame) => frame.type === "presence" && frame.users.some(
      (user) => user.username === bob.username && user.connected === false,
    ),
  );
  bobSocket.close();
  await bobDisconnected;
  aliceSocket.send(JSON.stringify({
    type: "message",
    chat_id: aliceOpened.direct.id,
    payload_b64: "b2ZmbGluZS1jaXBoZXJ0ZXh0",
  }));

  bobReconnect = await connect(bob.token);
  const replayed = waitForFrame(
    bobReconnect,
    (frame) => frame.type === "message" && frame.chat_id === aliceOpened.direct.id,
  );
  bobReconnect.send(JSON.stringify({ type: "join", chat_id: aliceOpened.direct.id }));
  const offlineMessage = await replayed;
  assert.equal(offlineMessage.sender_username, alice.username);
  assert.equal(offlineMessage.payload_b64, "b2ZmbGluZS1jaXBoZXJ0ZXh0");

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
}

console.log("relay integration passed: account lock, canonical DM, offline replay, routing, and access control");

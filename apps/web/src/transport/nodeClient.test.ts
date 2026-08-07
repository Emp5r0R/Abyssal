import { afterEach, describe, expect, it, vi } from "vitest";
import type { AccountSession, IncomingFrame, NodeEndpoint } from "../domain/types";
import { bytesToBase64 } from "../security/crypto";
import {
  finishOpaqueAccount,
  RelaySocket,
  revokeSession,
  startOpaqueAccount,
} from "./nodeClient";

const endpoint: NodeEndpoint = {
  apiBaseUrl: "https://node.example",
  wsBaseUrl: "wss://node.example",
  displayHost: "node.example",
};

const session: AccountSession = {
  token: "token-123",
  nodeId: "node-1",
  username: "Alice",
  maxRoomsPerUser: 3,
  sessionInactivitySec: 900,
  endpoint,
  created: false,
  identityPublicKey: new Uint8Array(128),
  identityPrekeyId: "test-prekey",
};

afterEach(() => {
  vi.restoreAllMocks();
});

describe("account transport", () => {
  it("starts OPAQUE without sending password or browser credentials", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({
      accepted: true,
      mode: "login",
      handshake_id: "76f1b4b6-6dd8-4352-80b9-76fa0150484c",
      response_b64: "AQID",
      node_id: "node-1",
    }), { status: 200, headers: { "Content-Type": "application/json" } }));

    await expect(startOpaqueAccount(
      endpoint,
      " CODE-1234567 ",
      new Uint8Array([1]),
      new Uint8Array([2]),
    )).resolves.toMatchObject({
      mode: "login",
      node_id: "node-1",
    });
    expect(fetchMock).toHaveBeenCalledWith("https://node.example/v2/account/start", expect.objectContaining({
      method: "POST",
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
      body: JSON.stringify({
        code: "CODE-1234567",
        registration_request_b64: "AQ",
        credential_request_b64: "Ag",
      }),
    }));
    expect(JSON.stringify(fetchMock.mock.calls)).not.toContain("password1");
  });

  it("uses the same vague error for malformed and rejected responses", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("not-json", { status: 401 }));
    await expect(startOpaqueAccount(
      endpoint,
      "CODE-1234567",
      new Uint8Array([1]),
      new Uint8Array([2]),
    )).rejects.toThrow("Wrong information");
  });

  it("finishes OPAQUE and validates returned identity material", async () => {
    const publicKey = new Uint8Array(128).fill(7);
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({
      accepted: true,
      created: true,
      token: "token-123",
      node_id: "node-1",
      username: "Alice",
      max_rooms_per_user: 3,
      session_inactivity_sec: 900,
      identity_public_b64: bytesToBase64(publicKey),
      identity_prekey_id: "test-prekey",
      identity_envelope_b64: "AQID",
    }), { status: 200, headers: { "Content-Type": "application/json" } }));

    await expect(finishOpaqueAccount(endpoint, {
      handshakeId: "76f1b4b6-6dd8-4352-80b9-76fa0150484c",
      credentialFinalization: new Uint8Array([9]),
    })).resolves.toMatchObject({ username: "Alice", identityPublicKey: publicKey });
    expect(fetchMock).toHaveBeenCalledWith("https://node.example/v2/account/finish", expect.objectContaining({
      method: "POST",
      credentials: "omit",
    }));
  });

  it("revokes a token with a no-store bearer request", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 204 }));
    await revokeSession(session);
    expect(fetchMock).toHaveBeenCalledWith("https://node.example/v1/account/logout", expect.objectContaining({
      method: "POST",
      cache: "no-store",
      credentials: "omit",
      keepalive: true,
      headers: { Authorization: "Bearer token-123" },
    }));
  });
});

describe("RelaySocket", () => {
  it("uses subprotocol authentication and emits canonical DM commands", () => {
    const original = globalThis.WebSocket;
    const sockets: FakeWebSocket[] = [];
    class TestWebSocket extends FakeWebSocket {
      constructor(url: string, protocols: string[]) {
        super(url, protocols);
        sockets.push(this);
      }
    }
    Object.assign(TestWebSocket, { OPEN: 1, CLOSED: 3 });
    globalThis.WebSocket = TestWebSocket as unknown as typeof WebSocket;
    const frames: IncomingFrame[] = [];
    const states: string[] = [];

    try {
      const relay = new RelaySocket(session, (frame) => frames.push(frame), (state) => states.push(state));
      relay.connect();
      const socket = sockets[0];
      expect(socket.url).toBe("wss://node.example/v1/ws");
      expect(socket.protocols).toEqual(["abyssal-v1", "bearer.token-123"]);
      socket.readyState = 1;
      socket.onopen?.(new Event("open"));
      expect(relay.openDirect("Bob")).toBe(true);
      expect(relay.acknowledge("dm_123", "message_1", "Alice", {
        revision: 2,
        envelope: new Uint8Array([2, 3, 4]),
        identityPublicKey: new Uint8Array(128).fill(7),
        prekeyId: "test-prekey",
      }, "used-prekey")).toBe(true);
      expect(socket.sent).toEqual([
        JSON.stringify({ type: "open_direct", peer_username: "Bob" }),
        JSON.stringify({
          type: "message_ack",
          chat_id: "dm_123",
          message_id: "message_1",
          sender_username: "Alice",
          state_revision: 2,
          identity_envelope_b64: "AgME",
          identity_public_b64: bytesToBase64(new Uint8Array(128).fill(7)),
          prekey_id: "test-prekey",
          used_prekey_id: "used-prekey",
        }),
      ]);

      socket.onmessage?.(new MessageEvent("message", { data: JSON.stringify({
        type: "direct_opened",
        direct: { id: "dm_123", peer_username: "Bob" },
      }) }));
      socket.onmessage?.(new MessageEvent("message", { data: "invalid" }));
      expect(frames).toHaveLength(1);
      expect(states).toEqual(["connecting", "connected"]);
      relay.close();
    } finally {
      globalThis.WebSocket = original;
    }
  });
});

class FakeWebSocket {
  static OPEN = 1;
  readonly sent: string[] = [];
  readyState = 0;
  onopen: ((event: Event) => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;
  onclose: ((event: CloseEvent) => void) | null = null;

  constructor(readonly url: string, readonly protocols: string[]) {}

  send(value: string): void {
    this.sent.push(value);
  }

  close(): void {
    this.readyState = 3;
  }
}

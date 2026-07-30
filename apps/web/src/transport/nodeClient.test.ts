import { afterEach, describe, expect, it, vi } from "vitest";
import type { AccountSession, IncomingFrame, NodeEndpoint } from "../domain/types";
import { enterAccount, RelaySocket, revokeSession } from "./nodeClient";

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
};

afterEach(() => {
  vi.restoreAllMocks();
});

describe("account transport", () => {
  it("enters an account without browser credentials or referrer leakage", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({
      accepted: true,
      created: true,
      token: "token-123",
      node_id: "node-1",
      username: "Alice",
      max_rooms_per_user: 3,
      session_inactivity_sec: 900,
    }), { status: 200, headers: { "Content-Type": "application/json" } }));

    await expect(enterAccount(endpoint, " CODE-1234567 ", "password1")).resolves.toMatchObject({
      token: "token-123",
      username: "Alice",
      created: true,
    });
    expect(fetchMock).toHaveBeenCalledWith("https://node.example/v1/account/enter", expect.objectContaining({
      method: "POST",
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
      body: JSON.stringify({ code: "CODE-1234567", password: "password1" }),
    }));
  });

  it("uses the same vague error for malformed and rejected responses", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("not-json", { status: 401 }));
    await expect(enterAccount(endpoint, "CODE-1234567", "password1")).rejects.toThrow("Wrong information");
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
      expect(socket.sent).toEqual([JSON.stringify({ type: "open_direct", peer_username: "Bob" })]);

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

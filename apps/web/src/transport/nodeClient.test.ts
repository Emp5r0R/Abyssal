import { afterEach, describe, expect, it, vi } from "vitest";
import type { AccountSession, IncomingFrame, NodeEndpoint } from "../domain/types";
import { bytesToBase64 } from "../security/crypto";
import {
  finishOpaqueAccount,
  RelaySocket,
  revokeSession,
  startOpaqueAccount,
  downloadEncryptedAttachment,
  completeAttachmentDownload,
  decryptAndCompleteAttachment,
  uploadEncryptedAttachment,
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

const CLAIM_TRUNCATED = "11111111-1111-4111-8111-111111111111";
const CLAIM_EXTRA = "22222222-2222-4222-8222-222222222222";
const CLAIM_EMPTY = "33333333-3333-4333-8333-333333333333";
const CLAIM_PRIMARY = "44444444-4444-4444-8444-444444444444";
const CLAIM_FAILED = "55555555-5555-4555-8555-555555555555";
const CLAIM_DECRYPT = "66666666-6666-4666-8666-666666666666";

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

  it("streams bounded attachment bodies and rejects an oversized declaration", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(
      new Uint8Array([1, 2, 3, 4]),
      { status: 200, headers: { "content-length": "4" } },
    ));
    await expect(downloadEncryptedAttachment(session, "attachment-1")).resolves.toEqual(
      { bytes: new Uint8Array([1, 2, 3, 4]) },
    );
    expect(fetchMock).toHaveBeenCalledWith(
      "https://node.example/v1/attachment/attachment-1",
      expect.objectContaining({ cache: "no-store", credentials: "omit" }),
    );

    fetchMock.mockResolvedValue(new Response(new Uint8Array([1]), {
      status: 200,
      headers: { "content-length": "999999999999999999999" },
    }));
    await expect(downloadEncryptedAttachment(session, "attachment-2")).rejects.toThrow(
      "Attachment unavailable",
    );
  });

  it("requires Content-Length and rejects truncated or extra encrypted bytes", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(new Uint8Array([1]), { status: 200 }))
      .mockResolvedValueOnce(new Response(new Uint8Array([1, 2]), {
        status: 200,
        headers: {
          "content-length": "4",
          "X-Abyssal-Attachment-Claim": CLAIM_TRUNCATED,
        },
      }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(new Response(new Uint8Array([1, 2, 3]), {
        status: 200,
        headers: {
          "content-length": "2",
          "X-Abyssal-Attachment-Claim": CLAIM_EXTRA,
        },
      }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));

    await expect(downloadEncryptedAttachment(session, "missing-length")).rejects.toThrow(
      "Attachment unavailable",
    );
    await expect(downloadEncryptedAttachment(session, "truncated")).rejects.toThrow(
      "Attachment unavailable",
    );
    await expect(downloadEncryptedAttachment(session, "extra")).rejects.toThrow(
      "Attachment unavailable",
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      3,
      "https://node.example/v1/attachment/truncated/claim",
      expect.objectContaining({ method: "DELETE" }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      5,
      "https://node.example/v1/attachment/extra/claim",
      expect.objectContaining({ method: "DELETE" }),
    );
  });

  it("rejects an empty attachment and releases a reserved claim", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(new Uint8Array(0), {
        status: 200,
        headers: {
          "content-length": "0",
          "X-Abyssal-Attachment-Claim": CLAIM_EMPTY,
        },
      }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));

    await expect(downloadEncryptedAttachment(session, "empty attachment")).rejects.toThrow(
      "Attachment unavailable",
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      "https://node.example/v1/attachment/empty%20attachment/claim",
      expect.objectContaining({
        method: "DELETE",
        cache: "no-store",
        credentials: "omit",
        referrerPolicy: "no-referrer",
        headers: {
          Authorization: "Bearer token-123",
          "X-Abyssal-Attachment-Claim": CLAIM_EMPTY,
        },
      }),
    );
  });

  it("returns an optional claim without changing exact encrypted bytes", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(
      new Uint8Array([0, 1, 2, 255]),
      {
        status: 200,
        headers: {
          "content-length": "4",
          "X-Abyssal-Attachment-Claim": CLAIM_PRIMARY,
        },
      },
    ));

    await expect(downloadEncryptedAttachment(session, "attachment-1")).resolves.toEqual({
      bytes: new Uint8Array([0, 1, 2, 255]),
      claim: CLAIM_PRIMARY,
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("completes a claim with the authenticated bearer and claim header", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 204 }));

    await expect(completeAttachmentDownload(session, "attachment/1", CLAIM_PRIMARY)).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledWith(
      "https://node.example/v1/attachment/attachment%2F1/complete",
      expect.objectContaining({
        method: "POST",
        cache: "no-store",
        credentials: "omit",
        referrerPolicy: "no-referrer",
        headers: {
          Authorization: "Bearer token-123",
          "X-Abyssal-Attachment-Claim": CLAIM_PRIMARY,
        },
      }),
    );
  });

  it("rejects noncanonical attachment claims before sending a mutation", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch");

    await expect(completeAttachmentDownload(session, "attachment-1", "claim-123"))
      .rejects.toThrow("Attachment unavailable");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("releases a claim when authenticated completion fails", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(null, { status: 409 }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    const plaintext = new Uint8Array([4, 5, 6]);

    await expect(decryptAndCompleteAttachment(
      session,
      "attachment-1",
      { bytes: new Uint8Array([1]), claim: CLAIM_FAILED },
      () => plaintext,
    )).rejects.toThrow("Attachment unavailable");
    expect(plaintext).toEqual(new Uint8Array(3));
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      "https://node.example/v1/attachment/attachment-1/claim",
      expect.objectContaining({ method: "DELETE" }),
    );
  });

  it("releases a claim when authenticated decryption fails", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 204 }));

    await expect(decryptAndCompleteAttachment(
      session,
      "attachment-1",
      { bytes: new Uint8Array([1]), claim: CLAIM_DECRYPT },
      () => { throw new Error("bad ciphertext"); },
    )).rejects.toThrow("bad ciphertext");
    expect(fetchMock).toHaveBeenCalledWith(
      "https://node.example/v1/attachment/attachment-1/claim",
      expect.objectContaining({ method: "DELETE" }),
    );
  });

  it("rejects empty plaintext before completing and releases a destructive claim", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 204 }));
    const plaintext = new Uint8Array(0);

    await expect(decryptAndCompleteAttachment(
      session,
      "attachment-empty",
      { bytes: new Uint8Array([1]), claim: CLAIM_FAILED },
      () => plaintext,
      { expectedBytes: 1, maxBytes: 20 },
    )).rejects.toThrow("Attachment unavailable");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith(
      "https://node.example/v1/attachment/attachment-empty/claim",
      expect.objectContaining({ method: "DELETE" }),
    );
  });

  it("rejects authenticated plaintext whose metadata size is mismatched or over the media limit", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 204 }));
    const plaintext = new Uint8Array([1, 2, 3, 4]);

    await expect(decryptAndCompleteAttachment(
      session,
      "attachment-mismatch",
      { bytes: new Uint8Array([1]), claim: CLAIM_FAILED },
      () => plaintext,
      { expectedBytes: 3, maxBytes: 4 },
    )).rejects.toThrow("Attachment unavailable");
    await expect(decryptAndCompleteAttachment(
      session,
      "attachment-oversize",
      { bytes: new Uint8Array([1]), claim: CLAIM_DECRYPT },
      () => plaintext,
      { expectedBytes: 4, maxBytes: 3 },
    )).rejects.toThrow("Attachment unavailable");
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls.every(([url, init]) => (
      String(url).endsWith("/claim") && (init as RequestInit).method === "DELETE"
    ))).toBe(true);
  });

  it("completes a destructive claim only after exact plaintext policy validation", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 204 }));
    const plaintext = new Uint8Array([9, 8, 7]);

    await expect(decryptAndCompleteAttachment(
      session,
      "attachment-exact",
      { bytes: new Uint8Array([1]), claim: CLAIM_PRIMARY },
      () => plaintext,
      { expectedBytes: 3, maxBytes: 3 },
    )).resolves.toBe(plaintext);
    expect(fetchMock).toHaveBeenCalledWith(
      "https://node.example/v1/attachment/attachment-exact/complete",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("does not complete or release non-destructive downloads", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch");
    const plaintext = new Uint8Array([7, 8]);

    await expect(decryptAndCompleteAttachment(
      session,
      "attachment-1",
      { bytes: new Uint8Array([1]) },
      () => plaintext,
    )).resolves.toBe(plaintext);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("passes the encrypted upload view to XHR without making a full copy", async () => {
    const original = globalThis.XMLHttpRequest;
    let sent: unknown;
    class TestXmlHttpRequest {
      readonly upload = { onprogress: null as ((event: ProgressEvent) => void) | null };
      responseType = "";
      status = 201;
      response: unknown = { attachment_id: "attachment-1" };
      onerror: (() => void) | null = null;
      onabort: (() => void) | null = null;
      onload: (() => void) | null = null;

      open(): void {}

      setRequestHeader(): void {}

      send(body: unknown): void {
        sent = body;
        this.onload?.();
      }
    }
    globalThis.XMLHttpRequest = TestXmlHttpRequest as unknown as typeof XMLHttpRequest;
    const encrypted = new Uint8Array([1, 2, 3]);
    try {
      await expect(uploadEncryptedAttachment(
        session,
        "dm_Alice_Bob",
        "FILE",
        encrypted,
        { oneTime: false, deleteAfterDownload: false, ttlSec: 60 },
        () => undefined,
      )).resolves.toBe("attachment-1");
      expect(sent).toBe(encrypted);
    } finally {
      globalThis.XMLHttpRequest = original;
    }
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

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ControlRejected } from "./v11Control";
import type { AccountSession, IncomingFrame, NodeEndpoint } from "../domain/types";
import {
  bytesToBase64,
  ATTACHMENT_CHUNK_RECORD_BYTES,
  IDENTITY_PUBLIC_KEY_BYTES,
} from "../security/crypto";
import {
  RelaySocket,
  revokeSession,
  streamEncryptedAttachmentRecords,
  completeAttachmentDownload,
  decryptAndCompleteAttachment,
  deleteUploadedAttachment,
  MAX_RELAY_TEXT_BYTES,
  MAX_PENDING_PREKEY_LEASES,
  PREKEY_LEASE_TIMEOUT_MS,
  PrekeyLeaseError,
  uploadEncryptedAttachment,
  type AttachmentDownloadPolicy,
} from "./nodeClient";
import {
  LEGACY_RELAY_DOMAIN_MAX_BYTES,
  MLS_RELAY_DOMAIN_MAX_BYTES,
  padOutgoingControlFrame,
} from "./messagePadding";

// Protocol-v11 records are sealed in WASM; these tests cover the client logic
// around them with the sealing modules replaced by controllable fakes.
const v11 = vi.hoisted(() => ({
  issue: vi.fn(),
  logout: vi.fn(),
  upload: vi.fn(),
  download: vi.fn(),
  complete: vi.fn(),
  release: vi.fn(),
  remove: vi.fn(),
}));
vi.mock("./v11Control", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./v11Control")>()),
  issueWsTicketV11: v11.issue,
  logoutV11: v11.logout,
}));
vi.mock("./v11Attachment", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./v11Attachment")>()),
  uploadAttachmentV11: v11.upload,
  downloadAttachmentV11: v11.download,
  completeDownloadV11: v11.complete,
  releaseDownloadV11: v11.release,
  deleteAttachmentV11: v11.remove,
}));
vi.mock("./v11Socket", () => ({
  WS_PROTOCOL_V11: "abyssal-v11",
  /** A channel that is ready at once and passes text through, like the pre-v11 socket. */
  V11SocketChannel: class {
    readonly ready = true;
    clientHello() { return null; }
    receive(data: unknown) {
      if (typeof data !== "string") throw new Error("Transport unavailable");
      return data;
    }
    seal(text: string) { return text; }
    destroy() { return undefined; }
  },
}));

beforeEach(() => {
  Object.values(v11).forEach((mock) => mock.mockReset());
  v11.issue.mockResolvedValue({ ticket: WS_TICKET_V11, expiresInSec: 30 });
});

const endpoint: NodeEndpoint = {
  apiBaseUrl: "https://node.example",
  wsBaseUrl: "wss://node.example",
  displayHost: "node.example",
};
const SESSION_TOKEN = "87fced9a-30b1-42f4-9f9d-b75381e03af7";

const session: AccountSession = {
  token: SESSION_TOKEN,
  transport: {
    nodePublicKey: new Uint8Array(32).fill(1),
    sessionId: new Uint8Array(32).fill(2),
    transportRoot: new Uint8Array(32).fill(3),
  },
  nodeId: "node-1",
  username: "Alice",
  maxRoomsPerUser: 3,
  sessionInactivitySec: 900,
  endpoint,
  created: false,
  identityPublicKey: new Uint8Array(IDENTITY_PUBLIC_KEY_BYTES),
  identityPrekeyId: "test-prekey",
};

async function downloadEncryptedAttachment(
  account: AccountSession,
  attachmentId: string,
  policy: AttachmentDownloadPolicy,
): Promise<{ bytes: Uint8Array; claim?: string }> {
  const records: Uint8Array[] = [];
  try {
    const streamed = await streamEncryptedAttachmentRecords(
      account,
      attachmentId,
      policy,
      (record) => {
        records.push(record.slice());
      },
    );
    const bytes = new Uint8Array(records.length * ATTACHMENT_CHUNK_RECORD_BYTES);
    records.forEach((record, index) => bytes.set(record, index * ATTACHMENT_CHUNK_RECORD_BYTES));
    return streamed.claim ? { bytes, claim: streamed.claim } : { bytes };
  } finally {
    records.forEach((record) => record.fill(0));
  }
}
const WS_TICKET_V11 = "T".repeat(43);
const ACK_SIGNATURE = new Uint8Array(64).fill(9);
const DIRECTORY_STAMP = {
  directory_node_id: "node-1",
  directory_revision: 1,
  directory_digest: bytesToBase64(new Uint8Array(32).fill(3)),
} as const;

function encryptedFrame(messageId: string): Record<string, unknown> {
  return {
    type: "message",
    chat_id: "dm_123",
    version: 9,
    message_id: messageId,
    nonce_b64: "nonce",
    ciphertext_b64: "ciphertext",
    state_revision: 1,
    identity_envelope_b64: "identity-envelope",
    identity_public_b64: "identity-public",
    prekey_id: "prekey",
    state_signature_b64: "state-signature",
    envelopes: [{
      recipient_username: "Bob",
      wrapped_key_b64: "wrapped",
      prekey_id: "",
      is_prekey: false,
      signature_b64: "signature",
    }],
    ...DIRECTORY_STAMP,
  };
}

function paddedRelayMessage(): { text: string; frame: Record<string, unknown> } {
  const base = {
    type: "message",
    chat_id: "dm_123",
    version: 9,
    message_id: "incoming-1",
    nonce_b64: "nonce",
    ciphertext_b64: "ciphertext",
    signature_b64: "signature",
    wrapped_key_b64: "wrapped",
    prekey_id: "",
    is_prekey: false,
    sender_username: "Bob",
    sender_public_key_b64: "sender-public",
    identity_public_b64: "sender-public",
    ...DIRECTORY_STAMP,
  };
  const bucket = 4096;
  const empty = JSON.stringify({ ...base, padding_bucket: bucket, padding: "" });
  const padding = "A".repeat(bucket - new TextEncoder().encode(empty).byteLength);
  const text = JSON.stringify({ ...base, padding_bucket: bucket, padding });
  if (new TextEncoder().encode(text).byteLength !== bucket) throw new Error("bad padded fixture");
  return { text, frame: JSON.parse(text) as Record<string, unknown> };
}

function paddedControlFrame(frame: Record<string, unknown>): string {
  const domainLimit = typeof frame.type === "string" && frame.type.startsWith("mls_")
    ? MLS_RELAY_DOMAIN_MAX_BYTES
    : LEGACY_RELAY_DOMAIN_MAX_BYTES;
  return padOutgoingControlFrame(frame, domainLimit) ?? (() => {
    throw new Error("bad padded control fixture");
  })();
}

function unpaddedControlFrame(text: string | undefined): Record<string, unknown> {
  if (text === undefined) throw new Error("missing control frame");
  const frame = JSON.parse(text) as Record<string, unknown>;
  delete frame.padding_bucket;
  delete frame.padding;
  return frame;
}

const CLAIM_PRIMARY = "44444444-4444-4444-8444-444444444444";
const CLAIM_FAILED = "55555555-5555-4555-8555-555555555555";
const CLAIM_DECRYPT = "66666666-6666-4666-8666-666666666666";
const ATTACHMENT_PRIMARY = "123e4567-e89b-42d3-a456-426614174000";
const ATTACHMENT_SECONDARY = "123e4567-e89b-42d3-a456-426614174001";
const ATTACHMENT_TERTIARY = "123e4567-e89b-42d3-a456-426614174002";
const ATTACHMENT_EMPTY = "123e4567-e89b-42d3-a456-426614174003";
const ATTACHMENT_EXACT = "123e4567-e89b-42d3-a456-426614174004";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("account and attachment transport over protocol v11", () => {
  it("revokes the session with a sealed control record, never a bearer token", async () => {
    v11.logout.mockResolvedValue(true);
    await revokeSession(session);
    expect(v11.logout).toHaveBeenCalledWith("https://node.example", session.transport, expect.any(AbortSignal));
  });

  it("uploads through the sealed attachment endpoint with the inner cipher version", async () => {
    v11.upload.mockImplementation(async (_base, _keys, _input, onProgress) => {
      onProgress(50, 100);
      return ATTACHMENT_PRIMARY;
    });
    const progress: number[] = [];
    const encrypted = new Uint8Array(ATTACHMENT_CHUNK_RECORD_BYTES).fill(5);
    await expect(uploadEncryptedAttachment(
      session,
      "dm_123",
      "7f0bf6e6-2d60-4b33-9a4b-1a7c1d1b3c11",
      "FILE",
      encrypted,
      { oneTime: true, deleteAfterDownload: false, ttlSec: 60 },
      ({ loaded }) => progress.push(loaded),
    )).resolves.toBe(ATTACHMENT_PRIMARY);
    const [base, keys, input] = v11.upload.mock.calls[0];
    expect(base).toBe("https://node.example");
    expect(keys).toBe(session.transport);
    expect(input).toMatchObject({
      chatId: "dm_123",
      mediaType: "FILE",
      cipherVersion: 2,
      oneTime: true,
      deleteAfterDownload: true,
      ttlSec: 60,
    });
    expect(input.ciphertext.size).toBe(ATTACHMENT_CHUNK_RECORD_BYTES);
    expect(progress).toEqual([Math.floor(ATTACHMENT_CHUNK_RECORD_BYTES / 2)]);
  });

  it("rejects an upload without a valid message binding or exact cipher records before sending", async () => {
    const options = { oneTime: false, deleteAfterDownload: false, ttlSec: 0 };
    await expect(uploadEncryptedAttachment(session, "dm_123", "not-a-uuid", "FILE",
      new Uint8Array(ATTACHMENT_CHUNK_RECORD_BYTES), options, () => undefined)).rejects.toThrow("Upload rejected");
    await expect(uploadEncryptedAttachment(session, "dm_123", "7f0bf6e6-2d60-4b33-9a4b-1a7c1d1b3c11", "FILE",
      new Uint8Array(ATTACHMENT_CHUNK_RECORD_BYTES - 1), options, () => undefined)).rejects.toThrow("Upload rejected");
    expect(v11.upload).not.toHaveBeenCalled();
  });

  it("re-chunks sealed stream payloads into exact cipher records and maps the claim", async () => {
    const recordBytes = ATTACHMENT_CHUNK_RECORD_BYTES;
    v11.download.mockImplementation(async (_base, _keys, _id, _max, onData) => {
      // Transport payloads do not line up with cipher records.
      await onData(new Uint8Array(1000).fill(1));
      await onData(new Uint8Array(recordBytes * 2 - 1000).fill(2));
      return { total: recordBytes * 2, claimId: Uint8Array.from({ length: 16 }, (_, index) => index) };
    });
    const result = await downloadEncryptedAttachment(session, ATTACHMENT_PRIMARY, { mediaType: "FILE", expectedPlaintextBytes: 300_000 });
    expect(result.bytes.byteLength).toBe(recordBytes * 2);
    expect(result.bytes[999]).toBe(1);
    expect(result.bytes[1000]).toBe(2);
    expect(result.claim).toBe("00010203-0405-0607-0809-0a0b0c0d0e0f");
  });

  it("releases a claim when the downloaded size does not match the metadata", async () => {
    v11.download.mockImplementation(async (_base, _keys, _id, _max, onData) => {
      await onData(new Uint8Array(ATTACHMENT_CHUNK_RECORD_BYTES));
      return { total: ATTACHMENT_CHUNK_RECORD_BYTES, claimId: new Uint8Array(16).fill(0x44) };
    });
    v11.release.mockResolvedValue(true);
    await expect(downloadEncryptedAttachment(session, ATTACHMENT_SECONDARY, {
      mediaType: "FILE",
      expectedPlaintextBytes: 600_000,
    })).rejects.toThrow("Attachment unavailable");
    expect(v11.release).toHaveBeenCalledWith(
      "https://node.example", session.transport, ATTACHMENT_SECONDARY, expect.any(Uint8Array), expect.any(AbortSignal),
    );
  });

  it("completes and deletes through sealed actions and rejects noncanonical claims", async () => {
    v11.complete.mockResolvedValue(true);
    v11.remove.mockResolvedValue(true);
    await completeAttachmentDownload(session, ATTACHMENT_PRIMARY, CLAIM_PRIMARY);
    // The claim bytes are handed over, then wiped once the action finishes.
    expect(v11.complete.mock.calls[0].slice(0, 3)).toEqual(["https://node.example", session.transport, ATTACHMENT_PRIMARY]);
    expect(v11.complete.mock.calls[0][3]).toEqual(new Uint8Array(16));
    await expect(completeAttachmentDownload(session, ATTACHMENT_PRIMARY, "not-a-claim")).rejects.toThrow("Attachment unavailable");
    v11.complete.mockResolvedValueOnce(false);
    await expect(completeAttachmentDownload(session, ATTACHMENT_PRIMARY, CLAIM_PRIMARY)).rejects.toThrow("Attachment unavailable");
    await deleteUploadedAttachment(session, ATTACHMENT_TERTIARY);
    expect(v11.remove).toHaveBeenCalledWith("https://node.example", session.transport, ATTACHMENT_TERTIARY, expect.any(AbortSignal));
  });

  it("releases a destructive claim when decryption fails or the plaintext is empty", async () => {
    v11.release.mockResolvedValue(true);
    await expect(decryptAndCompleteAttachment(
      session, ATTACHMENT_PRIMARY, CLAIM_DECRYPT, () => { throw new Error("bad ciphertext"); },
    )).rejects.toThrow("bad ciphertext");
    await expect(decryptAndCompleteAttachment(
      session, ATTACHMENT_EMPTY, CLAIM_FAILED, () => new Uint8Array(0), { expectedBytes: 1, maxBytes: 20 },
    )).rejects.toThrow("Attachment unavailable");
    expect(v11.release).toHaveBeenCalledTimes(2);
    expect(v11.complete).not.toHaveBeenCalled();
  });

  it("completes a destructive claim only after exact plaintext policy validation", async () => {
    v11.complete.mockResolvedValue(true);
    const plaintext = new Uint8Array([9, 8, 7]);
    await expect(decryptAndCompleteAttachment(
      session, ATTACHMENT_EXACT, CLAIM_PRIMARY, () => plaintext, { expectedBytes: 3, maxBytes: 3 },
    )).resolves.toBe(plaintext);
    expect(v11.complete).toHaveBeenCalledTimes(1);

    v11.release.mockResolvedValue(true);
    await expect(decryptAndCompleteAttachment(
      session, ATTACHMENT_SECONDARY, CLAIM_PRIMARY, () => new Uint8Array([1, 2, 3, 4]), { expectedBytes: 3, maxBytes: 20 },
    )).rejects.toThrow("Attachment unavailable");
    expect(v11.release).toHaveBeenCalledTimes(1);
  });

  it("does not complete or release non-destructive downloads", async () => {
    const plaintext = new Uint8Array([7, 8]);
    await expect(decryptAndCompleteAttachment(session, ATTACHMENT_PRIMARY, undefined, () => plaintext)).resolves.toBe(plaintext);
    expect(v11.complete).not.toHaveBeenCalled();
    expect(v11.release).not.toHaveBeenCalled();
  });
});

describe("RelaySocket", () => {
  it("leases an exact v9 prekey tuple and releases only the unused claim", async () => {
    const context = await connectRelay();
    const { relay, socket, originalWebSocket } = context;
    const publicKey = new Uint8Array(IDENTITY_PUBLIC_KEY_BYTES).fill(7);
    try {
      const pending = relay.requestPrekeyLease("dm_123", "lease-1", "Bob");
      expect(unpaddedControlFrame(socket.sent.at(-1))).toEqual({
        type: "prekey_lease",
        chat_id: "dm_123",
        message_id: "lease-1",
        recipient_username: "Bob",
      });
      socket.onmessage?.(new MessageEvent("message", { data: paddedControlFrame({
        type: "prekey_lease",
        chat_id: "dm_123",
        message_id: "lease-1",
        recipient_username: "Bob",
        recipient_public_key_b64: bytesToBase64(publicKey),
        prekey_id: "pool-key-1",
        // The relay is authoritative for lease TTL; the client must not
        // reject a server-valid timestamp because of local clock skew.
        expires_at_ms: 1,
      }) }));
      const lease = await pending;
      expect(lease).toMatchObject({
        chatId: "dm_123",
        messageId: "lease-1",
        recipientUsername: "Bob",
        prekeyId: "pool-key-1",
      });
      expect(lease.recipientPublicKey).toEqual(publicKey);
      expect(relay.releasePrekeyLease(lease)).toBe(true);
      expect(unpaddedControlFrame(socket.sent.at(-1))).toEqual({
        type: "prekey_lease_release",
        chat_id: "dm_123",
        message_id: "lease-1",
        recipient_username: "Bob",
        prekey_id: "pool-key-1",
      });
    } finally {
      publicKey.fill(0);
      relay.close();
      globalThis.WebSocket = originalWebSocket;
    }
  });

  it("rejects duplicate, mismatched, malformed, timed-out, and closed lease operations", async () => {
    const context = await connectRelay();
    const { relay, socket, originalWebSocket } = context;
    const publicKey = new Uint8Array(IDENTITY_PUBLIC_KEY_BYTES).fill(7);
    vi.useFakeTimers();
    try {
      const first = relay.requestPrekeyLease("dm_123", "lease-2", "Bob");
      await expect(relay.requestPrekeyLease("dm_123", "lease-2", "Bob"))
        .rejects.toMatchObject({ code: "NOT_SENT" });
      socket.onmessage?.(new MessageEvent("message", { data: paddedControlFrame({
        type: "prekey_lease",
        chat_id: "dm_123",
        message_id: "lease-2",
        recipient_username: "Carol",
        recipient_public_key_b64: bytesToBase64(publicKey),
        prekey_id: "pool-key-2",
        expires_at_ms: Date.now() + 60_000,
      }) }));
      await expect(first).rejects.toMatchObject({ code: "CLOSED" });
      expect(socket.readyState).toBe(3);

      const timeoutContext = await connectRelay();
      const timeout = timeoutContext.relay.requestPrekeyLease("dm_123", "lease-timeout", "Bob");
      const timeoutAssertion = expect(timeout).rejects.toMatchObject({ code: "AMBIGUOUS" });
      await vi.advanceTimersByTimeAsync(PREKEY_LEASE_TIMEOUT_MS);
      await timeoutAssertion;
      timeoutContext.relay.close();
      globalThis.WebSocket = timeoutContext.originalWebSocket;
    } finally {
      vi.useRealTimers();
      publicKey.fill(0);
      relay.close();
      globalThis.WebSocket = originalWebSocket;
    }
  });

  it("caps pending leases and rejects all pending promises on purge", async () => {
    const context = await connectRelay(() => undefined, () => undefined);
    const { relay, socket, originalWebSocket } = context;
    try {
      const pending = Array.from({ length: MAX_PENDING_PREKEY_LEASES }, (_, index) =>
        relay.requestPrekeyLease("dm_123", `lease-${index}`, "Bob"));
      await expect(relay.requestPrekeyLease("dm_123", "lease-over-cap", "Bob"))
        .rejects.toMatchObject({ code: "NOT_SENT" });
      socket.onclose?.({ code: 4001, reason: "purge", wasClean: true } as CloseEvent);
      await expect(Promise.all(pending)).rejects.toBeInstanceOf(PrekeyLeaseError);
      await expect(pending[0]).rejects.toMatchObject({ code: "CLOSED" });
    } finally {
      relay.close();
      globalThis.WebSocket = originalWebSocket;
    }
  });

  it("rejects a pending lease on manual close and clears its timer", async () => {
    const context = await connectRelay();
    const { relay, originalWebSocket } = context;
    vi.useFakeTimers();
    try {
      const pending = relay.requestPrekeyLease("dm_123", "lease-close", "Bob");
      relay.close();
      await expect(pending).rejects.toMatchObject({ code: "CLOSED" });
      await vi.advanceTimersByTimeAsync(PREKEY_LEASE_TIMEOUT_MS);
      await expect(pending).rejects.toMatchObject({ code: "CLOSED" });
    } finally {
      vi.useRealTimers();
      relay.close();
      globalThis.WebSocket = originalWebSocket;
    }
  });

  it("uses a short-lived ticket subprotocol and emits canonical DM commands", async () => {
    const original = globalThis.WebSocket;
    const sockets: FakeWebSocket[] = [];
    class TestWebSocket extends FakeWebSocket {
      constructor(url: string, protocols: string[]) {
        // Browser implementations copy the protocol list during construction.
        super(url, [...protocols]);
        sockets.push(this);
      }
    }
    Object.assign(TestWebSocket, { OPEN: 1, CLOSED: 3 });
    globalThis.WebSocket = TestWebSocket as unknown as typeof WebSocket;
    // Tickets come from the sealed control client; no plaintext fetch may happen.
    const fetchMock = vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("unexpected fetch"));
    const frames: IncomingFrame[] = [];
    const states: string[] = [];

    try {
      const relay = new RelaySocket(session, (frame) => frames.push(frame), (state) => states.push(state));
      relay.connect();
      await vi.waitFor(() => expect(sockets).toHaveLength(1));
      expect(v11.issue).toHaveBeenCalledWith(
        "https://node.example",
        session.transport,
        { platform: "web", version: "0.0.0", buildSignatureB64: "" },
        expect.any(AbortSignal),
      );
      expect(fetchMock).not.toHaveBeenCalled();
      const socket = sockets[0];
      expect(socket.url).toBe("wss://node.example/v1/ws");
      // The ticket travels inside the sealed ClientHello, never as a subprotocol.
      expect(socket.protocols).toEqual(["abyssal-v11"]);
      expect(socket.protocols.join(" ")).not.toContain(WS_TICKET_V11);
      socket.readyState = 1;
      socket.onopen?.(new Event("open"));
      relay.setDirectoryStamp(DIRECTORY_STAMP);
      expect(relay.openDirect("Bob")).toBe(true);
      const pendingAck = relay.acknowledge("dm_123", "message_1", "Alice", {
        revision: 2,
        envelope: new Uint8Array([2, 3, 4]),
        identityPublicKey: new Uint8Array(IDENTITY_PUBLIC_KEY_BYTES).fill(7),
        prekeyId: "test-prekey",
        stateSignature: new Uint8Array(64).fill(8),
      }, ACK_SIGNATURE, "used-prekey");
      expect(socket.sent.map((frame) => unpaddedControlFrame(frame))).toEqual([
        { type: "open_direct", peer_username: "Bob" },
        {
          type: "message_ack",
          chat_id: "dm_123",
          message_id: "message_1",
          sender_username: "Alice",
          state_revision: 2,
          identity_envelope_b64: "AgME",
          identity_public_b64: bytesToBase64(new Uint8Array(IDENTITY_PUBLIC_KEY_BYTES).fill(7)),
          prekey_id: "test-prekey",
          state_signature_b64: bytesToBase64(new Uint8Array(64).fill(8)),
          ack_signature_b64: bytesToBase64(ACK_SIGNATURE),
          used_prekey_id: "used-prekey",
        },
      ]);
      socket.onmessage?.(new MessageEvent("message", { data: paddedControlFrame({
        type: "ack_result",
        message_id: "message_1",
        accepted: true,
      }) }));
      await expect(pendingAck).resolves.toBe("ACCEPTED");

      const parseSpy = vi.spyOn(JSON, "parse");
      socket.onmessage?.(new MessageEvent("message", { data: JSON.stringify({
        type: "direct_opened",
        direct: { id: "dm_oversized", peer_username: "Mallory" },
        padding: "x".repeat(1024 * 1024),
      }) }));
      expect(parseSpy).not.toHaveBeenCalled();
      expect(socket.readyState).toBe(3);
      expect(relay.openDirect("Bob")).toBe(false);

      // Use a fresh connection for the remaining parser-shape checks because an
      // oversized relay frame permanently fails this authenticated socket closed.
      const parserRelay = new RelaySocket(session, (frame) => frames.push(frame), (state) => states.push(state));
      parserRelay.connect();
      await vi.waitFor(() => expect(sockets).toHaveLength(2));
      const parserSocket = sockets[1];
      parserSocket.readyState = 1;
      parserSocket.onopen?.(new Event("open"));
      parserRelay.setDirectoryStamp(DIRECTORY_STAMP);
      parserSocket.onmessage?.(new MessageEvent("message", { data: paddedControlFrame({
        type: "direct_opened",
        direct: { id: "dm_123", peer_username: "Bob" },
      }) }));
      parserSocket.onmessage?.(new MessageEvent("message", { data: paddedControlFrame({
        type: "presence",
        users: { username: "Mallory" },
      }) }));
      parserSocket.onmessage?.(new MessageEvent("message", { data: "invalid" }));
      expect(frames).toHaveLength(1);
      expect(states).toEqual(["connecting", "connected", "connecting", "connected", "disconnected"]);
      relay.close();
      parserRelay.close();
    } finally {
      globalThis.WebSocket = original;
    }
  });

  it("treats release admission rejection as terminal and reports it once", async () => {
    const rejected = vi.fn();
    const states: string[] = [];
    v11.issue.mockRejectedValue(new ControlRejected("build"));
    const timeoutSpy = vi.spyOn(window, "setTimeout");
    const relay = new RelaySocket(
      session,
      () => undefined,
      (state) => states.push(state),
      undefined,
      rejected,
    );
    try {
      relay.connect();
      await vi.waitFor(() => expect(rejected).toHaveBeenCalledTimes(1));
      expect(rejected).toHaveBeenCalledTimes(1);
      expect(rejected).toHaveBeenCalledWith("build");
      expect(states).toEqual(["connecting", "disconnected"]);
      expect(timeoutSpy.mock.calls.some(([, delay]) =>
        typeof delay === "number" && delay >= 750 && delay <= 15_499,
      )).toBe(false);
    } finally {
      relay.close();
    }
  });

  it.each([
    ["session-expired"],
    ["platform-conflict"],
  ] as const)("reports a %s ticket refusal once without retrying", async (expected) => {
    const rejected = vi.fn();
    v11.issue.mockRejectedValue(new ControlRejected(expected));
    const timeoutSpy = vi.spyOn(window, "setTimeout");
    const relay = new RelaySocket(session, () => undefined, () => undefined, undefined, rejected);
    try {
      relay.connect();
      await vi.waitFor(() => expect(rejected).toHaveBeenCalledTimes(1));
      expect(rejected).toHaveBeenCalledWith(expected);
      expect(timeoutSpy.mock.calls.some(([, delay]) =>
        typeof delay === "number" && delay >= 750 && delay <= 15_499,
      )).toBe(false);
    } finally {
      relay.close();
    }
  });

  it("retries a relay that is temporarily without a release manifest", async () => {
    const rejected = vi.fn();
    // A generic sealed failure (or a network error) is transient.
    v11.issue.mockRejectedValue(new ControlRejected());
    const timeoutSpy = vi.spyOn(window, "setTimeout");
    const relay = new RelaySocket(session, () => undefined, () => undefined, undefined, rejected);
    try {
      relay.connect();
      await vi.waitFor(() => expect(timeoutSpy.mock.calls.some(([, delay]) =>
        typeof delay === "number" && delay >= 750 && delay <= 15_499,
      )).toBe(true));
      expect(rejected).not.toHaveBeenCalled();
    } finally {
      relay.close();
    }
  });

  it("rejects cyclic and oversized outbound frames before browser send", async () => {
    const original = globalThis.WebSocket;
    const sockets: FakeWebSocket[] = [];
    class TestWebSocket extends FakeWebSocket {
      constructor(url: string, protocols: string[]) {
        super(url, [...protocols]);
        sockets.push(this);
      }
    }
    Object.assign(TestWebSocket, { OPEN: 1, CLOSED: 3 });
    globalThis.WebSocket = TestWebSocket as unknown as typeof WebSocket;

    try {
      const relay = new RelaySocket(session, () => undefined, () => undefined);
      relay.connect();
      await vi.waitFor(() => expect(sockets).toHaveLength(1));
      const socket = sockets[0];
      socket.readyState = 1;
      socket.onopen?.(new Event("open"));
      relay.setDirectoryStamp(DIRECTORY_STAMP);

      const oversized = { type: "dummy", padding: "x".repeat(MAX_RELAY_TEXT_BYTES) };
      expect(relay.send(oversized)).toBe(false);
      const cyclic: { type: string; self?: unknown } = { type: "dummy" };
      cyclic.self = cyclic;
      expect(relay.send(cyclic)).toBe(false);
      expect(socket.sent).toEqual([]);
      expect(relay.activity()).toBe(true);
      expect(socket.sent.map((frame) => unpaddedControlFrame(frame))).toEqual([
        { type: "activity" },
      ]);
      relay.close();
    } finally {
      globalThis.WebSocket = original;
    }
  });

  it("rejects out-of-range ticket responses and schedules bounded reconnect", async () => {
    const original = globalThis.WebSocket;
    const sockets: FakeWebSocket[] = [];
    class TestWebSocket extends FakeWebSocket {
      constructor(url: string, protocols: string[]) {
        super(url, [...protocols]);
        sockets.push(this);
      }
    }
    Object.assign(TestWebSocket, { OPEN: 1, CLOSED: 3 });
    globalThis.WebSocket = TestWebSocket as unknown as typeof WebSocket;
    // An out-of-range ticket is refused inside the control client; the socket retries later.
    v11.issue.mockRejectedValue(new ControlRejected());
    const timeoutSpy = vi.spyOn(window, "setTimeout");
    const states: string[] = [];

    try {
      const relay = new RelaySocket(session, () => undefined, (state) => states.push(state));
      relay.connect();
      await vi.waitFor(() => expect(states).toContain("disconnected"));
      expect(sockets).toHaveLength(0);
      expect(timeoutSpy.mock.calls.some(([, delay]) =>
        typeof delay === "number" && delay >= 750 && delay <= 15_499,
      )).toBe(true);
      relay.close();
    } finally {
      globalThis.WebSocket = original;
    }
  });

  it("rejects the biased jitter boundary before accepting the next random sample", async () => {
    const original = globalThis.WebSocket;
    const randomSamples = [65_500, 65_499];
    const getRandomValues = vi.spyOn(globalThis.crypto, "getRandomValues")
      .mockImplementation((values) => {
        (values as Uint16Array)[0] = randomSamples.shift() ?? 0;
        return values;
      });
    v11.issue.mockRejectedValue(new ControlRejected());
    const timeoutSpy = vi.spyOn(window, "setTimeout");

    try {
      const relay = new RelaySocket(session, () => undefined, () => undefined);
      relay.connect();
      for (let index = 0; index < 20 && getRandomValues.mock.calls.length < 2; index += 1) {
        await Promise.resolve();
      }
      expect(getRandomValues).toHaveBeenCalledTimes(2);
      expect(getRandomValues.mock.calls[0]?.[0]).toBeInstanceOf(Uint16Array);
      expect(timeoutSpy.mock.calls.map(([, delay]) => delay)).toContain(750 + 499);
      relay.close();
    } finally {
      globalThis.WebSocket = original;
    }
  });

  it("aborts a pending ticket request and cannot open a late socket", async () => {
    const original = globalThis.WebSocket;
    const sockets: FakeWebSocket[] = [];
    class TestWebSocket extends FakeWebSocket {
      constructor(url: string, protocols: string[]) {
        super(url, [...protocols]);
        sockets.push(this);
      }
    }
    Object.assign(TestWebSocket, { OPEN: 1, CLOSED: 3 });
    globalThis.WebSocket = TestWebSocket as unknown as typeof WebSocket;
    let resolveTicket: ((ticket: { ticket: string; expiresInSec: number }) => void) | undefined;
    v11.issue.mockImplementation(() => new Promise((resolve) => {
      resolveTicket = resolve;
    }));

    try {
      const relay = new RelaySocket(session, () => undefined, () => undefined);
      relay.connect();
      await vi.waitFor(() => expect(v11.issue).toHaveBeenCalledTimes(1));
      relay.close();
      expect((v11.issue.mock.calls[0]?.[3] as AbortSignal).aborted).toBe(true);
      resolveTicket?.({ ticket: WS_TICKET_V11, expiresInSec: 30 });
      await new Promise((resolve) => window.setTimeout(resolve, 0));
      expect(sockets).toHaveLength(0);
    } finally {
      globalThis.WebSocket = original;
    }
  });

  it("commits encrypted sends only after a strict accepted result", async () => {
    const original = globalThis.WebSocket;
    const sockets: FakeWebSocket[] = [];
    class TestWebSocket extends FakeWebSocket {
      constructor(url: string, protocols: string[]) {
        super(url, [...protocols]);
        sockets.push(this);
      }
    }
    Object.assign(TestWebSocket, { OPEN: 1, CLOSED: 3 });
    globalThis.WebSocket = TestWebSocket as unknown as typeof WebSocket;
    const frames: IncomingFrame[] = [];

    try {
      const relay = new RelaySocket(session, (frame) => frames.push(frame), () => undefined);
      relay.connect();
      await vi.waitFor(() => expect(sockets).toHaveLength(1));
      const socket = sockets[0];
      socket.readyState = 1;
      socket.onopen?.(new Event("open"));
      relay.setDirectoryStamp(DIRECTORY_STAMP);
      const pending = relay.sendEncryptedPayload("message-1", encryptedFrame("message-1"));
      const sentFrame = socket.sent.at(-1) ?? "";
      expect(new TextEncoder().encode(sentFrame).byteLength).toBe(4096);
      expect(JSON.parse(sentFrame)).toMatchObject({
        type: "message",
        message_id: "message-1",
        padding_bucket: 4096,
      });
      socket.onmessage?.(new MessageEvent("message", {
        data: paddedControlFrame({
          type: "message_result", message_id: "message-1", accepted: true,
        }),
      }));
      await expect(pending).resolves.toBe("ACCEPTED");
      expect(frames).toHaveLength(0);
      relay.close();
    } finally {
      globalThis.WebSocket = original;
    }
  });

  it("strips canonical incoming padding and fails closed on noncanonical padding", async () => {
    const frames: IncomingFrame[] = [];
    const context = await connectRelay((frame) => frames.push(frame));
    const { relay, socket, originalWebSocket } = context;
    try {
      const canonical = paddedRelayMessage();
      socket.onmessage?.(new MessageEvent("message", { data: canonical.text }));
      expect(frames).toHaveLength(1);
      expect(frames[0]).not.toHaveProperty("padding_bucket");
      expect(frames[0]).not.toHaveProperty("padding");

      const noncanonical = { ...canonical.frame, padding_bucket: 16_384 };
      socket.onmessage?.(new MessageEvent("message", { data: JSON.stringify(noncanonical) }));
      expect(frames).toHaveLength(1);
      expect(socket.readyState).toBe(3);
    } finally {
      relay.close();
      globalThis.WebSocket = originalWebSocket;
    }
  });

  it("rejects encrypted sends without an installed or matching directory stamp", async () => {
    const context = await connectRelay();
    const { relay, socket, originalWebSocket } = context;
    try {
      relay.setDirectoryStamp(null);
      await expect(relay.sendEncryptedPayload("message-missing-stamp", encryptedFrame("message-missing-stamp")))
        .resolves.toBe("NOT_SENT");
      expect(socket.sent).toEqual([]);

      relay.setDirectoryStamp(DIRECTORY_STAMP);
      await expect(relay.sendEncryptedPayload("message-stale-stamp", {
        ...encryptedFrame("message-stale-stamp"),
        directory_revision: DIRECTORY_STAMP.directory_revision + 1,
      })).resolves.toBe("NOT_SENT");
      expect(socket.sent).toEqual([]);

      await expect(relay.sendEncryptedPayload("message-invalid-shape", {
        ...encryptedFrame("message-invalid-shape"),
        unexpected: true,
      })).resolves.toBe("NOT_SENT");
      expect(socket.sent).toEqual([]);
    } finally {
      relay.close();
      globalThis.WebSocket = originalWebSocket;
    }
  });

  it("surfaces an explicit relay rejection without treating it as ambiguous", async () => {
    const original = globalThis.WebSocket;
    const sockets: FakeWebSocket[] = [];
    class TestWebSocket extends FakeWebSocket {
      constructor(url: string, protocols: string[]) {
        super(url, [...protocols]);
        sockets.push(this);
      }
    }
    Object.assign(TestWebSocket, { OPEN: 1, CLOSED: 3 });
    globalThis.WebSocket = TestWebSocket as unknown as typeof WebSocket;

    try {
      const relay = new RelaySocket(session, () => undefined, () => undefined);
      relay.connect();
      await vi.waitFor(() => expect(sockets).toHaveLength(1));
      const socket = sockets[0];
      socket.readyState = 1;
      socket.onopen?.(new Event("open"));
      relay.setDirectoryStamp(DIRECTORY_STAMP);
      const pending = relay.sendEncryptedPayload("message-rejected", encryptedFrame("message-rejected"));
      socket.onmessage?.(new MessageEvent("message", {
        data: paddedControlFrame({
          type: "message_result", message_id: "message-rejected", accepted: false,
        }),
      }));
      await expect(pending).resolves.toBe("REJECTED");
      relay.close();
    } finally {
      globalThis.WebSocket = original;
    }
  });

  it("fails closed on malformed or unknown message results", async () => {
    const original = globalThis.WebSocket;
    const sockets: FakeWebSocket[] = [];
    class TestWebSocket extends FakeWebSocket {
      constructor(url: string, protocols: string[]) {
        super(url, [...protocols]);
        sockets.push(this);
      }
    }
    Object.assign(TestWebSocket, { OPEN: 1, CLOSED: 3 });
    globalThis.WebSocket = TestWebSocket as unknown as typeof WebSocket;

    try {
      const relay = new RelaySocket(session, () => undefined, () => undefined);
      relay.connect();
      await vi.waitFor(() => expect(sockets).toHaveLength(1));
      const socket = sockets[0];
      socket.readyState = 1;
      socket.onopen?.(new Event("open"));
      relay.setDirectoryStamp(DIRECTORY_STAMP);
      const pending = relay.sendEncryptedPayload("message-2", encryptedFrame("message-2"));
      socket.onmessage?.(new MessageEvent("message", {
        data: paddedControlFrame({
          type: "message_result",
          message_id: "message-2",
          accepted: true,
          unexpected: true,
        }),
      }));
      await expect(pending).resolves.toBe("AMBIGUOUS");
      expect(socket.readyState).toBe(3);
    } finally {
      globalThis.WebSocket = original;
    }
  });

  it("replays the exact encrypted frame after a same-session reconnect", async () => {
    const original = globalThis.WebSocket;
    const sockets: FakeWebSocket[] = [];
    class TestWebSocket extends FakeWebSocket {
      constructor(url: string, protocols: string[]) {
        super(url, [...protocols]);
        sockets.push(this);
      }
    }
    Object.assign(TestWebSocket, { OPEN: 1, CLOSED: 3 });
    globalThis.WebSocket = TestWebSocket as unknown as typeof WebSocket;

    try {
      const relay = new RelaySocket(session, () => undefined, () => undefined);
      relay.connect();
      await vi.waitFor(() => expect(sockets).toHaveLength(1));
      const socket = sockets[0];
      socket.readyState = 1;
      socket.onopen?.(new Event("open"));
      relay.setDirectoryStamp(DIRECTORY_STAMP);
      const pending = relay.sendEncryptedPayload("message-3", encryptedFrame("message-3"));
      const exactFrame = socket.sent.at(-1);
      socket.onclose?.({ code: 1006, reason: "network", wasClean: false } as CloseEvent);
      await vi.waitFor(() => expect(sockets).toHaveLength(2), { timeout: 3_000 });
      const recovered = sockets[1];
      recovered.readyState = 1;
      recovered.onopen?.(new Event("open"));
      expect(recovered.sent).toEqual([exactFrame]);
      recovered.onmessage?.(new MessageEvent("message", { data: paddedControlFrame({
        type: "message_result",
        message_id: "message-3",
        accepted: true,
      }) }));
      await expect(pending).resolves.toBe("ACCEPTED");
      relay.close();
    } finally {
      globalThis.WebSocket = original;
    }
  });

  it("ignores callbacks from a superseded socket generation", async () => {
    const original = globalThis.WebSocket;
    const sockets: FakeWebSocket[] = [];
    class TestWebSocket extends FakeWebSocket {
      constructor(url: string, protocols: string[]) {
        super(url, [...protocols]);
        sockets.push(this);
      }
    }
    Object.assign(TestWebSocket, { OPEN: 1, CLOSED: 3 });
    globalThis.WebSocket = TestWebSocket as unknown as typeof WebSocket;
    const frames: IncomingFrame[] = [];

    try {
      const relay = new RelaySocket(session, (frame) => frames.push(frame), () => undefined);
      relay.connect();
      await vi.waitFor(() => expect(sockets).toHaveLength(1));
      const first = sockets[0];
      first.readyState = 1;
      first.onopen?.(new Event("open"));
      relay.setDirectoryStamp(DIRECTORY_STAMP);
      first.onclose?.({ code: 1006, reason: "network", wasClean: false } as CloseEvent);
      await vi.waitFor(() => expect(sockets).toHaveLength(2), { timeout: 3_000 });
      const second = sockets[1];
      second.readyState = 1;
      second.onopen?.(new Event("open"));
      relay.setDirectoryStamp(DIRECTORY_STAMP);
      first.onopen?.(new Event("open"));
      first.onmessage?.(new MessageEvent("message", {
        data: JSON.stringify({ type: "direct_opened", direct: { id: "dm_stale", peer_username: "Stale" } }),
      }));
      expect(frames).toHaveLength(0);
      relay.close();
    } finally {
      globalThis.WebSocket = original;
    }
  });

  it("bounds pending encrypted sends", async () => {
    const original = globalThis.WebSocket;
    const sockets: FakeWebSocket[] = [];
    class TestWebSocket extends FakeWebSocket {
      constructor(url: string, protocols: string[]) {
        super(url, [...protocols]);
        sockets.push(this);
      }
    }
    Object.assign(TestWebSocket, { OPEN: 1, CLOSED: 3 });
    globalThis.WebSocket = TestWebSocket as unknown as typeof WebSocket;

    try {
      const relay = new RelaySocket(session, () => undefined, () => undefined);
      relay.connect();
      await vi.waitFor(() => expect(sockets).toHaveLength(1));
      const socket = sockets[0];
      socket.readyState = 1;
      socket.onopen?.(new Event("open"));
      relay.setDirectoryStamp(DIRECTORY_STAMP);
      const pending = Array.from({ length: 257 }, (_, index) =>
        relay.sendEncryptedPayload(`message-${index}`, encryptedFrame(`message-${index}`)));
      await expect(pending.at(-1)).resolves.toBe("NOT_SENT");
      relay.close();
      await expect(pending[0]).resolves.toBe("AMBIGUOUS");
    } finally {
      globalThis.WebSocket = original;
    }
  });

  it("resolves accepted and rejected ACK results without publishing inbound frames", async () => {
    const context = await connectRelay();
    const { relay, socket, frames, originalWebSocket } = context;
    try {
      const accepted = relay.acknowledge(
        "dm_123",
        "ack-accepted",
        "Bob",
        ackState(),
        ACK_SIGNATURE,
        "used-prekey",
      );
      const ackFrame = JSON.parse(socket.sent.at(-1) ?? "{}") as Record<string, unknown>;
      expect(ackFrame.type).toBe("message_ack");
      expect(ackFrame).not.toHaveProperty("directory_node_id");
      expect(ackFrame).not.toHaveProperty("directory_revision");
      expect(ackFrame).not.toHaveProperty("directory_digest");
      socket.onmessage?.(new MessageEvent("message", { data: paddedControlFrame({
        type: "ack_result",
        message_id: "ack-accepted",
        accepted: true,
      }) }));
      await expect(accepted).resolves.toBe("ACCEPTED");

      const rejected = relay.acknowledge(
        "dm_123",
        "ack-rejected",
        "Bob",
        ackState(),
        ACK_SIGNATURE,
        "used-prekey",
      );
      socket.onmessage?.(new MessageEvent("message", { data: paddedControlFrame({
        type: "ack_result",
        message_id: "ack-rejected",
        accepted: false,
      }) }));
      await expect(rejected).resolves.toBe("REJECTED");
      expect(frames).toEqual([]);
    } finally {
      relay.close();
      globalThis.WebSocket = originalWebSocket;
    }
  });

  it("returns NOT_SENT for an unavailable socket and invalid or duplicate ACK tickets", async () => {
    const disconnected = new RelaySocket(session, () => undefined, () => undefined);
    await expect(disconnected.acknowledge(
      "dm_123",
      "ack-offline",
      "Bob",
      ackState(),
      ACK_SIGNATURE,
      "used-prekey",
    )).resolves.toBe("NOT_SENT");

    const context = await connectRelay();
    const { relay, socket, originalWebSocket } = context;
    try {
      await expect(relay.acknowledge(
        "dm_123",
        "not valid!",
        "Bob",
        ackState(),
        ACK_SIGNATURE,
        "used-prekey",
      )).resolves.toBe("NOT_SENT");
      const pending = relay.acknowledge(
        "dm_123",
        "ack-duplicate",
        "Bob",
        ackState(),
        ACK_SIGNATURE,
        "used-prekey",
      );
      await expect(relay.acknowledge(
        "dm_123",
        "ack-duplicate",
        "Bob",
        ackState(),
        ACK_SIGNATURE,
        "used-prekey",
      )).resolves.toBe("NOT_SENT");
      socket.onmessage?.(new MessageEvent("message", { data: paddedControlFrame({
        type: "ack_result",
        message_id: "ack-duplicate",
        accepted: true,
      }) }));
      await expect(pending).resolves.toBe("ACCEPTED");
    } finally {
      relay.close();
      globalThis.WebSocket = originalWebSocket;
    }
  });

  it("fails closed on a non-exact ACK result and settles the pending ticket", async () => {
    const context = await connectRelay();
    const { relay, socket, originalWebSocket } = context;
    try {
      const pending = relay.acknowledge(
        "dm_123",
        "ack-malformed",
        "Bob",
        ackState(),
        ACK_SIGNATURE,
        "used-prekey",
      );
      socket.onmessage?.(new MessageEvent("message", { data: paddedControlFrame({
        type: "ack_result",
        message_id: "ack-malformed",
        accepted: true,
        unexpected: true,
      }) }));
      await expect(pending).resolves.toBe("AMBIGUOUS");
      expect(socket.readyState).toBe(3);
    } finally {
      relay.close();
      globalThis.WebSocket = originalWebSocket;
    }
  });

  it("fails closed on unknown and duplicate ACK results", async () => {
    const unknownContext = await connectRelay();
    try {
      const pending = unknownContext.relay.acknowledge(
        "dm_123",
        "ack-pending",
        "Bob",
        ackState(),
        ACK_SIGNATURE,
        "used-prekey",
      );
      unknownContext.socket.onmessage?.(new MessageEvent("message", { data: paddedControlFrame({
        type: "ack_result",
        message_id: "ack-unknown",
        accepted: true,
      }) }));
      await expect(pending).resolves.toBe("AMBIGUOUS");
      expect(unknownContext.socket.readyState).toBe(3);
    } finally {
      unknownContext.relay.close();
      globalThis.WebSocket = unknownContext.originalWebSocket;
    }

    const duplicateContext = await connectRelay();
    try {
      const pending = duplicateContext.relay.acknowledge(
        "dm_123",
        "ack-once",
        "Bob",
        ackState(),
        ACK_SIGNATURE,
        "used-prekey",
      );
      const result = paddedControlFrame({
        type: "ack_result", message_id: "ack-once", accepted: true,
      });
      duplicateContext.socket.onmessage?.(new MessageEvent("message", { data: result }));
      await expect(pending).resolves.toBe("ACCEPTED");
      duplicateContext.socket.onmessage?.(new MessageEvent("message", { data: result }));
      expect(duplicateContext.socket.readyState).toBe(3);
    } finally {
      duplicateContext.relay.close();
      globalThis.WebSocket = duplicateContext.originalWebSocket;
    }
  });

  it("retries an ACK byte-for-byte and fails closed only after the recovery deadline", async () => {
    const context = await connectRelay();
    const { relay, socket, originalWebSocket } = context;
    vi.useFakeTimers();
    try {
      const pending = relay.acknowledge(
        "dm_123",
        "ack-timeout",
        "Bob",
        ackState(),
        ACK_SIGNATURE,
        "used-prekey",
      );
      const exactFrame = socket.sent.at(-1);
      await vi.advanceTimersByTimeAsync(30_000);
      await expect(pending).resolves.toBe("AMBIGUOUS");
      const ackFrames = socket.sent.filter((value) => JSON.parse(value).type === "message_ack");
      expect(ackFrames.length).toBeGreaterThan(1);
      expect(new Set(ackFrames)).toEqual(new Set([exactFrame]));
      expect(socket.readyState).toBe(3);
    } finally {
      vi.useRealTimers();
      relay.close();
      globalThis.WebSocket = originalWebSocket;
    }
  });

  it.each([
    ["socket close", (socket: FakeWebSocket) => socket.onclose?.({ code: 1006, reason: "network", wasClean: false } as CloseEvent)],
    ["socket error", (socket: FakeWebSocket) => socket.onerror?.(new Event("error"))],
  ])("retains message and ACK operations through %s until recovery expires", async (_label, trigger) => {
    const context = await connectRelay();
    const { relay, socket, originalWebSocket } = context;
    vi.useFakeTimers();
    try {
      const message = relay.sendEncryptedPayload("message-close", encryptedFrame("message-close"));
      const ack = relay.acknowledge(
        "dm_123",
        "ack-close",
        "Bob",
        ackState(),
        ACK_SIGNATURE,
        "used-prekey",
      );
      trigger(socket);
      await vi.advanceTimersByTimeAsync(30_000);
      await expect(message).resolves.toBe("AMBIGUOUS");
      await expect(ack).resolves.toBe("AMBIGUOUS");
    } finally {
      vi.useRealTimers();
      relay.close();
      globalThis.WebSocket = originalWebSocket;
    }
  });

  it("settles recoverable operations immediately on explicit client close", async () => {
    const context = await connectRelay();
    const { relay, originalWebSocket } = context;
    try {
      const message = relay.sendEncryptedPayload("message-close", encryptedFrame("message-close"));
      const ack = relay.acknowledge(
        "dm_123", "ack-close", "Bob", ackState(), ACK_SIGNATURE, "used-prekey",
      );
      relay.close();
      await expect(message).resolves.toBe("AMBIGUOUS");
      await expect(ack).resolves.toBe("AMBIGUOUS");
    } finally {
      relay.close();
      globalThis.WebSocket = originalWebSocket;
    }
  });

  it("settles both pending maps and invokes purge once on a purge close", async () => {
    let purges = 0;
    const context = await connectRelay(() => undefined, () => { purges += 1; });
    const { relay, socket, originalWebSocket } = context;
    try {
      const message = relay.sendEncryptedPayload("message-purge", encryptedFrame("message-purge"));
      const ack = relay.acknowledge(
        "dm_123",
        "ack-purge",
        "Bob",
        ackState(),
        ACK_SIGNATURE,
        "used-prekey",
      );
      socket.onclose?.({ code: 4001, reason: "purge", wasClean: true } as CloseEvent);
      await expect(message).resolves.toBe("AMBIGUOUS");
      await expect(ack).resolves.toBe("AMBIGUOUS");
      expect(purges).toBe(1);
      socket.onmessage?.(new MessageEvent("message", { data: paddedControlFrame({
        type: "ack_result",
        message_id: "ack-purge",
        accepted: true,
      }) }));
      expect(purges).toBe(1);
    } finally {
      relay.close();
      globalThis.WebSocket = originalWebSocket;
    }
  });

  it("bounds pending ACK operations independently from encrypted messages", async () => {
    const context = await connectRelay();
    const { relay, socket, originalWebSocket } = context;
    try {
      const pending = Array.from({ length: 257 }, (_, index) => relay.acknowledge(
        "dm_123",
        `ack-${index}`,
        "Bob",
        ackState(),
        ACK_SIGNATURE,
        "used-prekey",
      ));
      await expect(pending.at(-1)).resolves.toBe("NOT_SENT");
      expect(socket.sent.filter((value) => JSON.parse(value).type === "message_ack")).toHaveLength(256);
      relay.close();
      await expect(Promise.all(pending.slice(0, 256))).resolves.toEqual(
        Array.from({ length: 256 }, () => "AMBIGUOUS"),
      );
    } finally {
      relay.close();
      globalThis.WebSocket = originalWebSocket;
    }
  });

  it("ignores a late ACK result from a superseded socket generation", async () => {
    const originalWebSocket = globalThis.WebSocket;
    const sockets: FakeWebSocket[] = [];
    class TestWebSocket extends FakeWebSocket {
      constructor(url: string, protocols: string[]) {
        super(url, [...protocols]);
        sockets.push(this);
      }
    }
    Object.assign(TestWebSocket, { OPEN: 1, CLOSED: 3 });
    globalThis.WebSocket = TestWebSocket as unknown as typeof WebSocket;
    const frames: IncomingFrame[] = [];
    try {
      const relay = new RelaySocket(session, (frame) => frames.push(frame), () => undefined);
      relay.connect();
      await vi.waitFor(() => expect(sockets).toHaveLength(1));
      const first = sockets[0];
      first.readyState = 1;
      first.onopen?.(new Event("open"));
      relay.setDirectoryStamp(DIRECTORY_STAMP);
      const pending = relay.acknowledge(
        "dm_123",
        "ack-stale",
        "Bob",
        ackState(),
        ACK_SIGNATURE,
        "used-prekey",
      );
      const lease = relay.requestPrekeyLease("dm_123", "lease-stale", "Bob");
      const leaseAssertion = expect(lease).rejects.toMatchObject({ code: "AMBIGUOUS" });
      const exactAck = first.sent.find((value) => JSON.parse(value).type === "message_ack");
      first.onclose?.({ code: 1006, reason: "network", wasClean: false } as CloseEvent);
      await leaseAssertion;
      await vi.waitFor(() => expect(sockets).toHaveLength(2), { timeout: 3_000 });
      const second = sockets[1];
      second.readyState = 1;
      second.onopen?.(new Event("open"));
      relay.setDirectoryStamp(DIRECTORY_STAMP);
      expect(second.sent).toContain(exactAck);
      first.onmessage?.(new MessageEvent("message", { data: paddedControlFrame({
        type: "ack_result",
        message_id: "ack-stale",
        accepted: true,
      }) }));
      first.onmessage?.(new MessageEvent("message", { data: paddedControlFrame({
        type: "prekey_lease",
        chat_id: "dm_123",
        message_id: "lease-stale",
        recipient_username: "Bob",
        recipient_public_key_b64: bytesToBase64(new Uint8Array(IDENTITY_PUBLIC_KEY_BYTES).fill(7)),
        prekey_id: "stale-key",
        expires_at_ms: Date.now() + 60_000,
      }) }));
      expect(frames).toEqual([]);
      second.onmessage?.(new MessageEvent("message", { data: paddedControlFrame({
        type: "ack_result",
        message_id: "ack-stale",
        accepted: true,
      }) }));
      await expect(pending).resolves.toBe("ACCEPTED");
      relay.close();
    } finally {
      globalThis.WebSocket = originalWebSocket;
    }
  });

  it("binds MLS results to room, message, revision, and result domain", async () => {
    const { relay, socket, originalWebSocket } = await connectRelay();
    try {
      const frame = { type: "mls_application", protocol_version: 10, room_id: "forum_alpha", message_id: "mls-message", revision: "7" };
      const pending = relay.sendMlsTransaction("forum_alpha", "mls-message", 7n, frame);
      socket.onmessage?.(new MessageEvent("message", { data: paddedControlFrame({
        type: "mls_room_result", protocol_version: 10, room_id: "forum_alpha", message_id: "mls-message", revision: "7", accepted: true,
      }) }));
      await expect(pending).resolves.toBe("ACCEPTED");
      expect(unpaddedControlFrame(socket.sent.at(-1))).toEqual(frame);

      const snapshot = relay.sendMlsSnapshot("forum_alpha", "snapshot-message", 8n, {
        type: "mls_state_snapshot", protocol_version: 10, room_id: "forum_alpha", message_id: "snapshot-message", revision: "8",
      });
      socket.onmessage?.(new MessageEvent("message", { data: paddedControlFrame({
        type: "mls_room_result", protocol_version: 10, room_id: "forum_alpha", message_id: "snapshot-message", revision: "8", accepted: true,
      }) }));
      await expect(snapshot).resolves.toBe("AMBIGUOUS");
      expect(socket.readyState).toBe(3);
    } finally { relay.close(); globalThis.WebSocket = originalWebSocket; }
  });

  it("accepts exact snapshot rejection and fails closed on noncanonical counters", async () => {
    const { relay, socket, originalWebSocket } = await connectRelay();
    try {
      const pending = relay.sendMlsSnapshot("forum_alpha", "snapshot-ok", 9n, {
        type: "mls_state_snapshot", protocol_version: 10, room_id: "forum_alpha", message_id: "snapshot-ok", revision: "9",
      });
      socket.onmessage?.(new MessageEvent("message", { data: paddedControlFrame({
        type: "mls_snapshot_result", protocol_version: 10, room_id: "forum_alpha", message_id: "snapshot-ok", revision: "9", accepted: false,
      }) }));
      await expect(pending).resolves.toBe("REJECTED");
      socket.onmessage?.(new MessageEvent("message", { data: paddedControlFrame({
        type: "mls_snapshot_result", protocol_version: 10, room_id: "forum_alpha", message_id: "bad", revision: "09", accepted: true,
      }) }));
      expect(socket.readyState).toBe(3);
    } finally { relay.close(); globalThis.WebSocket = originalWebSocket; }
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

function ackState() {
  return {
    revision: 2,
    envelope: new Uint8Array([2, 3, 4]),
    identityPublicKey: new Uint8Array(IDENTITY_PUBLIC_KEY_BYTES).fill(7),
    prekeyId: "test-prekey",
    stateSignature: new Uint8Array(64).fill(8),
  };
}

async function connectRelay(
  onFrame: (frame: IncomingFrame) => void = () => undefined,
  onPurge: () => void = () => undefined,
): Promise<{
  relay: RelaySocket;
  socket: FakeWebSocket;
  frames: IncomingFrame[];
  originalWebSocket: typeof WebSocket;
}> {
  const originalWebSocket = globalThis.WebSocket;
  const sockets: FakeWebSocket[] = [];
  class TestWebSocket extends FakeWebSocket {
    constructor(url: string, protocols: string[]) {
      super(url, [...protocols]);
      sockets.push(this);
    }
  }
  Object.assign(TestWebSocket, { OPEN: 1, CLOSED: 3 });
  globalThis.WebSocket = TestWebSocket as unknown as typeof WebSocket;
  const frames: IncomingFrame[] = [];
  const relay = new RelaySocket(session, (frame) => {
    frames.push(frame);
    onFrame(frame);
  }, () => undefined, onPurge);
  relay.connect();
  await vi.waitFor(() => expect(sockets).toHaveLength(1));
  const socket = sockets[0];
  socket.readyState = 1;
  socket.onopen?.(new Event("open"));
  relay.setDirectoryStamp(DIRECTORY_STAMP);
  return { relay, socket, frames, originalWebSocket };
}

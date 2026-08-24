import { afterEach, describe, expect, it, vi } from "vitest";
import type { AccountSession, IncomingFrame, NodeEndpoint } from "../domain/types";
import {
  bytesToBase64,
  ATTACHMENT_CHUNK_RECORD_BYTES,
  IDENTITY_PUBLIC_KEY_BYTES,
} from "../security/crypto";
import {
  finishOpaqueAccount,
  RelaySocket,
  revokeSession,
  startOpaqueAccount,
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

const endpoint: NodeEndpoint = {
  apiBaseUrl: "https://node.example",
  wsBaseUrl: "wss://node.example",
  displayHost: "node.example",
};
const SESSION_TOKEN = "87fced9a-30b1-42f4-9f9d-b75381e03af7";

const session: AccountSession = {
  token: SESSION_TOKEN,
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
const WS_TICKET = bytesToBase64(new Uint8Array(32).fill(7));
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

function websocketTicketResponse(expiresInSec = 30): Response {
  return new Response(JSON.stringify({
    ticket: WS_TICKET,
    expires_in_sec: expiresInSec,
  }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

const CLAIM_TRUNCATED = "11111111-1111-4111-8111-111111111111";
const CLAIM_EXTRA = "22222222-2222-4222-8222-222222222222";
const CLAIM_EMPTY = "33333333-3333-4333-8333-333333333333";
const CLAIM_PRIMARY = "44444444-4444-4444-8444-444444444444";
const CLAIM_FAILED = "55555555-5555-4555-8555-555555555555";
const CLAIM_DECRYPT = "66666666-6666-4666-8666-666666666666";
const ATTACHMENT_PRIMARY = "123e4567-e89b-42d3-a456-426614174000";
const ATTACHMENT_SECONDARY = "123e4567-e89b-42d3-a456-426614174001";
const ATTACHMENT_TERTIARY = "123e4567-e89b-42d3-a456-426614174002";
const ATTACHMENT_EMPTY = "123e4567-e89b-42d3-a456-426614174003";
const ATTACHMENT_EXACT = "123e4567-e89b-42d3-a456-426614174004";
const FILE_THREE_BYTE_POLICY = { mediaType: "FILE" as const, expectedPlaintextBytes: 3 };
const exactEncryptedRecord = (fill: number) => new Uint8Array(ATTACHMENT_CHUNK_RECORD_BYTES).fill(fill);
const OPAQUE_CHALLENGE_B64 = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

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
      challenge_b64: null,
      node_id: "node-1",
      identity_public_b64: bytesToBase64(new Uint8Array(IDENTITY_PUBLIC_KEY_BYTES).fill(7)),
      identity_prekey_id: "test-prekey",
      identity_envelope_b64: "AQID",
      error: null,
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

  it("rejects non-canonical and malformed base64url in OPAQUE/account responses", async () => {
    const registrationResponse = (response_b64: string) => new Response(JSON.stringify({
      accepted: true,
      mode: "registration",
      handshake_id: "76f1b4b6-6dd8-4352-80b9-76fa0150484c",
      response_b64,
      challenge_b64: OPAQUE_CHALLENGE_B64,
      node_id: "node-1",
      identity_public_b64: null,
      identity_prekey_id: null,
      identity_envelope_b64: null,
      error: null,
    }), { status: 200 });
    const fetchMock = vi.spyOn(globalThis, "fetch")
      // AR decodes to the same byte as AQ, but has non-zero unused bits.
      .mockResolvedValueOnce(registrationResponse("AR"))
      // Base64url lengths modulo four equal to one are never valid.
      .mockResolvedValueOnce(registrationResponse("A"));

    await expect(startOpaqueAccount(
      endpoint,
      "CODE-1234567",
      new Uint8Array([1]),
      new Uint8Array([2]),
    )).rejects.toThrow("Wrong information");
    await expect(startOpaqueAccount(
      endpoint,
      "CODE-1234567",
      new Uint8Array([1]),
      new Uint8Array([2]),
    )).rejects.toThrow("Wrong information");

    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const canonicalPublic = bytesToBase64(new Uint8Array(IDENTITY_PUBLIC_KEY_BYTES).fill(7));
    const lastIndex = alphabet.indexOf(canonicalPublic.at(-1)!);
    const nonCanonicalPublic = `${canonicalPublic.slice(0, -1)}${alphabet[(lastIndex & 0x30) | 1]}`;
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({
      accepted: true,
      created: true,
      token: SESSION_TOKEN,
      node_id: "node-1",
      username: "Alice",
      max_rooms_per_user: 3,
      session_inactivity_sec: 900,
      identity_public_b64: nonCanonicalPublic,
      identity_prekey_id: "test-prekey",
      identity_envelope_b64: "AQID",
      error: null,
    }), { status: 200 }));

    await expect(finishOpaqueAccount(endpoint, {
      handshakeId: "76f1b4b6-6dd8-4352-80b9-76fa0150484c",
      credentialFinalization: new Uint8Array([9]),
    })).rejects.toThrow("Wrong information");
  });

  it("fails closed on the retired 128-byte account identity bundle", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({
      accepted: true,
      created: false,
      token: SESSION_TOKEN,
      node_id: "node-1",
      username: "Alice",
      max_rooms_per_user: 3,
      session_inactivity_sec: 900,
      identity_public_b64: bytesToBase64(new Uint8Array(128).fill(7)),
      identity_prekey_id: "test-prekey",
      identity_envelope_b64: "AQID",
      error: null,
    }), { status: 200 }));
    await expect(finishOpaqueAccount(endpoint, {
      handshakeId: "76f1b4b6-6dd8-4352-80b9-76fa0150484c",
      credentialFinalization: new Uint8Array([9]),
    })).rejects.toThrow("Wrong information");
  });

  it("cancels an oversized streamed OPAQUE response", async () => {
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(768 * 1024 + 1));
      },
      cancel() {
        cancelled = true;
      },
    });
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(stream, { status: 200 }));

    await expect(startOpaqueAccount(
      endpoint,
      "CODE-1234567",
      new Uint8Array([1]),
      new Uint8Array([2]),
    )).rejects.toThrow("Wrong information");
    expect(cancelled).toBe(true);
  });

  it("rejects truncated OPAQUE JSON using the declared content length", async () => {
    const body = JSON.stringify({ accepted: true });
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(body, {
      status: 200,
      headers: { "Content-Length": String(new TextEncoder().encode(body).byteLength + 4) },
    }));

    await expect(startOpaqueAccount(
      endpoint,
      "CODE-1234567",
      new Uint8Array([1]),
      new Uint8Array([2]),
    )).rejects.toThrow("Wrong information");
  });

  it("bounds decoded compressed responses without comparing their wire length", async () => {
    const body = JSON.stringify({
      accepted: true,
      mode: "registration",
      handshake_id: "76f1b4b6-6dd8-4352-80b9-76fa0150484c",
      response_b64: "AQID",
      challenge_b64: OPAQUE_CHALLENGE_B64,
      node_id: "node-1",
      identity_public_b64: null,
      identity_prekey_id: null,
      identity_envelope_b64: null,
      error: null,
    });
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(body, {
      status: 200,
      headers: { "Content-Encoding": "br", "Content-Length": "17" },
    }));

    await expect(startOpaqueAccount(
      endpoint,
      "CODE-1234567",
      new Uint8Array([1]),
      new Uint8Array([2]),
    )).resolves.toMatchObject({ mode: "registration", node_id: "node-1" });
  });

  it("rejects malformed or oversized content lengths and cancels the body", async () => {
    let cancellations = 0;
    const body = () => new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array([123]));
      },
      cancel() {
        cancellations += 1;
      },
    });
    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(body(), {
        status: 200,
        headers: { "Content-Length": "12x" },
      }))
      .mockResolvedValueOnce(new Response(body(), {
        status: 200,
        headers: { "Content-Length": String(768 * 1024 + 1) },
      }));

    await expect(startOpaqueAccount(endpoint, "CODE-1234567", new Uint8Array([1]), new Uint8Array([2])))
      .rejects.toThrow("Wrong information");
    await expect(startOpaqueAccount(endpoint, "CODE-1234567", new Uint8Array([1]), new Uint8Array([2])))
      .rejects.toThrow("Wrong information");
    expect(cancellations).toBe(2);
  });

  it("cancels the response body when the account request is aborted", async () => {
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array([123]));
      },
      cancel() {
        cancelled = true;
      },
    });
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(stream, { status: 200 }));
    const abort = new AbortController();
    abort.abort();

    await expect(startOpaqueAccount(
      endpoint,
      "CODE-1234567",
      new Uint8Array([1]),
      new Uint8Array([2]),
      abort.signal,
    )).rejects.toThrow("Wrong information");
    expect(cancelled).toBe(true);
  });

  it("rejects malformed types, unknown fields, and invalid session tokens", async () => {
    const invalidStart = new Response(JSON.stringify({
      accepted: true,
      mode: "registration",
      handshake_id: "76f1b4b6-6dd8-4352-80b9-76fa0150484c",
      response_b64: "AQID",
      node_id: "node-1",
      unexpected: "field",
    }), { status: 200 });
    const invalidFinish = new Response(JSON.stringify({
      accepted: true,
      created: false,
      token: "not-a-session-token",
      node_id: "node-1",
      username: "Alice",
      max_rooms_per_user: "3",
      session_inactivity_sec: 900,
      identity_public_b64: bytesToBase64(new Uint8Array(IDENTITY_PUBLIC_KEY_BYTES).fill(7)),
      identity_prekey_id: "test-prekey",
      identity_envelope_b64: "AQID",
    }), { status: 200 });
    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(invalidStart)
      .mockResolvedValueOnce(invalidFinish);

    await expect(startOpaqueAccount(
      endpoint,
      "CODE-1234567",
      new Uint8Array([1]),
      new Uint8Array([2]),
    )).rejects.toThrow("Wrong information");
    await expect(finishOpaqueAccount(endpoint, {
      handshakeId: "76f1b4b6-6dd8-4352-80b9-76fa0150484c",
      credentialFinalization: new Uint8Array([9]),
    })).rejects.toThrow("Wrong information");
  });

  it("finishes OPAQUE and validates returned identity material", async () => {
    const publicKey = new Uint8Array(IDENTITY_PUBLIC_KEY_BYTES).fill(7);
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({
      accepted: true,
      created: true,
      token: SESSION_TOKEN,
      node_id: "node-1",
      username: "Alice",
      max_rooms_per_user: 3,
      session_inactivity_sec: 900,
      identity_public_b64: bytesToBase64(publicKey),
      identity_prekey_id: "test-prekey",
      identity_envelope_b64: "AQID",
      error: null,
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
      headers: { Authorization: `Bearer ${SESSION_TOKEN}` },
    }));
  });

  it("streams bounded attachment bodies and rejects an oversized declaration", async () => {
    const encrypted = exactEncryptedRecord(7);
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(
      encrypted.slice(),
      { status: 200, headers: { "content-length": String(encrypted.byteLength) } },
    ));
    await expect(downloadEncryptedAttachment(
      session,
      ATTACHMENT_PRIMARY,
      FILE_THREE_BYTE_POLICY,
    )).resolves.toEqual(
      { bytes: encrypted },
    );
    expect(fetchMock).toHaveBeenCalledWith(
      `https://node.example/v1/attachment/${ATTACHMENT_PRIMARY}`,
      expect.objectContaining({ cache: "no-store", credentials: "omit" }),
    );

    fetchMock.mockResolvedValue(new Response(new Uint8Array([1]), {
      status: 200,
      headers: { "content-length": "999999999999999999999" },
    }));
    await expect(downloadEncryptedAttachment(
      session,
      ATTACHMENT_SECONDARY,
      FILE_THREE_BYTE_POLICY,
    )).rejects.toThrow(
      "Attachment unavailable",
    );
  });

  it("accepts an exact chunked body without Content-Length and rejects FILE-sized IMAGE metadata before fetch", async () => {
    const exact = exactEncryptedRecord(6);
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(exact.slice(0, 13));
        controller.enqueue(exact.slice(13));
        controller.close();
      },
    });
    const fetchMock = vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(stream, { status: 200 }));

    await expect(downloadEncryptedAttachment(
      session,
      ATTACHMENT_PRIMARY,
      FILE_THREE_BYTE_POLICY,
    )).resolves.toEqual({ bytes: exact });
    await expect(downloadEncryptedAttachment(
      session,
      ATTACHMENT_SECONDARY,
      { mediaType: "IMAGE", expectedPlaintextBytes: 200 * 1024 * 1024 },
    )).rejects.toThrow("Attachment unavailable");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("frames arbitrary network chunks into fixed records and wipes callback buffers", async () => {
    const encrypted = new Uint8Array(2 * ATTACHMENT_CHUNK_RECORD_BYTES);
    encrypted.fill(0x11, 0, ATTACHMENT_CHUNK_RECORD_BYTES);
    encrypted.fill(0x22, ATTACHMENT_CHUNK_RECORD_BYTES);
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encrypted.slice(0, 17));
        controller.enqueue(encrypted.slice(17, ATTACHMENT_CHUNK_RECORD_BYTES + 29));
        controller.enqueue(encrypted.slice(ATTACHMENT_CHUNK_RECORD_BYTES + 29));
        controller.close();
      },
    });
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(stream, {
      status: 200,
      headers: { "content-length": String(encrypted.byteLength) },
    }));
    const callbackViews: Uint8Array[] = [];
    const observed: number[] = [];

    await expect(streamEncryptedAttachmentRecords(
      session,
      ATTACHMENT_PRIMARY,
      {
        mediaType: "FILE",
        expectedPlaintextBytes: 256 * 1024 + 1,
      },
      (record, index) => {
        callbackViews.push(record);
        observed.push(index, record[0]);
      },
    )).resolves.toEqual({});

    expect(observed).toEqual([0, 0x11, 1, 0x22]);
    for (const view of callbackViews) expect(view.every((value) => value === 0)).toBe(true);
  });

  it("releases a destructive claim when record processing fails", async () => {
    const encrypted = exactEncryptedRecord(9);
    const fetchMock = vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(encrypted, {
        status: 200,
        headers: {
          "content-length": String(encrypted.byteLength),
          "X-Abyssal-Attachment-Claim": CLAIM_DECRYPT,
        },
      }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    let callbackView: Uint8Array | undefined;

    await expect(streamEncryptedAttachmentRecords(
      session,
      ATTACHMENT_PRIMARY,
      FILE_THREE_BYTE_POLICY,
      (record) => {
        callbackView = record;
        throw new Error("decrypt failed");
      },
    )).rejects.toThrow("decrypt failed");

    expect(callbackView?.every((value) => value === 0)).toBe(true);
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      `https://node.example/v1/attachment/${ATTACHMENT_PRIMARY}/claim`,
      expect.objectContaining({ method: "DELETE" }),
    );
  });

  it("rejects truncated bodies and mismatched encrypted Content-Length values", async () => {
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

    await expect(downloadEncryptedAttachment(
      session,
      ATTACHMENT_PRIMARY,
      FILE_THREE_BYTE_POLICY,
    )).rejects.toThrow(
      "Attachment unavailable",
    );
    await expect(downloadEncryptedAttachment(
      session,
      ATTACHMENT_SECONDARY,
      FILE_THREE_BYTE_POLICY,
    )).rejects.toThrow(
      "Attachment unavailable",
    );
    await expect(downloadEncryptedAttachment(
      session,
      ATTACHMENT_TERTIARY,
      FILE_THREE_BYTE_POLICY,
    )).rejects.toThrow(
      "Attachment unavailable",
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      3,
      `https://node.example/v1/attachment/${ATTACHMENT_SECONDARY}/claim`,
      expect.objectContaining({ method: "DELETE" }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      5,
      `https://node.example/v1/attachment/${ATTACHMENT_TERTIARY}/claim`,
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

    await expect(downloadEncryptedAttachment(
      session,
      ATTACHMENT_EMPTY,
      FILE_THREE_BYTE_POLICY,
    )).rejects.toThrow(
      "Attachment unavailable",
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      `https://node.example/v1/attachment/${ATTACHMENT_EMPTY}/claim`,
      expect.objectContaining({
        method: "DELETE",
        cache: "no-store",
        credentials: "omit",
        referrerPolicy: "no-referrer",
        headers: {
          Authorization: `Bearer ${SESSION_TOKEN}`,
          "X-Abyssal-Attachment-Claim": CLAIM_EMPTY,
        },
      }),
    );
  });

  it("returns an optional claim without changing exact encrypted bytes", async () => {
    const encrypted = exactEncryptedRecord(5);
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(
      encrypted.slice(),
      {
        status: 200,
        headers: {
          "content-length": String(encrypted.byteLength),
          "X-Abyssal-Attachment-Claim": CLAIM_PRIMARY,
        },
      },
    ));

    await expect(downloadEncryptedAttachment(
      session,
      ATTACHMENT_PRIMARY,
      FILE_THREE_BYTE_POLICY,
    )).resolves.toEqual({
      bytes: encrypted,
      claim: CLAIM_PRIMARY,
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("completes a claim with the authenticated bearer and claim header", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 204 }));

    await expect(completeAttachmentDownload(session, ATTACHMENT_PRIMARY, CLAIM_PRIMARY)).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledWith(
      `https://node.example/v1/attachment/${ATTACHMENT_PRIMARY}/complete`,
      expect.objectContaining({
        method: "POST",
        cache: "no-store",
        credentials: "omit",
        referrerPolicy: "no-referrer",
        headers: {
          Authorization: `Bearer ${SESSION_TOKEN}`,
          "X-Abyssal-Attachment-Claim": CLAIM_PRIMARY,
        },
      }),
    );
  });

  it("rejects noncanonical attachment claims before sending a mutation", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch");

    await expect(completeAttachmentDownload(session, ATTACHMENT_PRIMARY, "claim-123"))
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
      ATTACHMENT_PRIMARY,
      CLAIM_FAILED,
      () => plaintext,
    )).rejects.toThrow("Attachment unavailable");
    expect(plaintext).toEqual(new Uint8Array(3));
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      `https://node.example/v1/attachment/${ATTACHMENT_PRIMARY}/claim`,
      expect.objectContaining({ method: "DELETE" }),
    );
  });

  it("releases a claim when authenticated decryption fails", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 204 }));

    await expect(decryptAndCompleteAttachment(
      session,
      ATTACHMENT_PRIMARY,
      CLAIM_DECRYPT,
      () => { throw new Error("bad ciphertext"); },
    )).rejects.toThrow("bad ciphertext");
    expect(fetchMock).toHaveBeenCalledWith(
      `https://node.example/v1/attachment/${ATTACHMENT_PRIMARY}/claim`,
      expect.objectContaining({ method: "DELETE" }),
    );
  });

  it("rejects empty plaintext before completing and releases a destructive claim", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 204 }));
    const plaintext = new Uint8Array(0);

    await expect(decryptAndCompleteAttachment(
      session,
      ATTACHMENT_EMPTY,
      CLAIM_FAILED,
      () => plaintext,
      { expectedBytes: 1, maxBytes: 20 },
    )).rejects.toThrow("Attachment unavailable");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith(
      `https://node.example/v1/attachment/${ATTACHMENT_EMPTY}/claim`,
      expect.objectContaining({ method: "DELETE" }),
    );
  });

  it("rejects authenticated plaintext whose metadata size is mismatched or over the media limit", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 204 }));
    const plaintext = new Uint8Array([1, 2, 3, 4]);

    await expect(decryptAndCompleteAttachment(
      session,
      ATTACHMENT_SECONDARY,
      CLAIM_FAILED,
      () => plaintext,
      { expectedBytes: 3, maxBytes: 4 },
    )).rejects.toThrow("Attachment unavailable");
    await expect(decryptAndCompleteAttachment(
      session,
      ATTACHMENT_TERTIARY,
      CLAIM_DECRYPT,
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
      ATTACHMENT_EXACT,
      CLAIM_PRIMARY,
      () => plaintext,
      { expectedBytes: 3, maxBytes: 3 },
    )).resolves.toBe(plaintext);
    expect(fetchMock).toHaveBeenCalledWith(
      `https://node.example/v1/attachment/${ATTACHMENT_EXACT}/complete`,
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("does not complete or release non-destructive downloads", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch");
    const plaintext = new Uint8Array([7, 8]);

    await expect(decryptAndCompleteAttachment(
      session,
      ATTACHMENT_PRIMARY,
      undefined,
      () => plaintext,
    )).resolves.toBe(plaintext);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("passes the encrypted upload view to XHR without making a full copy", async () => {
    const original = globalThis.XMLHttpRequest;
    let sent: unknown;
    let openedUrl = "";
    class TestXmlHttpRequest {
      readonly upload = { onprogress: null as ((event: ProgressEvent) => void) | null };
      responseType = "";
      status = 201;
      responseText = JSON.stringify({ attachment_id: ATTACHMENT_PRIMARY });
      onerror: (() => void) | null = null;
      onabort: (() => void) | null = null;
      onload: (() => void) | null = null;

      open(_method: string, url: string): void {
        openedUrl = url;
      }

      setRequestHeader(): void {}

      getResponseHeader(): string | null { return null; }

      send(body: unknown): void {
        sent = body;
        this.onload?.();
      }
    }
    globalThis.XMLHttpRequest = TestXmlHttpRequest as unknown as typeof XMLHttpRequest;
    const encrypted = exactEncryptedRecord(3);
    try {
      await expect(uploadEncryptedAttachment(
        session,
        "dm_Alice_Bob",
        ATTACHMENT_PRIMARY,
        "FILE",
        encrypted,
        { oneTime: false, deleteAfterDownload: false, ttlSec: 60 },
        () => undefined,
      )).resolves.toBe(ATTACHMENT_PRIMARY);
      expect(sent).toBe(encrypted);
      expect(openedUrl).toContain(`message_id=${ATTACHMENT_PRIMARY}`);
    } finally {
      globalThis.XMLHttpRequest = original;
    }
  });

  it("rejects an upload without a valid message binding before opening XHR", async () => {
    const original = globalThis.XMLHttpRequest;
    let opened = false;
    class UnusedXmlHttpRequest {
      open(): void {
        opened = true;
      }
    }
    globalThis.XMLHttpRequest = UnusedXmlHttpRequest as unknown as typeof XMLHttpRequest;
    try {
      await expect(uploadEncryptedAttachment(
        session,
        "dm_Alice_Bob",
        "not-a-uuid",
        "FILE",
        exactEncryptedRecord(3),
        { oneTime: false, deleteAfterDownload: false, ttlSec: 60 },
        () => undefined,
      )).rejects.toThrow("Upload rejected");
      expect(opened).toBe(false);
    } finally {
      globalThis.XMLHttpRequest = original;
    }
  });

  it("aborts attachment uploads through the supplied signal", async () => {
    const original = globalThis.XMLHttpRequest;
    let aborted = false;
    class TestXmlHttpRequest {
      static readonly HEADERS_RECEIVED = 2;
      readonly upload = { onprogress: null as ((event: ProgressEvent) => void) | null };
      responseType = "";
      responseText = "";
      readyState = 1;
      status = 0;
      onerror: (() => void) | null = null;
      onabort: (() => void) | null = null;
      onload: (() => void) | null = null;
      onprogress: ((event: ProgressEvent) => void) | null = null;
      onreadystatechange: (() => void) | null = null;

      open(): void {}
      setRequestHeader(): void {}
      getResponseHeader(): string | null { return null; }
      send(): void {}
      abort(): void {
        aborted = true;
        this.onabort?.();
      }
    }
    globalThis.XMLHttpRequest = TestXmlHttpRequest as unknown as typeof XMLHttpRequest;
    const controller = new AbortController();
    try {
      const pending = uploadEncryptedAttachment(
        session,
        "dm_Alice_Bob",
        ATTACHMENT_PRIMARY,
        "FILE",
        exactEncryptedRecord(3),
        { oneTime: false, deleteAfterDownload: false, ttlSec: 60 },
        () => undefined,
        controller.signal,
      );
      controller.abort();
      await expect(pending).rejects.toThrow("Upload aborted");
      expect(aborted).toBe(true);
    } finally {
      globalThis.XMLHttpRequest = original;
    }
  });

  it("rejects oversized or non-exact attachment upload responses", async () => {
    const original = globalThis.XMLHttpRequest;
    class TestXmlHttpRequest {
      static readonly HEADERS_RECEIVED = 2;
      static responseText = "";
      static declaredLength: string | null = null;
      static responseProgressBytes: number | null = null;
      readonly upload = { onprogress: null as ((event: ProgressEvent) => void) | null };
      responseType = "";
      responseText = TestXmlHttpRequest.responseText;
      readyState = 1;
      status = 201;
      onerror: (() => void) | null = null;
      onabort: (() => void) | null = null;
      onload: (() => void) | null = null;
      onprogress: ((event: ProgressEvent) => void) | null = null;
      onreadystatechange: (() => void) | null = null;

      open(): void {}
      setRequestHeader(): void {}
      getResponseHeader(name: string): string | null {
        return name.toLowerCase() === "content-length" ? TestXmlHttpRequest.declaredLength : null;
      }
      send(): void {
        if (TestXmlHttpRequest.responseProgressBytes !== null) {
          this.onprogress?.({ loaded: TestXmlHttpRequest.responseProgressBytes } as ProgressEvent);
          if (this.readyState === 0) return;
        }
        this.readyState = TestXmlHttpRequest.HEADERS_RECEIVED;
        this.onreadystatechange?.();
        if (this.readyState === TestXmlHttpRequest.HEADERS_RECEIVED) this.onload?.();
      }
      abort(): void {
        this.readyState = 0;
        this.onabort?.();
      }
    }
    globalThis.XMLHttpRequest = TestXmlHttpRequest as unknown as typeof XMLHttpRequest;
    const upload = () => uploadEncryptedAttachment(
      session,
      "dm_Alice_Bob",
      ATTACHMENT_PRIMARY,
      "FILE",
      exactEncryptedRecord(3),
      { oneTime: false, deleteAfterDownload: false, ttlSec: 60 },
      () => undefined,
    );
    try {
      TestXmlHttpRequest.responseText = JSON.stringify({
        attachment_id: ATTACHMENT_PRIMARY,
        unexpected: true,
      });
      await expect(upload()).rejects.toThrow("Upload rejected");

      TestXmlHttpRequest.responseText = JSON.stringify({ attachment_id: ATTACHMENT_PRIMARY });
      TestXmlHttpRequest.declaredLength = String(4 * 1024 + 1);
      await expect(upload()).rejects.toThrow("Upload rejected");

      TestXmlHttpRequest.declaredLength = null;
      TestXmlHttpRequest.responseProgressBytes = 4 * 1024 + 1;
      await expect(upload()).rejects.toThrow("Upload rejected");
    } finally {
      globalThis.XMLHttpRequest = original;
    }
  });

  it("deletes an uploaded blob with the authenticated owner token", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 204 }));

    const attachmentId = ATTACHMENT_PRIMARY;
    await expect(deleteUploadedAttachment(session, attachmentId)).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledWith(
      `https://node.example/v1/attachment/${attachmentId}`,
      expect.objectContaining({
        method: "DELETE",
        cache: "no-store",
        credentials: "omit",
        referrerPolicy: "no-referrer",
        headers: { Authorization: `Bearer ${SESSION_TOKEN}` },
      }),
    );

    await expect(deleteUploadedAttachment(session, "not-a-uuid")).rejects.toThrow(
      "Attachment unavailable",
    );
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe("RelaySocket", () => {
  it("leases an exact v9 prekey tuple and releases only the unused claim", async () => {
    const context = await connectRelay();
    const { relay, socket, originalWebSocket } = context;
    const publicKey = new Uint8Array(IDENTITY_PUBLIC_KEY_BYTES).fill(7);
    try {
      const pending = relay.requestPrekeyLease("dm_123", "lease-1", "Bob");
      expect(socket.sent.at(-1)).toBe(JSON.stringify({
        type: "prekey_lease",
        chat_id: "dm_123",
        message_id: "lease-1",
        recipient_username: "Bob",
      }));
      socket.onmessage?.(new MessageEvent("message", { data: JSON.stringify({
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
      expect(socket.sent.at(-1)).toBe(JSON.stringify({
        type: "prekey_lease_release",
        chat_id: "dm_123",
        message_id: "lease-1",
        recipient_username: "Bob",
        prekey_id: "pool-key-1",
      }));
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
      socket.onmessage?.(new MessageEvent("message", { data: JSON.stringify({
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
    const fetchMock = vi.spyOn(globalThis, "fetch")
      .mockImplementation(() => Promise.resolve(websocketTicketResponse()));
    const frames: IncomingFrame[] = [];
    const states: string[] = [];

    try {
      const relay = new RelaySocket(session, (frame) => frames.push(frame), (state) => states.push(state));
      relay.connect();
      await vi.waitFor(() => expect(sockets).toHaveLength(1));
      expect(fetchMock).toHaveBeenCalledWith(
        "https://node.example/v1/ws-ticket",
        expect.objectContaining({
          method: "POST",
          cache: "no-store",
          credentials: "omit",
          referrerPolicy: "no-referrer",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${SESSION_TOKEN}`,
          },
          body: JSON.stringify({
            platform: "web",
            version: "0.0.0",
            build_signature_b64: "",
          }),
          signal: expect.any(AbortSignal),
        }),
      );
      const socket = sockets[0];
      expect(socket.url).toBe("wss://node.example/v1/ws");
      expect(socket.protocols).toEqual(["abyssal-v1", `ticket.${WS_TICKET}`]);
      expect(socket.protocols.join(" ")).not.toContain(SESSION_TOKEN);
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
      expect(socket.sent).toEqual([
        JSON.stringify({ type: "open_direct", peer_username: "Bob" }),
        JSON.stringify({
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
        }),
      ]);
      socket.onmessage?.(new MessageEvent("message", { data: JSON.stringify({
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
      parserSocket.onmessage?.(new MessageEvent("message", { data: JSON.stringify({
        type: "direct_opened",
        direct: { id: "dm_123", peer_username: "Bob" },
      }) }));
      parserSocket.onmessage?.(new MessageEvent("message", { data: JSON.stringify({
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
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 426 }));
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
      expect(states).toEqual(["connecting", "disconnected"]);
      expect(timeoutSpy.mock.calls.some(([, delay]) =>
        typeof delay === "number" && delay >= 750 && delay <= 15_499,
      )).toBe(false);
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
    vi.spyOn(globalThis, "fetch")
      .mockImplementation(() => Promise.resolve(websocketTicketResponse()));

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
      expect(socket.sent).toEqual([JSON.stringify({ type: "activity" })]);
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
    vi.spyOn(globalThis, "fetch")
      .mockImplementation(() => Promise.resolve(websocketTicketResponse(31)));
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
    vi.spyOn(globalThis, "fetch")
      .mockImplementation(() => Promise.resolve(websocketTicketResponse(31)));
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
    let resolveTicket: ((response: Response) => void) | undefined;
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(() =>
      new Promise<Response>((resolve) => {
        resolveTicket = resolve;
      }));

    try {
      const relay = new RelaySocket(session, () => undefined, () => undefined);
      relay.connect();
      await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
      relay.close();
      expect((fetchMock.mock.calls[0]?.[1] as RequestInit).signal?.aborted).toBe(true);
      resolveTicket?.(websocketTicketResponse());
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
    vi.spyOn(globalThis, "fetch").mockImplementation(() => Promise.resolve(websocketTicketResponse()));
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
        data: JSON.stringify({ type: "message_result", message_id: "message-1", accepted: true }),
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
    vi.spyOn(globalThis, "fetch").mockImplementation(() => Promise.resolve(websocketTicketResponse()));

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
        data: JSON.stringify({ type: "message_result", message_id: "message-rejected", accepted: false }),
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
    vi.spyOn(globalThis, "fetch").mockImplementation(() => Promise.resolve(websocketTicketResponse()));

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
        data: JSON.stringify({
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
    vi.spyOn(globalThis, "fetch").mockImplementation(() => Promise.resolve(websocketTicketResponse()));

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
      recovered.onmessage?.(new MessageEvent("message", { data: JSON.stringify({
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
    vi.spyOn(globalThis, "fetch").mockImplementation(() => Promise.resolve(websocketTicketResponse()));
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
    vi.spyOn(globalThis, "fetch").mockImplementation(() => Promise.resolve(websocketTicketResponse()));

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
      socket.onmessage?.(new MessageEvent("message", { data: JSON.stringify({
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
      socket.onmessage?.(new MessageEvent("message", { data: JSON.stringify({
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
      socket.onmessage?.(new MessageEvent("message", { data: JSON.stringify({
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
      socket.onmessage?.(new MessageEvent("message", { data: JSON.stringify({
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
      unknownContext.socket.onmessage?.(new MessageEvent("message", { data: JSON.stringify({
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
      const result = JSON.stringify({ type: "ack_result", message_id: "ack-once", accepted: true });
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
      trigger(socket, relay);
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
      socket.onmessage?.(new MessageEvent("message", { data: JSON.stringify({
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
    vi.spyOn(globalThis, "fetch").mockImplementation(() => Promise.resolve(websocketTicketResponse()));
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
      first.onmessage?.(new MessageEvent("message", { data: JSON.stringify({
        type: "ack_result",
        message_id: "ack-stale",
        accepted: true,
      }) }));
      first.onmessage?.(new MessageEvent("message", { data: JSON.stringify({
        type: "prekey_lease",
        chat_id: "dm_123",
        message_id: "lease-stale",
        recipient_username: "Bob",
        recipient_public_key_b64: bytesToBase64(new Uint8Array(IDENTITY_PUBLIC_KEY_BYTES).fill(7)),
        prekey_id: "stale-key",
        expires_at_ms: Date.now() + 60_000,
      }) }));
      expect(frames).toEqual([]);
      second.onmessage?.(new MessageEvent("message", { data: JSON.stringify({
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
      socket.onmessage?.(new MessageEvent("message", { data: JSON.stringify({
        type: "mls_room_result", protocol_version: 10, room_id: "forum_alpha", message_id: "mls-message", revision: "7", accepted: true,
      }) }));
      await expect(pending).resolves.toBe("ACCEPTED");
      expect(JSON.parse(socket.sent.at(-1)!)).toEqual(frame);

      const snapshot = relay.sendMlsSnapshot("forum_alpha", "snapshot-message", 8n, {
        type: "mls_state_snapshot", protocol_version: 10, room_id: "forum_alpha", message_id: "snapshot-message", revision: "8",
      });
      socket.onmessage?.(new MessageEvent("message", { data: JSON.stringify({
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
      socket.onmessage?.(new MessageEvent("message", { data: JSON.stringify({
        type: "mls_snapshot_result", protocol_version: 10, room_id: "forum_alpha", message_id: "snapshot-ok", revision: "9", accepted: false,
      }) }));
      await expect(pending).resolves.toBe("REJECTED");
      socket.onmessage?.(new MessageEvent("message", { data: JSON.stringify({
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
  vi.spyOn(globalThis, "fetch").mockImplementation(() => Promise.resolve(websocketTicketResponse()));
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

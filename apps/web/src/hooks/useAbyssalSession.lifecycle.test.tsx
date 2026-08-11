import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AccountSession, IncomingFrame, RoomRecord } from "../domain/types";

const mocks = vi.hoisted(() => {
  const identityPublicKey = new Uint8Array(128).fill(7);
  const nodeEndpoint = {
    apiBaseUrl: "https://node.example.test",
    wsBaseUrl: "wss://node.example.test",
    displayHost: "node.example.test",
  };
  class FakeCipher {
    static failAcknowledgement = false;
    static decryptCount = 0;
    static lastSnapshot: {
      envelope: Uint8Array;
      identityPublicKey: Uint8Array;
      stateSignature: Uint8Array;
    } | null = null;
    private publicKeyBytes: Uint8Array | null = null;
    private readonly prekey = "prekey-one";

    createIdentity(): { publicKey: Uint8Array; prekeyId: string; envelope: Uint8Array } {
      this.publicKeyBytes = identityPublicKey.slice();
      return {
        publicKey: identityPublicKey.slice(),
        prekeyId: this.prekey,
        envelope: new Uint8Array([1, 2, 3]),
      };
    }

    publicKey(): Uint8Array {
      if (!this.publicKeyBytes) throw new Error("Identity unavailable");
      return this.publicKeyBytes.slice();
    }

    prekeyId(): string {
      return this.prekey;
    }

    stateSnapshot() {
      const snapshot = {
        revision: 1,
        envelope: new Uint8Array([4, 5]),
        identityPublicKey: identityPublicKey.slice(),
        prekeyId: this.prekey,
        stateSignature: new Uint8Array(64).fill(6),
      };
      FakeCipher.lastSnapshot = snapshot;
      return snapshot;
    }

    signAcknowledgement(): Uint8Array {
      if (FakeCipher.failAcknowledgement) throw new Error("signing failed");
      return new Uint8Array(64).fill(8);
    }

    encryptText() {
      return {
        version: 7,
        messageId: "message",
        nonce: new Uint8Array([1]),
        ciphertext: new Uint8Array([2]),
        envelopes: [],
        stateRevision: 1,
        identityEnvelope: new Uint8Array([3]),
        identityPublicKey: identityPublicKey.slice(),
        prekeyId: this.prekey,
        stateSignature: new Uint8Array(64).fill(6),
      };
    }

    decryptText() {
      FakeCipher.decryptCount += 1;
      return JSON.stringify({
        kind: "text",
        id: "incoming-message",
        sender: "Bob",
        content: "incoming secret",
        timestamp_ms: Date.now(),
      });
    }

    clear(): void {
      this.publicKeyBytes?.fill(0);
      this.publicKeyBytes = null;
    }
  }

  class FakeRelay {
    static readonly instances: FakeRelay[] = [];
    private readonly frameHandler: (frame: IncomingFrame) => void;
    readonly session: AccountSession;
    connected = false;
    closed = false;
    sent: object[] = [];

    constructor(
      session: AccountSession,
      frameHandler: (frame: IncomingFrame) => void,
      private readonly stateHandler: (state: "connecting" | "connected" | "disconnected") => void,
    ) {
      this.session = session;
      this.frameHandler = frameHandler;
      FakeRelay.instances.push(this);
    }

    connect(): void {
      this.stateHandler("connecting");
      this.connected = true;
      this.stateHandler("connected");
    }

    close(): void {
      this.closed = true;
      this.connected = false;
      this.stateHandler("disconnected");
    }

    send(frame: object): boolean {
      if (!this.connected || this.closed) return false;
      this.sent.push(frame);
      return true;
    }

    join(): boolean { return this.send({ type: "join" }); }
    openDirect(): boolean { return this.send({ type: "open_direct" }); }
    createRoom(): boolean { return this.send({ type: "create_room" }); }
    deleteRoom(): boolean { return this.send({ type: "delete_room" }); }
    wipe(): boolean { return this.send({ type: "global_wipe" }); }
    activity(): boolean { return this.send({ type: "activity" }); }
    acknowledge(...args: unknown[]): boolean { return this.send({ type: "message_ack", args }); }

    emit(frame: IncomingFrame): void {
      this.frameHandler(frame);
    }
  }

  return {
    identityPublicKey,
    nodeEndpoint,
    accountSession: {
      token: "123e4567-e89b-42d3-a456-426614174000",
      nodeId: "node-one",
      username: "Alice",
      maxRoomsPerUser: 2,
      sessionInactivitySec: 900,
      endpoint: nodeEndpoint,
      // Keep this fixture mutable because lifecycle tests exercise both
      // registration and login responses.
      created: true as boolean,
      identityPublicKey: identityPublicKey.slice(),
      identityPrekeyId: "prekey-one",
    } satisfies AccountSession,
    FakeCipher,
    FakeRelay,
    getLastRelay: () => FakeRelay.instances.at(-1) ?? null,
    reset: () => {
      FakeRelay.instances.length = 0;
      FakeCipher.failAcknowledgement = false;
      FakeCipher.decryptCount = 0;
      FakeCipher.lastSnapshot = null;
    },
    startOpaqueAccount: vi.fn(async () => ({
      accepted: true,
      mode: "registration" as const,
      handshake_id: "handshake-one",
      response_b64: "AQ",
      node_id: "node-one",
    })),
    finishOpaqueAccount: vi.fn(async () => ({
      ...mocks.accountSession,
      identityPublicKey: mocks.identityPublicKey.slice(),
    })),
    revokeSession: vi.fn(async () => undefined),
    downloadEncryptedAttachment: vi.fn(async () => ({ bytes: new Uint8Array([1, 2, 3]) })),
    decryptAndCompleteAttachment: vi.fn(async () => new Uint8Array([8, 9, 10])),
  };
});

vi.mock("../security/crypto", async () => {
  const actual = await vi.importActual<typeof import("../security/crypto")>("../security/crypto");
  return {
    ...actual,
    startOpaque: vi.fn(async () => ({
      registrationState: new Uint8Array([1]),
      registrationRequest: new Uint8Array([2]),
      loginState: new Uint8Array([3]),
      credentialRequest: new Uint8Array([4]),
    })),
    finishOpaqueRegistration: vi.fn(async () => ({
      registrationUpload: new Uint8Array([5]),
      exportKey: new Uint8Array([6]),
    })),
    InMemoryPayloadCipher: mocks.FakeCipher,
    payloadToFrame: vi.fn(() => ({
      version: 7,
      message_id: "message",
      nonce_b64: "AQ",
      ciphertext_b64: "Ag",
      state_revision: 1,
      identity_envelope_b64: "Aw",
      identity_public_b64: "Bw",
      prekey_id: "prekey-one",
    })),
  };
});

vi.mock("../transport/nodeClient", async () => {
  const actual = await vi.importActual<typeof import("../transport/nodeClient")>("../transport/nodeClient");
  return {
    ...actual,
    RelaySocket: mocks.FakeRelay,
    startOpaqueAccount: mocks.startOpaqueAccount,
    finishOpaqueAccount: mocks.finishOpaqueAccount,
    revokeSession: mocks.revokeSession,
    downloadEncryptedAttachment: mocks.downloadEncryptedAttachment,
    decryptAndCompleteAttachment: mocks.decryptAndCompleteAttachment,
  };
});

import { useAbyssalSession } from "./useAbyssalSession";

const room: RoomRecord = {
  id: "forum_ops",
  name: "Operations",
  owner_username: "Alice",
  self_destruct_timer_sec: 5,
  overall_expiry_sec: 0,
  allow_images: true,
  allow_videos: true,
  allow_files: true,
  enforce_text_absolute_expiry: false,
  image_read_timer_sec: 5,
  image_overall_expiry_sec: 0,
  enforce_image_absolute_expiry: false,
  video_read_timer_sec: 5,
  video_overall_expiry_sec: 0,
  enforce_video_absolute_expiry: false,
  file_read_timer_sec: 5,
  file_overall_expiry_sec: 0,
  enforce_file_absolute_expiry: false,
};

const originalURL = URL;
const originalCreateObjectURL = URL.createObjectURL;
const originalRevokeObjectURL = URL.revokeObjectURL;
const validPublicKeyB64 = Buffer.from(mocks.identityPublicKey).toString("base64").replace(/=+$/u, "");

afterEach(() => {
  cleanup();
  mocks.reset();
  document.documentElement.classList.remove("abyssal-page-hidden");
  Object.defineProperty(originalURL, "createObjectURL", { configurable: true, value: originalCreateObjectURL });
  Object.defineProperty(originalURL, "revokeObjectURL", { configurable: true, value: originalRevokeObjectURL });
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubGlobal("URL", originalURL);
  Object.defineProperty(originalURL, "createObjectURL", {
    configurable: true,
    value: vi.fn(() => "blob:decrypted-media"),
  });
  Object.defineProperty(originalURL, "revokeObjectURL", {
    configurable: true,
    value: vi.fn(),
  });
});

describe("useAbyssalSession lifecycle cleanup", () => {
  it("rejects malformed, duplicate, and oversized relay catalogs without replacing state", async () => {
    const { result, unmount } = renderHook(() => useAbyssalSession());
    await act(async () => {
      await result.current.login({
        nodeUrl: "https://node.example.test",
        code: "ABCD-1234",
        password: "password",
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    const validPresence = [
      {
        username: "Alice",
        connected: true,
        identity_public_b64: validPublicKeyB64,
        identity_prekey_id: "prekey-one",
        directory_digest: "A".repeat(43),
      },
      {
        username: "Bob",
        connected: true,
        identity_public_b64: validPublicKeyB64,
        identity_prekey_id: "prekey-two",
        directory_digest: "A".repeat(43),
      },
    ];
    await act(async () => {
      relay?.emit({ type: "rooms", rooms: [room] });
      relay?.emit({ type: "presence", users: validPresence });
    });
    await waitFor(() => {
      expect(result.current.rooms).toHaveLength(1);
      expect(result.current.presence).toHaveLength(2);
    });

    const malformedRoom = { ...room, name: "x".repeat(37) };
    const malformedDigest = `${"A".repeat(42)}B`;
    await act(async () => {
      relay?.emit({ type: "rooms", rooms: [malformedRoom] });
      relay?.emit({ type: "rooms", rooms: [room, room] });
      relay?.emit({ type: "rooms", rooms: [room, { ...room, id: "FORUM_OPS" }] });
      relay?.emit({ type: "presence", users: [validPresence[0], validPresence[0]] });
      relay?.emit({
        type: "presence",
        users: [{ ...validPresence[0], directory_digest: malformedDigest }, validPresence[1]],
      });
      relay?.emit({ type: "presence", users: Array.from({ length: 129 }, () => validPresence[0]) });
    });

    expect(result.current.rooms).toEqual([room]);
    expect(result.current.presence).toEqual(validPresence);

    await act(async () => {
      relay?.emit({
        type: "directs",
        directs: [{ id: "dm_bob", peer_username: "Bob" }],
      });
    });
    await waitFor(() => expect(result.current.directs).toHaveLength(1));
    await act(async () => {
      relay?.emit({
        type: "directs",
        directs: [
          { id: "dm_BOB", peer_username: "Mallory" },
          { id: "dm_bob", peer_username: "Eve" },
        ],
      });
      relay?.emit({
        type: "directs",
        directs: [
          { id: "dm_eve", peer_username: "Eve" },
          { id: "dm_eve_two", peer_username: "eve" },
        ],
      });
      relay?.emit({
        type: "directs",
        directs: [
          { id: "dm_eve", peer_username: "Eve" },
          { id: "dm_EVE", peer_username: "Mallory" },
        ],
      });
      relay?.emit({
        type: "directs",
        directs: [{ id: "dm_eve", peer_username: "Eve", extra: true } as never],
      });
    });
    expect(result.current.directs).toEqual([{ id: "dm_bob", peer_username: "Bob" }]);
    unmount();
  });

  it("bounds dynamic room and direct updates with case-insensitive collision checks", async () => {
    const { result, unmount } = renderHook(() => useAbyssalSession());
    await act(async () => {
      await result.current.login({
        nodeUrl: "https://node.example.test",
        code: "ABCD-1234",
        password: "password",
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    const rooms = Array.from({ length: 1_023 }, (_, index) => ({
      ...room,
      id: `forum_room_${index}`,
      name: `Room ${index}`,
    }));
    await act(async () => relay?.emit({ type: "rooms", rooms }));
    await waitFor(() => expect(result.current.rooms).toHaveLength(1_023));

    await act(async () => relay?.emit({
      type: "room_created",
      room: { ...room, id: "forum_final", name: "Final" },
    }));
    await waitFor(() => expect(result.current.rooms).toHaveLength(1_024));
    await act(async () => {
      relay?.emit({
        type: "room_created",
        room: { ...room, id: "forum_overflow", name: "Overflow" },
      });
      relay?.emit({
        type: "room_created",
        room: { ...room, id: "forum_ROOM_0", name: "Collision" },
      });
      relay?.emit({
        type: "room_created",
        room: { ...room, id: "forum_room_0", name: "Replacement" },
      });
    });
    expect(result.current.rooms).toHaveLength(1_024);
    expect(result.current.rooms.some((candidate) => candidate.id === "forum_overflow")).toBe(false);
    expect(result.current.rooms.some((candidate) => candidate.id === "forum_ROOM_0")).toBe(false);
    expect(result.current.rooms.find((candidate) => candidate.id === "forum_room_0")?.name).toBe("Replacement");

    const directs = Array.from({ length: 128 }, (_, index) => ({
      id: `dm_peer_${index}`,
      peer_username: `Peer_${index}`,
    }));
    await act(async () => relay?.emit({ type: "directs", directs }));
    await waitFor(() => expect(result.current.directs).toHaveLength(128));
    await act(async () => {
      relay?.emit({
        type: "direct_opened",
        direct: { id: "dm_peer_0", peer_username: "Peer_0" },
      });
      relay?.emit({
        type: "direct_opened",
        direct: { id: "dm_PEER_0", peer_username: "Peer_0" },
      });
      relay?.emit({
        type: "direct_opened",
        direct: { id: "dm_overflow", peer_username: "Overflow" },
      });
    });
    expect(result.current.directs).toHaveLength(128);
    expect(result.current.directs.some((candidate) => candidate.id === "dm_PEER_0")).toBe(false);
    expect(result.current.directs.some((candidate) => candidate.id === "dm_overflow")).toBe(false);
    unmount();
  });

  it("acknowledges duplicate delivery without decrypting again and wipes proof buffers on failure", async () => {
    const { result, unmount } = renderHook(() => useAbyssalSession());
    await act(async () => {
      await result.current.login({
        nodeUrl: "https://node.example.test",
        code: "ABCD-1234",
        password: "password",
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    await act(async () => {
      relay?.emit({ type: "rooms", rooms: [room] });
      relay?.emit({
        type: "presence",
        users: [{
          username: "Bob",
          connected: true,
          identity_public_b64: validPublicKeyB64,
          identity_prekey_id: "prekey-one",
          directory_digest: "A".repeat(43),
        }],
      });
    });
    await waitFor(() => expect(result.current.rooms).toHaveLength(1));

    const frame: IncomingFrame = {
      type: "message",
      chat_id: room.id,
      version: 7,
      message_id: "incoming-message",
      nonce_b64: "AQ",
      ciphertext_b64: "Ag",
      signature_b64: "Aw",
      wrapped_key_b64: "BA",
      sender_username: "Bob",
      sender_public_key_b64: validPublicKeyB64,
      identity_public_b64: validPublicKeyB64,
      prekey_id: "prekey-one",
      is_prekey: false,
    };
    await act(async () => relay?.emit(frame));
    await waitFor(() => expect(result.current.messages[room.id]).toHaveLength(1));
    expect(mocks.FakeCipher.decryptCount).toBe(1);
    const firstAckCount = relay?.sent.filter((item) => (item as { type?: string }).type === "message_ack").length;
    expect(firstAckCount).toBe(1);

    await act(async () => relay?.emit(frame));
    await waitFor(() => expect(relay?.sent.filter((item) => (item as { type?: string }).type === "message_ack")).toHaveLength(2));
    expect(mocks.FakeCipher.decryptCount).toBe(1);
    expect(result.current.messages[room.id]).toHaveLength(1);
    expect(result.current.session).not.toBeNull();

    mocks.FakeCipher.failAcknowledgement = true;
    await act(async () => relay?.emit({ ...frame, message_id: "new-message" }));
    await waitFor(() => expect(mocks.FakeCipher.lastSnapshot).not.toBeNull());
    expect(mocks.FakeCipher.lastSnapshot?.envelope.every((byte) => byte === 0)).toBe(true);
    expect(mocks.FakeCipher.lastSnapshot?.identityPublicKey.every((byte) => byte === 0)).toBe(true);
    expect(mocks.FakeCipher.lastSnapshot?.stateSignature.every((byte) => byte === 0)).toBe(true);
    unmount();
  });

  it("decrypts only presence-pinned senders and accepts prekey rotation on the pinned identity", async () => {
    const { result, unmount } = renderHook(() => useAbyssalSession());
    await act(async () => {
      await result.current.login({
        nodeUrl: "https://node.example.test",
        code: "ABCD-1234",
        password: "password",
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    await act(async () => relay?.emit({ type: "rooms", rooms: [room] }));
    await waitFor(() => expect(result.current.rooms).toHaveLength(1));

    const baseFrame: IncomingFrame = {
      type: "message",
      chat_id: room.id,
      version: 7,
      message_id: "identity-bound-message",
      nonce_b64: "AQ",
      ciphertext_b64: "Ag",
      signature_b64: "Aw",
      wrapped_key_b64: "BA",
      sender_username: "Bob",
      sender_public_key_b64: validPublicKeyB64,
      identity_public_b64: validPublicKeyB64,
      prekey_id: "prekey-one",
      is_prekey: false,
    };
    await act(async () => relay?.emit(baseFrame));
    expect(mocks.FakeCipher.decryptCount).toBe(0);

    await act(async () => relay?.emit({
      type: "presence",
      users: [{
        username: "Bob",
        connected: true,
        identity_public_b64: validPublicKeyB64,
        identity_prekey_id: "prekey-one",
        directory_digest: "A".repeat(43),
      }],
    }));
    const mismatched = new Uint8Array(128).fill(9);
    const mismatchedB64 = Buffer.from(mismatched).toString("base64url");
    await act(async () => relay?.emit({
      ...baseFrame,
      sender_public_key_b64: mismatchedB64,
      identity_public_b64: mismatchedB64,
    }));
    await act(async () => relay?.emit({ ...baseFrame, sender_public_key_b64: "AAAA" }));
    expect(mocks.FakeCipher.decryptCount).toBe(0);

    const rotated = mocks.identityPublicKey.slice();
    rotated.fill(8, 64);
    const rotatedB64 = Buffer.from(rotated).toString("base64url");
    await act(async () => relay?.emit({
      ...baseFrame,
      sender_public_key_b64: rotatedB64,
      identity_public_b64: rotatedB64,
    }));
    await waitFor(() => expect(mocks.FakeCipher.decryptCount).toBe(1));
    expect(result.current.messages[room.id]).toHaveLength(1);
    expect(result.current.session).not.toBeNull();
    unmount();
  });

  it("fails closed when repeated presence catalogs exceed the identity pin bound", async () => {
    const { result, unmount } = renderHook(() => useAbyssalSession());
    await act(async () => {
      await result.current.login({
        nodeUrl: "https://node.example.test",
        code: "ABCD-1234",
        password: "password",
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    const presenceBatch = (batch: number) => Array.from({ length: 128 }, (_, index) => ({
      username: `User_${batch}_${index}`,
      connected: true,
      identity_public_b64: validPublicKeyB64,
      identity_prekey_id: "prekey-one",
      directory_digest: "A".repeat(43),
    }));

    for (let batch = 0; batch < 8; batch += 1) {
      await act(async () => relay?.emit({ type: "presence", users: presenceBatch(batch) }));
    }
    await waitFor(() => expect(result.current.presence[0]?.username).toBe("User_7_0"));
    expect(result.current.session).not.toBeNull();

    await act(async () => relay?.emit({ type: "presence", users: presenceBatch(8) }));
    await waitFor(() => expect(result.current.session).toBeNull());
    expect(result.current.presence).toEqual([]);
    unmount();
  });

  it("synchronously purges session state, messages, and decrypted media on pagehide", async () => {
    const { result, unmount } = renderHook(() => useAbyssalSession());

    await act(async () => {
      await result.current.login({
        nodeUrl: "https://node.example.test",
        code: "ABCD-1234",
        password: "password",
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    expect(relay).not.toBeNull();

    await act(async () => {
      relay?.emit({ type: "rooms", rooms: [room] });
      relay?.emit({
        type: "presence",
        users: [
          {
            username: "Alice",
            connected: true,
            identity_public_b64: validPublicKeyB64,
            identity_prekey_id: "prekey-one",
            directory_digest: "A".repeat(43),
          },
          {
            username: "Bob",
            connected: true,
            identity_public_b64: validPublicKeyB64,
            identity_prekey_id: "prekey-two",
            directory_digest: "A".repeat(43),
          },
        ],
      });
    });

    await waitFor(() => expect(result.current.rooms).toHaveLength(1));
    act(() => result.current.openRoom(room.id));
    await act(async () => {
      await result.current.sendText("local secret");
    });
    expect(result.current.messages[room.id]).toHaveLength(1);

    const attachmentMessage = {
      id: "attachment-message",
      chatId: room.id,
      sender: "Bob",
      content: "secret.txt",
      kind: "attachment" as const,
      createdAtMs: Date.now(),
      receivedAtMs: Date.now(),
      selfDestructSec: 0,
      absoluteExpirySec: 0,
      mine: false,
      attachment: {
        id: "123e4567-e89b-42d3-a456-426614174000",
        encryptionVersion: 1,
        encryptionKey: new Uint8Array(32).fill(9),
        name: "secret.txt",
        mediaType: "FILE" as const,
        mimeType: "text/plain",
        sizeBytes: 3,
        oneTime: false,
        deleteAfterDownload: false,
      },
    };
    await act(async () => {
      await result.current.viewAttachment(attachmentMessage);
    });
    expect(result.current.media?.objectUrl).toBe("blob:decrypted-media");
    expect(URL.revokeObjectURL).not.toHaveBeenCalled();

    act(() => {
      window.dispatchEvent(new Event("pagehide"));
    });

    expect(result.current.session).toBeNull();
    expect(result.current.messages).toEqual({});
    expect(result.current.media).toBeNull();
    expect(result.current.activeRoomId).toBeNull();
    expect(document.documentElement).toHaveClass("abyssal-page-hidden");
    expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:decrypted-media");
    expect(mocks.revokeSession).toHaveBeenCalledOnce();

    unmount();
  });

  it("revokes viewed media and clears private navigation without logging out", async () => {
    const { result, unmount } = renderHook(() => useAbyssalSession());
    await act(async () => {
      await result.current.login({
        nodeUrl: "https://node.example.test",
        code: "ABCD-1234",
        password: "password",
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    await act(async () => relay?.emit({ type: "rooms", rooms: [room] }));
    await waitFor(() => expect(result.current.rooms).toHaveLength(1));
    act(() => result.current.openRoom(room.id));
    await act(async () => {
      await result.current.viewAttachment({
        id: "attachment-message",
        chatId: room.id,
        sender: "Bob",
        content: "secret.txt",
        kind: "attachment",
        createdAtMs: Date.now(),
        receivedAtMs: Date.now(),
        selfDestructSec: 0,
        absoluteExpirySec: 0,
        mine: false,
        attachment: {
          id: "123e4567-e89b-42d3-a456-426614174000",
          encryptionVersion: 1,
          encryptionKey: new Uint8Array(32).fill(9),
          name: "secret.txt",
          mediaType: "FILE",
          mimeType: "text/plain",
          sizeBytes: 3,
          oneTime: false,
          deleteAfterDownload: false,
        },
      });
    });
    expect(result.current.media).not.toBeNull();

    act(() => result.current.clearPrivateView());

    expect(result.current.session).not.toBeNull();
    expect(result.current.activeRoomId).toBeNull();
    expect(result.current.media).toBeNull();
    expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:decrypted-media");
    expect(mocks.revokeSession).not.toHaveBeenCalled();
    unmount();
  });

  it("rejects a finish response from a different node and revokes its candidate session", async () => {
    mocks.startOpaqueAccount.mockResolvedValueOnce({
      accepted: true,
      mode: "registration",
      handshake_id: "handshake-one",
      response_b64: "AQ",
      node_id: "different-node",
    });
    const { result, unmount } = renderHook(() => useAbyssalSession());

    await act(async () => {
      await expect(result.current.login({
        nodeUrl: "https://node.example.test",
        code: "ABCD-1234",
        password: "password",
        retainWhenHidden: true,
      })).rejects.toThrow("Wrong information");
    });

    expect(result.current.session).toBeNull();
    expect(mocks.revokeSession).toHaveBeenCalledOnce();
    expect(mocks.getLastRelay()).toBeNull();
    unmount();
  });

  it("rejects a registration finish marked as an existing login", async () => {
    mocks.finishOpaqueAccount.mockResolvedValueOnce({
      ...mocks.accountSession,
      created: false,
      identityPublicKey: mocks.identityPublicKey.slice(),
    });
    const { result, unmount } = renderHook(() => useAbyssalSession());

    await act(async () => {
      await expect(result.current.login({
        nodeUrl: "https://node.example.test",
        code: "ABCD-1234",
        password: "password",
        retainWhenHidden: true,
      })).rejects.toThrow("Wrong information");
    });

    expect(result.current.session).toBeNull();
    expect(mocks.revokeSession).toHaveBeenCalledOnce();
    expect(mocks.getLastRelay()).toBeNull();
    unmount();
  });
});

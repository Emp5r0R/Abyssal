import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AccountSession, IncomingFrame, RoomRecord } from "../domain/types";

const mocks = vi.hoisted(() => {
  const identityPublicKey = new Uint8Array(608).fill(7);
  const nodeEndpoint = {
    apiBaseUrl: "https://node.example.test",
    wsBaseUrl: "wss://node.example.test",
    displayHost: "node.example.test",
  };
  class FakeCipher {
    static failAcknowledgement = false;
    static encryptError: Error | null = null;
    static decryptError: Error | null = null;
    static decryptCount = 0;
    static requiredPeers = new Set<string>();
    static payloadIdOverride: string | null = null;
    static plaintextOverride: Record<string, unknown> | null = null;
    static lastAttachmentPlain: Uint8Array | null = null;
    static lastAttachmentKey: Uint8Array | null = null;
    static lastAttachmentBlob: Uint8Array | null = null;
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

    requiresPrekey(peer: string): boolean {
      return FakeCipher.requiredPeers.has(peer);
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

    signRegistrationIdentityProof(): Uint8Array {
      return new Uint8Array(64).fill(9);
    }

    encryptText() {
      if (FakeCipher.encryptError) throw FakeCipher.encryptError;
      return {
        version: 9,
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

    commitOutbound(): void {}
    rollbackOutbound(): void {}

    decryptText(_chatId: string, messageId: string) {
      FakeCipher.decryptCount += 1;
      if (FakeCipher.decryptError) throw FakeCipher.decryptError;
      if (FakeCipher.plaintextOverride) return JSON.stringify(FakeCipher.plaintextOverride);
      return JSON.stringify({
        kind: "text",
        id: FakeCipher.payloadIdOverride ?? messageId,
        sender: "Bob",
        content: "incoming secret",
        timestamp_ms: Date.now(),
      });
    }

    encryptAttachment(_chatId: string, _messageId: string, _sender: string, _mediaType: string, plain: Uint8Array) {
      const key = new Uint8Array(32).fill(9);
      const blob = new Uint8Array(plain.byteLength + 41).fill(8);
      FakeCipher.lastAttachmentPlain = plain;
      FakeCipher.lastAttachmentKey = key;
      FakeCipher.lastAttachmentBlob = blob;
      return { version: 1, key, blob };
    }

    decryptAttachment(): Uint8Array {
      return new Uint8Array([8, 9, 10]);
    }

    clear(): void {
      this.publicKeyBytes?.fill(0);
      this.publicKeyBytes = null;
    }
  }

  class FakeRelay {
    static readonly instances: FakeRelay[] = [];
    static encryptedOutcome: "ACCEPTED" | "REJECTED" | "NOT_SENT" | "AMBIGUOUS" = "ACCEPTED";
    static leaseFailureAt: number | null = null;
    static leaseFailureCode: "NOT_SENT" | "AMBIGUOUS" | "CLOSED" = "NOT_SENT";
    static acknowledgeResult: Promise<typeof FakeRelay.encryptedOutcome> | null = null;
    private readonly frameHandler: (frame: IncomingFrame) => void;
    readonly session: AccountSession;
    connected = false;
    closed = false;
    sent: object[] = [];
    leasesRequested: string[] = [];
    leasesReleased: string[] = [];

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

    sendEncryptedPayload(_messageId: string, frame: object): Promise<typeof FakeRelay.encryptedOutcome> {
      this.send(frame);
      return Promise.resolve(FakeRelay.encryptedOutcome);
    }

    requestPrekeyLease(chatId: string, messageId: string, recipientUsername: string) {
      this.leasesRequested.push(recipientUsername);
      if (FakeRelay.leaseFailureAt !== null &&
        this.leasesRequested.length > FakeRelay.leaseFailureAt) {
        return Promise.reject(Object.assign(new Error("lease rejected"), {
          code: FakeRelay.leaseFailureCode,
        }));
      }
      return Promise.resolve({
        chatId,
        messageId,
        recipientUsername,
        recipientPublicKey: identityPublicKey.slice(),
        prekeyId: `lease-${recipientUsername}`,
        expiresAtMs: Date.now() + 60_000,
      });
    }

    releasePrekeyLease(lease: { prekeyId: string }): boolean {
      this.leasesReleased.push(lease.prekeyId);
      return this.send({ type: "prekey_lease_release", prekey_id: lease.prekeyId });
    }

    join(): boolean { return this.send({ type: "join" }); }
    openDirect(): boolean { return this.send({ type: "open_direct" }); }
    createRoom(): boolean { return this.send({ type: "create_room" }); }
    deleteRoom(): boolean { return this.send({ type: "delete_room" }); }
    wipe(): boolean { return this.send({ type: "global_wipe" }); }
    activity(): boolean { return this.send({ type: "activity" }); }
    acknowledge(...args: unknown[]): Promise<typeof FakeRelay.encryptedOutcome> {
      this.send({ type: "message_ack", args });
      return FakeRelay.acknowledgeResult ?? Promise.resolve(FakeRelay.encryptedOutcome);
    }

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
      FakeRelay.encryptedOutcome = "ACCEPTED";
      FakeRelay.leaseFailureAt = null;
      FakeRelay.leaseFailureCode = "NOT_SENT";
      FakeRelay.acknowledgeResult = null;
      FakeCipher.failAcknowledgement = false;
      FakeCipher.encryptError = null;
      FakeCipher.decryptError = null;
      FakeCipher.decryptCount = 0;
      FakeCipher.requiredPeers.clear();
      FakeCipher.payloadIdOverride = null;
      FakeCipher.plaintextOverride = null;
      FakeCipher.lastAttachmentPlain = null;
      FakeCipher.lastAttachmentKey = null;
      FakeCipher.lastAttachmentBlob = null;
      FakeCipher.lastSnapshot = null;
    },
    startOpaqueAccount: vi.fn(async () => ({
      accepted: true,
      mode: "registration" as const,
      handshake_id: "handshake-one",
      response_b64: "AQ",
      challenge_b64: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
      node_id: "node-one",
    })),
    finishOpaqueAccount: vi.fn(async () => ({
      ...mocks.accountSession,
      identityPublicKey: mocks.identityPublicKey.slice(),
    })),
    revokeSession: vi.fn(async () => undefined),
    downloadEncryptedAttachment: vi.fn(async () => ({ bytes: new Uint8Array([1, 2, 3]) })),
    decryptAndCompleteAttachment: vi.fn(async () => new Uint8Array([8, 9, 10])),
    uploadEncryptedAttachment: vi.fn(async () => "123e4567-e89b-42d3-a456-426614174000"),
    deleteUploadedAttachment: vi.fn(async () => undefined),
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
      version: 9,
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
    uploadEncryptedAttachment: mocks.uploadEncryptedAttachment,
    deleteUploadedAttachment: mocks.deleteUploadedAttachment,
  };
});

import { FatalCipherError } from "../security/crypto";
import { rememberBoundedId, useAbyssalSession } from "./useAbyssalSession";

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
      version: 9,
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

  it("does not repopulate messages or receipts when an ACK resolves after logout", async () => {
    let resolveAck: ((outcome: "ACCEPTED" | "REJECTED" | "NOT_SENT" | "AMBIGUOUS") => void) | undefined;
    mocks.FakeRelay.acknowledgeResult = new Promise((resolve) => {
      resolveAck = resolve;
    });
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
    const frame: IncomingFrame = {
      type: "message",
      chat_id: room.id,
      version: 9,
      message_id: "late-ack-message",
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
    await waitFor(() => expect(resolveAck).toBeDefined());
    expect(result.current.messages).toEqual({});

    await act(async () => {
      await result.current.logout();
    });
    expect(result.current.session).toBeNull();
    expect(result.current.messages).toEqual({});
    expect(result.current.rooms).toEqual([]);
    expect(result.current.presence).toEqual([]);

    await act(async () => {
      resolveAck?.("ACCEPTED");
      await Promise.resolve();
    });
    await act(async () => relay?.emit(frame));
    await Promise.resolve();
    expect(result.current.session).toBeNull();
    expect(result.current.messages).toEqual({});
    expect(result.current.rooms).toEqual([]);
    expect(result.current.presence).toEqual([]);
    expect(relay?.sent.filter((item) => (item as { type?: string }).type === "message_ack")).toHaveLength(1);
    expect(relay?.sent.filter((item) => (item as { type?: string }).type === "message")).toHaveLength(0);
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
      version: 9,
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

    const retiredIdentityB64 = Buffer.from(new Uint8Array(128).fill(7)).toString("base64url");
    await act(async () => relay?.emit({
      type: "presence",
      users: [{
        username: "Bob",
        connected: true,
        identity_public_b64: retiredIdentityB64,
        identity_prekey_id: "prekey-one",
        directory_digest: "A".repeat(43),
      }],
    }));
    expect(result.current.presence).toEqual([]);
    await act(async () => relay?.emit({ ...baseFrame, version: 8 }));
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
    const mismatched = new Uint8Array(608).fill(9);
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

  it("rejects unknown conversations and third-party senders before direct decrypt or ACK", async () => {
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
      relay?.emit({ type: "directs", directs: [{ id: "dm_bob", peer_username: "Bob" }] });
      relay?.emit({
        type: "presence",
        users: ["Bob", "Mallory"].map((username) => ({
          username,
          connected: true,
          identity_public_b64: validPublicKeyB64,
          identity_prekey_id: "prekey-one",
          directory_digest: "A".repeat(43),
        })),
      });
    });
    const frame = (chatId: string, sender: string, messageId: string): IncomingFrame => ({
      type: "message",
      chat_id: chatId,
      version: 9,
      message_id: messageId,
      nonce_b64: "AQ",
      ciphertext_b64: "Ag",
      signature_b64: "Aw",
      wrapped_key_b64: "BA",
      sender_username: sender,
      sender_public_key_b64: validPublicKeyB64,
      identity_public_b64: validPublicKeyB64,
      prekey_id: "prekey-one",
      is_prekey: false,
    });

    await act(async () => {
      relay?.emit(frame("dm_bob", "Mallory", "third-party"));
      relay?.emit(frame("dm_unknown", "Bob", "unknown-chat"));
    });
    expect(mocks.FakeCipher.decryptCount).toBe(0);
    expect(relay?.sent.filter((item) => (item as { type?: string }).type === "message_ack")).toHaveLength(0);
    expect(result.current.messages).toEqual({});

    await act(async () => relay?.emit(frame("dm_bob", "Bob", "peer-message")));
    await waitFor(() => expect(mocks.FakeCipher.decryptCount).toBe(1));
    expect(result.current.messages.dm_bob).toHaveLength(1);
    expect(relay?.sent.filter((item) => (item as { type?: string }).type === "message_ack")).toHaveLength(1);
    unmount();
  });

  it("drops authenticated plaintext whose inner ID differs from the frame ID", async () => {
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
    mocks.FakeCipher.payloadIdOverride = "different-id";
    await act(async () => relay?.emit({
      type: "message",
      chat_id: room.id,
      version: 9,
      message_id: "outer-id",
      nonce_b64: "AQ",
      ciphertext_b64: "Ag",
      signature_b64: "Aw",
      wrapped_key_b64: "BA",
      sender_username: "Bob",
      sender_public_key_b64: validPublicKeyB64,
      identity_public_b64: validPublicKeyB64,
      prekey_id: "prekey-one",
      is_prekey: false,
    }));
    await waitFor(() => expect(mocks.FakeCipher.decryptCount).toBe(1));
    expect(result.current.messages[room.id]).toBeUndefined();
    expect(relay?.sent.filter((item) => (item as { type?: string }).type === "message_ack")).toHaveLength(1);
    unmount();
  });

  it("drops ordinary decrypt failures but fails closed for fatal decrypt wrapper failures", async () => {
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
    const frame = (messageId: string): IncomingFrame => ({
      type: "message",
      chat_id: room.id,
      version: 9,
      message_id: messageId,
      nonce_b64: "AQ",
      ciphertext_b64: "Ag",
      signature_b64: "Aw",
      wrapped_key_b64: "BA",
      sender_username: "Bob",
      sender_public_key_b64: validPublicKeyB64,
      identity_public_b64: validPublicKeyB64,
      prekey_id: "prekey-one",
      is_prekey: false,
    });

    mocks.FakeCipher.decryptError = new Error("malformed ciphertext");
    await act(async () => relay?.emit(frame("ordinary-decrypt-failure")));
    await waitFor(() => expect(mocks.FakeCipher.decryptCount).toBe(1));
    expect(result.current.session).not.toBeNull();
    expect(result.current.messages).toEqual({});

    mocks.FakeCipher.decryptError = new FatalCipherError();
    await act(async () => relay?.emit(frame("fatal-decrypt-wrapper")));
    await waitFor(() => expect(result.current.session).toBeNull());
    expect(result.current.messages).toEqual({});
    expect(mocks.revokeSession).toHaveBeenCalledOnce();
    unmount();
  });

  it("applies a read receipt only when its inner ID matches the authenticated frame ID", async () => {
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
    act(() => result.current.openRoom(room.id));
    await act(async () => expect(result.current.sendText("outgoing secret")).resolves.toBe(true));
    const ownMessageId = result.current.messages[room.id]?.[0]?.id;
    expect(ownMessageId).toBeDefined();

    const receiptFrame = (messageId: string): IncomingFrame => ({
      type: "message",
      chat_id: room.id,
      version: 9,
      message_id: messageId,
      nonce_b64: "AQ",
      ciphertext_b64: "Ag",
      signature_b64: "Aw",
      wrapped_key_b64: "BA",
      sender_username: "Bob",
      sender_public_key_b64: validPublicKeyB64,
      identity_public_b64: validPublicKeyB64,
      prekey_id: "prekey-one",
      is_prekey: false,
    });
    mocks.FakeCipher.plaintextOverride = {
      kind: "read_receipt",
      id: "different-receipt-id",
      message_id: ownMessageId,
    };
    await act(async () => relay?.emit(receiptFrame("outer-receipt-id")));
    expect(result.current.messages[room.id]?.[0]?.readAtMs).toBeUndefined();

    mocks.FakeCipher.plaintextOverride = {
      kind: "read_receipt",
      id: "matching-receipt-id",
      message_id: ownMessageId,
    };
    await act(async () => relay?.emit(receiptFrame("matching-receipt-id")));
    await waitFor(() => expect(result.current.messages[room.id]?.[0]?.readAtMs).toEqual(expect.any(Number)));
    unmount();
  });

  it("bounds sent-message IDs with deterministic oldest eviction", () => {
    const ids = new Set(["first", "second", "third"]);
    rememberBoundedId(ids, "fourth", 3);
    expect([...ids]).toEqual(["second", "third", "fourth"]);
    rememberBoundedId(ids, "third", 3);
    expect([...ids]).toEqual(["second", "third", "fourth"]);
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

  it("aborts an in-flight attachment upload and promptly wipes its plaintext and cipher buffers", async () => {
    let uploadSignal: AbortSignal | undefined;
    mocks.uploadEncryptedAttachment.mockImplementationOnce((...args: unknown[]) => new Promise<string>((_resolve, reject) => {
      uploadSignal = args[6] as AbortSignal;
      uploadSignal.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")), { once: true });
    }));
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
    act(() => result.current.openRoom(room.id));
    let pending: Promise<boolean> | undefined;
    act(() => {
      pending = result.current.sendAttachment({
        file: new File([new Uint8Array([1, 2, 3])], "secret.bin", { type: "application/octet-stream" }),
        options: { oneTime: false, deleteAfterDownload: false, ttlSec: 0 },
      });
    });
    await waitFor(() => expect(uploadSignal).toBeDefined());

    act(() => result.current.clearMemory());
    await act(async () => expect(pending).resolves.toBe(false));

    expect(uploadSignal?.aborted).toBe(true);
    expect(mocks.FakeCipher.lastAttachmentPlain?.every((byte) => byte === 0)).toBe(true);
    expect(mocks.FakeCipher.lastAttachmentKey?.every((byte) => byte === 0)).toBe(true);
    expect(mocks.FakeCipher.lastAttachmentBlob?.every((byte) => byte === 0)).toBe(true);
    expect(result.current.session).toBeNull();
    expect(result.current.upload.active).toBe(false);
    unmount();
  });

  it("does not delete an attachment when metadata delivery is ambiguous", async () => {
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
    act(() => result.current.openRoom(room.id));
    mocks.FakeRelay.encryptedOutcome = "AMBIGUOUS";
    await act(async () => expect(result.current.sendAttachment({
      file: new File([new Uint8Array([1, 2, 3])], "secret.bin", { type: "application/octet-stream" }),
      options: { oneTime: false, deleteAfterDownload: false, ttlSec: 0 },
    })).resolves.toBe(false));
    expect(mocks.deleteUploadedAttachment).not.toHaveBeenCalled();
    expect(result.current.session).toBeNull();
    unmount();
  });

  it("fails closed when outbound encryption reports an unrecoverable staged state", async () => {
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
    act(() => result.current.openRoom(room.id));
    mocks.FakeCipher.requiredPeers.add("Bob");
    mocks.FakeCipher.encryptError = new FatalCipherError();

    await act(async () => expect(result.current.sendText("must not publish")).resolves.toBe(false));

    expect(relay?.leasesReleased).toEqual(["lease-Bob"]);
    expect(result.current.session).toBeNull();
    expect(result.current.messages[room.id]).toBeUndefined();
    expect(mocks.revokeSession).toHaveBeenCalledOnce();
    unmount();
  });

  it("aborts an in-flight attachment download, wipes the copied key, and revokes exports on purge", async () => {
    let downloadSignal: AbortSignal | undefined;
    mocks.downloadEncryptedAttachment.mockImplementationOnce((...args: unknown[]) => new Promise(( _resolve, reject) => {
      downloadSignal = args[3] as AbortSignal;
      downloadSignal.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")), { once: true });
    }));
    const { result, unmount } = renderHook(() => useAbyssalSession());
    await act(async () => {
      await result.current.login({
        nodeUrl: "https://node.example.test",
        code: "ABCD-1234",
        password: "password",
        retainWhenHidden: true,
      });
    });
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
    const originalSlice = Uint8Array.prototype.slice;
    const copiedKeys: Uint8Array[] = [];
    const sliceSpy = vi.spyOn(Uint8Array.prototype, "slice").mockImplementation(function (
      this: Uint8Array,
      start?: number,
      end?: number,
    ) {
      const copy = originalSlice.call(this, start, end);
      if (this === attachmentMessage.attachment.encryptionKey) copiedKeys.push(copy);
      return copy;
    });
    let pending: Promise<void> | undefined;
    act(() => { pending = result.current.viewAttachment(attachmentMessage); });
    await waitFor(() => expect(downloadSignal).toBeDefined());

    act(() => result.current.clearMemory());
    await act(async () => pending);
    sliceSpy.mockRestore();

    expect(downloadSignal?.aborted).toBe(true);
    expect(copiedKeys).toHaveLength(1);
    expect(copiedKeys[0]?.every((byte) => byte === 0)).toBe(true);
    expect(result.current.media).toBeNull();

    mocks.downloadEncryptedAttachment.mockResolvedValueOnce({ bytes: new Uint8Array([1, 2, 3]) });
    await act(async () => {
      await result.current.login({
        nodeUrl: "https://node.example.test",
        code: "ABCD-1234",
        password: "password",
        retainWhenHidden: true,
      });
    });
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    await act(async () => result.current.exportAttachment(attachmentMessage));
    expect(URL.revokeObjectURL).not.toHaveBeenCalledWith("blob:decrypted-media");
    act(() => result.current.clearMemory());
    expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:decrypted-media");
    clickSpy.mockRestore();
    unmount();
  });

  it("rejects a finish response from a different node and revokes its candidate session", async () => {
    mocks.startOpaqueAccount.mockResolvedValueOnce({
      accepted: true,
      mode: "registration",
      handshake_id: "handshake-one",
      response_b64: "AQ",
      challenge_b64: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
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

  it("leases only direct first contact and keeps established sends lease-free", async () => {
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
      relay?.emit({ type: "directs", directs: [{ id: "dm_bob", peer_username: "Bob" }] });
      relay?.emit({ type: "presence", users: [{
        username: "Bob",
        connected: true,
        identity_public_b64: validPublicKeyB64,
        identity_prekey_id: "catalog-key",
        directory_digest: "A".repeat(43),
      }] });
    });
    await waitFor(() => {
      expect(result.current.directs).toHaveLength(1);
      expect(result.current.presence).toHaveLength(1);
      expect(result.current.connection).toBe("connected");
    });
    act(() => result.current.openRoom("dm_bob"));
    await waitFor(() => expect(result.current.activeRoomId).toBe("dm_bob"));

    mocks.FakeCipher.requiredPeers.add("Bob");
    await act(async () => expect(await result.current.sendText("first")).toBe(true));
    expect(relay?.leasesRequested).toEqual(["Bob"]);
    expect(relay?.leasesReleased).toEqual([]);

    mocks.FakeCipher.requiredPeers.delete("Bob");
    await act(async () => expect(await result.current.sendText("established")).toBe(true));
    expect(relay?.leasesRequested).toEqual(["Bob"]);
    expect(relay?.leasesReleased).toEqual([]);
    unmount();
  });

  it("releases partial timeout and rejected room leases but never ambiguous admission", async () => {
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
      relay?.emit({ type: "presence", users: ["Bob", "Carol"].map((username) => ({
        username,
        connected: true,
        identity_public_b64: validPublicKeyB64,
        identity_prekey_id: "catalog-key",
        directory_digest: "A".repeat(43),
      })) });
    });
    await waitFor(() => {
      expect(result.current.rooms).toHaveLength(1);
      expect(result.current.presence).toHaveLength(2);
      expect(result.current.connection).toBe("connected");
    });
    act(() => result.current.openRoom(room.id));
    await waitFor(() => expect(result.current.activeRoomId).toBe(room.id));
    mocks.FakeCipher.requiredPeers.add("Bob");
    mocks.FakeCipher.requiredPeers.add("Carol");

    mocks.FakeRelay.leaseFailureAt = 1;
    mocks.FakeRelay.leaseFailureCode = "AMBIGUOUS";
    await act(async () => expect(await result.current.sendText("partial")).toBe(false));
    expect(relay?.leasesReleased).toHaveLength(1);

    mocks.FakeRelay.leaseFailureAt = null;
    mocks.FakeRelay.encryptedOutcome = "REJECTED";
    await act(async () => expect(await result.current.sendText("rejected")).toBe(false));
    expect(relay?.leasesReleased).toHaveLength(3);

    mocks.FakeRelay.encryptedOutcome = "AMBIGUOUS";
    await act(async () => expect(await result.current.sendText("ambiguous")).toBe(false));
    expect(relay?.leasesReleased).toHaveLength(3);
    unmount();
  });
});

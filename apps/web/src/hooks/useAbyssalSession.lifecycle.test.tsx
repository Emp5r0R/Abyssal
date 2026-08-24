import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { createHash } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type {
  AccountSession,
  DirectoryStamp,
  IncomingFrame,
  PresenceUser,
  RoomRecord,
} from "../domain/types";

const mocks = vi.hoisted(() => {
  const identityPublicKey = new Uint8Array(608).fill(7);
  const nodeEndpoint = {
    apiBaseUrl: "https://node.example.test",
    wsBaseUrl: "wss://node.example.test",
    displayHost: "node.example.test",
  };
  class FakeMlsManager {
    static instances: FakeMlsManager[] = [];
    closed = false;
    finishOutcomes: string[] = [];
    snapshotOutcomes: string[] = [];
    receiveApplicationCount = 0;
    pendingJoinItems: Array<{ roomId: string; requestId: string; username: string }> = [];
    ownJoin: { roomId: string; requestId: string } | null = null;
    pendingLeaveItems: Array<{ roomId: string; requestId: string; username: string }> = [];
    constructor() { FakeMlsManager.instances.push(this); }
    close() { this.closed = true; }
    recoverCatalog(rooms: Array<{ room_id: string; owner_username: string; active: boolean }>) {
      return rooms.map((room) => ({
        id: room.room_id, name: "MLS room", owner_username: room.owner_username, conversation_type: "room" as const,
        mlsActive: room.active, self_destruct_timer_sec: 0, overall_expiry_sec: 0, allow_images: true, allow_videos: true,
        allow_files: true, enforce_text_absolute_expiry: false, image_read_timer_sec: 0, image_overall_expiry_sec: 0,
        enforce_image_absolute_expiry: false, video_read_timer_sec: 0, video_overall_expiry_sec: 0,
        enforce_video_absolute_expiry: false, file_read_timer_sec: 0, file_overall_expiry_sec: 0,
        enforce_file_absolute_expiry: false,
      }));
    }
    removeRoom(roomId?: string) {
      if (!roomId) return;
      this.pendingLeaveItems = this.pendingLeaveItems.filter((leave) => leave.roomId !== roomId);
      this.pendingJoinItems = this.pendingJoinItems.filter((join) => join.roomId !== roomId);
      if (this.ownJoin?.roomId === roomId) this.ownJoin = null;
    }
    beginJoin(frame: { room_id: string }) {
      this.ownJoin = { roomId: frame.room_id, requestId: "own-join-request" };
      return { type: "mls_join_request", protocol_version: 10, room_id: frame.room_id, request_id: "own-join-request" };
    }
    rejectOwnJoin(roomId: string, requestId: string) {
      if (this.ownJoin?.roomId !== roomId || this.ownJoin.requestId !== requestId) throw new Error("Room unavailable");
      this.ownJoin = null;
    }
    rememberJoin(frame: { room_id: string; request_id: string; username: string }) {
      const existing = this.pendingJoinItems.find((join) => join.requestId === frame.request_id);
      if (existing && (existing.roomId !== frame.room_id || existing.username !== frame.username)) throw new Error("Room unavailable");
      if (!existing) this.pendingJoinItems.push({ roomId: frame.room_id, requestId: frame.request_id, username: frame.username });
    }
    pendingJoins() { return this.pendingJoinItems.map((join) => ({ ...join })); }
    rejectJoin(requestId: string) {
      const request = this.pendingJoinItems.find((join) => join.requestId === requestId);
      if (!request) throw new Error("Room unavailable");
      return { type: "mls_join_reject", protocol_version: 10, room_id: request.roomId, request_id: requestId };
    }
    forgetJoin(roomId: string, requestId: string) {
      const request = this.pendingJoinItems.find((join) => join.requestId === requestId);
      if (!request || request.roomId !== roomId) throw new Error("Room unavailable");
      this.pendingJoinItems = this.pendingJoinItems.filter((join) => join.requestId !== requestId);
    }
    pendingLeaves() { return this.pendingLeaveItems.map((leave) => ({ ...leave })); }
    rememberLeave(frame: { room_id: string; request_id: string; username: string }) {
      const existing = this.pendingLeaveItems.find((leave) => leave.requestId === frame.request_id);
      if (existing && (existing.roomId !== frame.room_id || existing.username !== frame.username)) throw new Error("Room unavailable");
      if (!existing) this.pendingLeaveItems.push({ roomId: frame.room_id, requestId: frame.request_id, username: frame.username });
    }
    beginLeave(roomId: string) {
      const frame = { type: "mls_leave_request", protocol_version: 10, room_id: roomId, request_id: "member-leave" };
      this.pendingLeaveItems.push({ roomId, requestId: frame.request_id, username: "Alice" });
      return frame;
    }
    acceptLeave(requestId: string) {
      const request = this.pendingLeaveItems.find((leave) => leave.requestId === requestId);
      if (!request) throw new Error("Room unavailable");
      return {
        roomId: request.roomId, messageId: "leave-membership", revision: 2n, requestId, requestType: "leave",
        frame: { type: "mls_membership_commit", room_id: request.roomId, message_id: "leave-membership", revision: "2", request_id: requestId },
      };
    }
    rejectLeave(requestId: string) {
      const request = this.pendingLeaveItems.find((leave) => leave.requestId === requestId);
      if (!request) throw new Error("Room unavailable");
      return { type: "mls_leave_reject", protocol_version: 10, room_id: request.roomId, request_id: requestId };
    }
    forgetLeave(roomId: string, requestId: string) {
      this.pendingLeaveItems = this.pendingLeaveItems.filter((leave) => leave.roomId !== roomId || leave.requestId !== requestId);
    }
    prepareApplication(roomId: string, messageId: string) {
      return { roomId, messageId, revision: 2n, frame: { type: "mls_application", room_id: roomId, message_id: messageId, revision: "2" } };
    }
    finishTransaction(prepared: { requestType?: string; requestId?: string; roomId?: string }, outcome: string) {
      this.finishOutcomes.push(outcome);
      if (outcome === "ACCEPTED" && prepared.requestType === "leave" && prepared.requestId && prepared.roomId) {
        this.forgetLeave(prepared.roomId, prepared.requestId);
      }
    }
    receiveApplication(frame: { room_id: string; message_id: string }) {
      this.receiveApplicationCount += 1;
      return {
        plaintext: new TextEncoder().encode(JSON.stringify({
          kind: "text", id: frame.message_id, sender: "Bob", content: "incoming MLS", timestamp_ms: Date.now(),
          sender_client: "android",
        })),
        snapshot: {
          roomId: frame.room_id, messageId: frame.message_id, revision: 3n, nativePending: true,
          frame: { type: "mls_state_snapshot", protocol_version: 10, room_id: frame.room_id, message_id: frame.message_id, revision: "3" },
        },
      };
    }
    finishSnapshot(_prepared: unknown, outcome: string) { this.snapshotOutcomes.push(outcome); }
  }
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
    static encryptedPlaintexts: string[] = [];
    static directoryStamp: DirectoryStamp = {
      directory_node_id: "node-one",
      directory_revision: 1,
      directory_digest: "",
    };
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

    encryptText(_chatId: string, _messageId: string, _sender: string, plaintext: string) {
      if (FakeCipher.encryptError) throw FakeCipher.encryptError;
      FakeCipher.encryptedPlaintexts.push(plaintext);
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
      const payload = FakeCipher.plaintextOverride ?? {
        kind: "text",
        id: FakeCipher.payloadIdOverride ?? messageId,
        sender: "Bob",
        content: "incoming secret",
        timestamp_ms: Date.now(),
        sender_client: "web",
      };
      return JSON.stringify({ ...FakeCipher.directoryStamp, ...payload });
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

    createMlsManager() {
      return new FakeMlsManager();
    }

    clear(): void {
      this.publicKeyBytes?.fill(0);
      this.publicKeyBytes = null;
    }
  }

  class FakeRelay {
    static readonly instances: FakeRelay[] = [];
    static encryptedOutcome: "ACCEPTED" | "REJECTED" | "NOT_SENT" | "AMBIGUOUS" = "ACCEPTED";
    static encryptedResult: Promise<typeof FakeRelay.encryptedOutcome> | null = null;
    static leaseFailureAt: number | null = null;
    static leaseFailureCode: "NOT_SENT" | "AMBIGUOUS" | "CLOSED" = "NOT_SENT";
    static acknowledgeResult: Promise<typeof FakeRelay.encryptedOutcome> | null = null;
    static mlsControlResult = true;
    private readonly frameHandler: (frame: IncomingFrame) => void;
    readonly session: AccountSession;
    connected = false;
    closed = false;
    sent: object[] = [];
    leasesRequested: string[] = [];
    leasesReleased: string[] = [];
    directoryStamp: DirectoryStamp | null = null;

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

    setDirectoryStamp(stamp: DirectoryStamp | null): void {
      this.directoryStamp = stamp ? { ...stamp } : null;
      if (stamp) FakeCipher.directoryStamp = { ...stamp };
    }

    sendEncryptedPayload(_messageId: string, frame: object): Promise<typeof FakeRelay.encryptedOutcome> {
      this.send(frame);
      return FakeRelay.encryptedResult ?? Promise.resolve(FakeRelay.encryptedOutcome);
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
    sendMlsControl(frame: object): boolean { return FakeRelay.mlsControlResult && this.send(frame); }
    sendMlsTransaction(_room: string, _message: string, _revision: bigint, frame: object): Promise<typeof FakeRelay.encryptedOutcome> {
      this.send(frame); return Promise.resolve(FakeRelay.encryptedOutcome);
    }
    sendMlsSnapshot(_room: string, _message: string, _revision: bigint, frame: object): Promise<typeof FakeRelay.encryptedOutcome> {
      this.send(frame); return Promise.resolve(FakeRelay.encryptedOutcome);
    }
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
    FakeMlsManager,
    FakeRelay,
    getLastRelay: () => FakeRelay.instances.at(-1) ?? null,
    reset: () => {
      FakeRelay.instances.length = 0;
      FakeRelay.encryptedOutcome = "ACCEPTED";
      FakeRelay.encryptedResult = null;
      FakeRelay.leaseFailureAt = null;
      FakeRelay.leaseFailureCode = "NOT_SENT";
      FakeRelay.acknowledgeResult = null;
      FakeRelay.mlsControlResult = true;
      FakeMlsManager.instances.length = 0;
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
      FakeCipher.encryptedPlaintexts = [];
      FakeCipher.directoryStamp = {
        directory_node_id: "node-one",
        directory_revision: 1,
        directory_digest: "",
      };
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
    conversationSafetyNumber: vi.fn(() => "1234 5678 9012"),
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
const DIRECTORY_NODE_ID = "node-one";
const DIRECTORY_REVISION = 1;

function directoryDigest(users: readonly PresenceUser[], nodeId = DIRECTORY_NODE_ID, revision = DIRECTORY_REVISION): string {
  const domain = Buffer.from("ABYSSAL_DIRECTORY_CHECKPOINT_V2", "utf8");
  const node = Buffer.from(nodeId, "utf8");
  const sorted = [...users].sort((left, right) => left.username < right.username ? -1 : left.username > right.username ? 1 : 0);
  const parts: Buffer[] = [
    domain,
    (() => { const bytes = Buffer.alloc(4); bytes.writeUInt32BE(node.byteLength); return bytes; })(),
    node,
    (() => { const bytes = Buffer.alloc(8); bytes.writeBigUInt64BE(BigInt(revision)); return bytes; })(),
    (() => { const bytes = Buffer.alloc(4); bytes.writeUInt32BE(sorted.length); return bytes; })(),
  ];
  sorted.forEach((user) => {
    const username = Buffer.from(user.username, "utf8");
    const identity = Buffer.from(user.identity_public_b64, "base64url");
    const length = Buffer.alloc(4);
    length.writeUInt32BE(username.byteLength);
    parts.push(length, username, identity.subarray(0, 64));
  });
  return createHash("sha256").update(Buffer.concat(parts)).digest("base64url");
}

function presenceUser(username: string, overrides: Partial<PresenceUser> = {}): PresenceUser {
  return {
    username,
    connected: true,
    identity_public_b64: validPublicKeyB64,
    identity_prekey_id: "prekey-one",
    directory_node_id: DIRECTORY_NODE_ID,
    directory_revision: DIRECTORY_REVISION,
    directory_digest: "",
    ...overrides,
  };
}

function presenceCatalog(
  entries: Array<string | Partial<PresenceUser>>,
  nodeId = DIRECTORY_NODE_ID,
  revision = DIRECTORY_REVISION,
): { users: PresenceUser[]; stamp: DirectoryStamp } {
  const users = entries.map((entry) => typeof entry === "string" ? presenceUser(entry) : presenceUser(entry.username ?? "User", entry));
  users.forEach((user) => {
    user.directory_node_id = nodeId;
    user.directory_revision = revision;
  });
  const digest = directoryDigest(users, nodeId, revision);
  users.forEach((user) => { user.directory_digest = digest; });
  return { users, stamp: { directory_node_id: nodeId, directory_revision: revision, directory_digest: digest } };
}

function stampedFrame(
  frame: Omit<Extract<IncomingFrame, { type: "message" }>, keyof DirectoryStamp>,
  stamp: DirectoryStamp,
): Extract<IncomingFrame, { type: "message" }> {
  return { ...frame, ...stamp };
}

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
        password: new TextEncoder().encode("password"),
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    const validPresence = presenceCatalog([
      "Alice",
      { username: "Bob", identity_prekey_id: "prekey-two" },
    ]).users;
    await act(async () => {
      relay?.emit({ type: "rooms", rooms: [room] });
      relay?.emit({ type: "presence", users: validPresence });
    });
    await waitFor(() => {
      expect(result.current.rooms).toHaveLength(1);
      expect(result.current.presence).toHaveLength(2);
    });

    const malformedRoom = { ...room, name: "x".repeat(37) };
    await act(async () => {
      relay?.emit({ type: "rooms", rooms: [malformedRoom] });
      relay?.emit({ type: "rooms", rooms: [room, room] });
      relay?.emit({ type: "rooms", rooms: [room, { ...room, id: "FORUM_OPS" }] });
    });
    expect(result.current.rooms).toEqual([room]);
    expect(result.current.presence).toEqual(validPresence);

    await act(async () => {
      relay?.emit({ type: "presence", users: [validPresence[0], validPresence[0]] });
    });
    await waitFor(() => expect(result.current.session).toBeNull());
    expect(result.current.rooms).toEqual([]);
    expect(result.current.presence).toEqual([]);
    unmount();
  });

  it.each([
    ["missing directory evidence", (user: PresenceUser) => {
      const missing = { ...user } as Partial<PresenceUser>;
      delete missing.directory_digest;
      return missing as PresenceUser;
    }],
    ["malformed directory digest", (user: PresenceUser) => ({
      ...user,
      directory_digest: `${"A".repeat(42)}B`,
    })],
    ["case-colliding usernames", (user: PresenceUser) => user],
  ] as const)("fails closed on %s presence evidence", async (_label, transform) => {
    const { result, unmount } = renderHook(() => useAbyssalSession());
    await act(async () => {
      await result.current.login({
        nodeUrl: "https://node.example.test",
        code: "ABCD-1234",
        password: new TextEncoder().encode("password"),
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    const catalog = presenceCatalog(["Bob"]);
    await act(async () => relay?.emit({ type: "presence", users: catalog.users }));
    await waitFor(() => expect(result.current.presence).toHaveLength(1));
    const users = _label === "case-colliding usernames"
      ? [catalog.users[0], { ...catalog.users[0], username: "bob" }]
      : [transform(catalog.users[0])];
    await act(async () => relay?.emit({ type: "presence", users: users as PresenceUser[] }));
    await waitFor(() => expect(result.current.session).toBeNull());
    expect(result.current.rooms).toEqual([]);
    expect(result.current.presence).toEqual([]);
    unmount();
  });

  it("fails closed when a catalog conflicts at an already-seen revision", async () => {
    const { result, unmount } = renderHook(() => useAbyssalSession());
    await act(async () => {
      await result.current.login({
        nodeUrl: "https://node.example.test",
        code: "ABCD-1234",
        password: new TextEncoder().encode("password"),
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    await act(async () => relay?.emit({ type: "presence", users: presenceCatalog(["Bob"]).users }));
    await waitFor(() => expect(result.current.presence).toHaveLength(1));
    await act(async () => relay?.emit({
      type: "presence",
      users: presenceCatalog(["Bob", "Carol"]).users,
    }));
    await waitFor(() => expect(result.current.session).toBeNull());
    expect(result.current.presence).toEqual([]);
    unmount();
  });

  it("fails closed when directory evidence is issued by a different node", async () => {
    const { result, unmount } = renderHook(() => useAbyssalSession());
    await act(async () => {
      await result.current.login({
        nodeUrl: "https://node.example.test",
        code: "ABCD-1234",
        password: new TextEncoder().encode("password"),
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    const foreign = presenceCatalog(["Bob"], "node-foreign", 1);
    await act(async () => relay?.emit({ type: "presence", users: foreign.users }));
    await waitFor(() => expect(result.current.session).toBeNull());
    expect(result.current.presence).toEqual([]);
    unmount();
  });

  it("drops authenticated messages carrying an evicted unknown-old directory stamp", async () => {
    const { result, unmount } = renderHook(() => useAbyssalSession());
    await act(async () => {
      await result.current.login({
        nodeUrl: "https://node.example.test",
        code: "ABCD-1234",
        password: new TextEncoder().encode("password"),
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    await act(async () => relay?.emit({ type: "rooms", rooms: [room] }));
    await waitFor(() => expect(result.current.rooms).toHaveLength(1));
    for (let revision = 1; revision <= 34; revision += 1) {
      await act(async () => relay?.emit({
        type: "presence",
        users: presenceCatalog(["Bob"], DIRECTORY_NODE_ID, revision).users,
      }));
      await waitFor(() => expect(result.current.presence[0]?.directory_revision).toBe(revision));
    }
    const oldStamp = presenceCatalog(["Bob"], DIRECTORY_NODE_ID, 1).stamp;
    const frame = stampedFrame({
      type: "message",
      chat_id: room.id,
      version: 9,
      message_id: "unknown-old-message",
      nonce_b64: "AQ",
      ciphertext_b64: "Ag",
      signature_b64: "Aw",
      wrapped_key_b64: "BA",
      sender_username: "Bob",
      sender_public_key_b64: validPublicKeyB64,
      identity_public_b64: validPublicKeyB64,
      prekey_id: "prekey-one",
      is_prekey: false,
    }, oldStamp);
    await act(async () => relay?.emit(frame));
    expect(mocks.FakeCipher.decryptCount).toBe(0);
    expect(relay?.sent.filter((item) => (item as { type?: string }).type === "message_ack")).toHaveLength(0);
    expect(result.current.session).not.toBeNull();
    unmount();
  });

  it("serializes presence installation before a following message with the same checkpoint", async () => {
    const { result, unmount } = renderHook(() => useAbyssalSession());
    await act(async () => {
      await result.current.login({
        nodeUrl: "https://node.example.test",
        code: "ABCD-1234",
        password: new TextEncoder().encode("password"),
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    const catalog = presenceCatalog(["Bob"]);
    await act(async () => relay?.emit({ type: "rooms", rooms: [room] }));
    await waitFor(() => expect(result.current.rooms).toHaveLength(1));
    const frame = stampedFrame({
      type: "message",
      chat_id: room.id,
      version: 9,
      message_id: "ordered-checkpoint-message",
      nonce_b64: "AQ",
      ciphertext_b64: "Ag",
      signature_b64: "Aw",
      wrapped_key_b64: "BA",
      sender_username: "Bob",
      sender_public_key_b64: validPublicKeyB64,
      identity_public_b64: validPublicKeyB64,
      prekey_id: "prekey-one",
      is_prekey: false,
    }, catalog.stamp);
    await act(async () => {
      relay?.emit({ type: "presence", users: catalog.users });
      relay?.emit(frame);
    });
    await waitFor(() => expect(result.current.messages[room.id]).toHaveLength(1));
    expect(relay?.sent.filter((item) => (item as { type?: string }).type === "message_ack")).toHaveLength(1);
    expect(result.current.session).not.toBeNull();
    unmount();
  });

  it("does not install an old queued presence catalog after a relogin", async () => {
    let signalDigestStarted!: () => void;
    let releaseDigest!: () => void;
    const digestStarted = new Promise<void>((resolve) => { signalDigestStarted = resolve; });
    const digestReleased = new Promise<void>((resolve) => { releaseDigest = resolve; });
    const digest = crypto.subtle.digest.bind(crypto.subtle);
    const digestSpy = vi.spyOn(crypto.subtle, "digest").mockImplementation(async (algorithm, data) => {
      signalDigestStarted();
      await digestReleased;
      return digest(algorithm, data);
    });
    const { result, unmount } = renderHook(() => useAbyssalSession());
    try {
      await act(async () => {
        await result.current.login({
          nodeUrl: "https://node.example.test",
          code: "ABCD-1234",
          password: new TextEncoder().encode("password"),
          retainWhenHidden: true,
        });
      });
      const oldRelay = mocks.getLastRelay();
      const catalog = presenceCatalog(["Bob"]);
      await act(async () => oldRelay?.emit({ type: "presence", users: catalog.users }));
      await digestStarted;

      await act(async () => {
        await result.current.logout();
        await result.current.login({
          nodeUrl: "https://node.example.test",
          code: "ABCD-1234",
          password: new TextEncoder().encode("password"),
          retainWhenHidden: true,
        });
      });
      const replacementRelay = mocks.getLastRelay();
      expect(replacementRelay).not.toBe(oldRelay);
      expect(result.current.session).not.toBeNull();
      releaseDigest();
      await waitFor(() => expect(result.current.presence).toEqual([]));
      expect(result.current.session).not.toBeNull();
      expect(oldRelay?.closed).toBe(true);
    } finally {
      digestSpy.mockRestore();
      unmount();
    }
  });

  it("fails closed on an outer and inner directory evidence mismatch before ACK or publication", async () => {
    const { result, unmount } = renderHook(() => useAbyssalSession());
    await act(async () => {
      await result.current.login({
        nodeUrl: "https://node.example.test",
        code: "ABCD-1234",
        password: new TextEncoder().encode("password"),
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    const stamp = presenceCatalog(["Bob"]).stamp;
    await act(async () => {
      relay?.emit({ type: "rooms", rooms: [room] });
      relay?.emit({ type: "presence", users: presenceCatalog(["Bob"]).users });
    });
    await waitFor(() => expect(result.current.presence).toHaveLength(1));
    mocks.FakeCipher.plaintextOverride = {
      kind: "text",
      id: "mismatched-inner-evidence",
      sender: "Bob",
      content: "must not publish",
      sender_client: "web",
      directory_node_id: "node-other",
      directory_revision: stamp.directory_revision,
      directory_digest: stamp.directory_digest,
    };
    const frame = stampedFrame({
      type: "message",
      chat_id: room.id,
      version: 9,
      message_id: "mismatched-inner-evidence",
      nonce_b64: "AQ",
      ciphertext_b64: "Ag",
      signature_b64: "Aw",
      wrapped_key_b64: "BA",
      sender_username: "Bob",
      sender_public_key_b64: validPublicKeyB64,
      identity_public_b64: validPublicKeyB64,
      prekey_id: "prekey-one",
      is_prekey: false,
    }, stamp);
    await act(async () => relay?.emit(frame));
    await waitFor(() => expect(result.current.session).toBeNull());
    expect(result.current.messages).toEqual({});
    expect(relay?.sent.filter((item) => (item as { type?: string }).type === "message_ack")).toHaveLength(0);
    unmount();
  });

  it("rejects a replayed message when its directory evidence changes", async () => {
    const { result, unmount } = renderHook(() => useAbyssalSession());
    await act(async () => {
      await result.current.login({
        nodeUrl: "https://node.example.test",
        code: "ABCD-1234",
        password: new TextEncoder().encode("password"),
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    const first = presenceCatalog(["Bob"]);
    const second = presenceCatalog(["Bob"], DIRECTORY_NODE_ID, 2);
    await act(async () => {
      relay?.emit({ type: "rooms", rooms: [room] });
      relay?.emit({ type: "presence", users: first.users });
    });
    await waitFor(() => expect(result.current.presence).toHaveLength(1));
    const base = {
      type: "message" as const,
      chat_id: room.id,
      version: 9,
      message_id: "replay-evidence-message",
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
    await act(async () => relay?.emit(stampedFrame(base, first.stamp)));
    await waitFor(() => expect(result.current.messages[room.id]).toHaveLength(1));
    const ackCount = relay?.sent.filter((item) => (item as { type?: string }).type === "message_ack").length;
    expect(ackCount).toBe(1);
    await act(async () => relay?.emit({ type: "presence", users: second.users }));
    await waitFor(() => expect(result.current.presence[0]?.directory_revision).toBe(2));
    await act(async () => relay?.emit(stampedFrame(base, second.stamp)));
    await waitFor(() => expect(result.current.session).toBeNull());
    expect(relay?.sent.filter((item) => (item as { type?: string }).type === "message_ack")).toHaveLength(1);
    unmount();
  });

  it("fails closed on inbound text missing or unknowning its sender-client tag", async () => {
    const { result, unmount } = renderHook(() => useAbyssalSession());
    await act(async () => {
      await result.current.login({
        nodeUrl: "https://node.example.test",
        code: "ABCD-1234",
        password: new TextEncoder().encode("password"),
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    const catalog = presenceCatalog(["Bob"]);
    await act(async () => {
      relay?.emit({ type: "rooms", rooms: [room] });
      relay?.emit({ type: "presence", users: catalog.users });
    });
    await waitFor(() => expect(result.current.presence).toHaveLength(1));
    const base = {
      type: "message" as const,
      chat_id: room.id,
      version: 9,
      message_id: "untagged-message",
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

    mocks.FakeCipher.plaintextOverride = {
      kind: "text",
      id: "untagged-message",
      sender: "Bob",
      content: "no origin disclosed",
      timestamp_ms: Date.now(),
    };
    await act(async () => relay?.emit(stampedFrame(base, catalog.stamp)));
    expect(mocks.FakeCipher.decryptCount).toBeGreaterThan(0);
    expect(result.current.messages[room.id]).toBeUndefined();
    // The relay-level acknowledgement precedes plaintext validation, so the
    // pending frame is consumed while the message is never published.
    expect(relay?.sent.filter((item) => (item as { type?: string }).type === "message_ack")).toHaveLength(1);

    mocks.FakeCipher.decryptCount = 0;
    mocks.FakeCipher.plaintextOverride = {
      kind: "text",
      id: "unknown-origin-message",
      sender: "Bob",
      content: "unknown origin",
      timestamp_ms: Date.now(),
      sender_client: "desktop",
    };
    await act(async () => relay?.emit(stampedFrame({
      ...base,
      message_id: "unknown-origin-message",
    }, catalog.stamp)));
    expect(mocks.FakeCipher.decryptCount).toBeGreaterThan(0);
    expect(result.current.messages[room.id]).toBeUndefined();
    expect(relay?.sent.filter((item) => (item as { type?: string }).type === "message_ack")).toHaveLength(2);
    unmount();
  });

  it("publishes inbound text carrying the exact android sender-client tag", async () => {
    const { result, unmount } = renderHook(() => useAbyssalSession());
    await act(async () => {
      await result.current.login({
        nodeUrl: "https://node.example.test",
        code: "ABCD-1234",
        password: new TextEncoder().encode("password"),
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    const catalog = presenceCatalog(["Bob"]);
    await act(async () => {
      relay?.emit({ type: "rooms", rooms: [room] });
      relay?.emit({ type: "presence", users: catalog.users });
    });
    await waitFor(() => expect(result.current.presence).toHaveLength(1));
    mocks.FakeCipher.plaintextOverride = {
      kind: "text",
      id: "android-tagged-message",
      sender: "Bob",
      content: "from the hardened client",
      timestamp_ms: Date.now(),
      sender_client: "android",
    };
    await act(async () => relay?.emit(stampedFrame({
      type: "message",
      chat_id: room.id,
      version: 9,
      message_id: "android-tagged-message",
      nonce_b64: "AQ",
      ciphertext_b64: "Ag",
      signature_b64: "Aw",
      wrapped_key_b64: "BA",
      sender_username: "Bob",
      sender_public_key_b64: validPublicKeyB64,
      identity_public_b64: validPublicKeyB64,
      prekey_id: "prekey-one",
      is_prekey: false,
    }, catalog.stamp)));
    await waitFor(() => expect(result.current.messages[room.id]).toHaveLength(1));
    expect(result.current.messages[room.id]?.[0]?.senderClient).toBe("android");
    unmount();
  });

  it("bounds dynamic room and direct updates with case-insensitive collision checks", async () => {
    const { result, unmount } = renderHook(() => useAbyssalSession());
    await act(async () => {
      await result.current.login({
        nodeUrl: "https://node.example.test",
        code: "ABCD-1234",
        password: new TextEncoder().encode("password"),
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
        password: new TextEncoder().encode("password"),
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    const directoryStamp = presenceCatalog(["Bob"]).stamp;
    await act(async () => {
      relay?.emit({ type: "rooms", rooms: [room] });
      relay?.emit({ type: "presence", users: presenceCatalog(["Bob"]).users });
    });
    await waitFor(() => expect(result.current.rooms).toHaveLength(1));

    const frame: IncomingFrame = stampedFrame({
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
    }, directoryStamp);
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
        password: new TextEncoder().encode("password"),
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    const directoryStamp = presenceCatalog(["Bob"]).stamp;
    await act(async () => {
      relay?.emit({ type: "rooms", rooms: [room] });
      relay?.emit({ type: "presence", users: presenceCatalog(["Bob"]).users });
    });
    const frame: IncomingFrame = stampedFrame({
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
    }, directoryStamp);
    await act(async () => relay?.emit(frame));
    await waitFor(() => expect(resolveAck).toBeDefined());
    await waitFor(() => expect(relay?.sent.filter((item) => (item as { type?: string }).type === "message_ack")).toHaveLength(1));
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
        password: new TextEncoder().encode("password"),
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    const directoryStamp = presenceCatalog(["Bob"]).stamp;
    await act(async () => relay?.emit({ type: "rooms", rooms: [room] }));
    await waitFor(() => expect(result.current.rooms).toHaveLength(1));

    const baseFrame: IncomingFrame = stampedFrame({
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
    }, directoryStamp);
    await act(async () => relay?.emit(baseFrame));
    expect(mocks.FakeCipher.decryptCount).toBe(0);

    await act(async () => relay?.emit({ type: "presence", users: presenceCatalog(["Bob"]).users }));
    await waitFor(() => expect(result.current.presence).toHaveLength(1));
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
        password: new TextEncoder().encode("password"),
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    await act(async () => {
      relay?.emit({ type: "directs", directs: [{ id: "dm_bob", peer_username: "Bob" }] });
      relay?.emit({ type: "presence", users: presenceCatalog(["Bob", "Mallory"]).users });
    });
    const directoryStamp = presenceCatalog(["Bob", "Mallory"]).stamp;
    const frame = (chatId: string, sender: string, messageId: string): IncomingFrame => stampedFrame({
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
    }, directoryStamp);

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
        password: new TextEncoder().encode("password"),
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    const directoryStamp = presenceCatalog(["Bob"]).stamp;
    await act(async () => {
      relay?.emit({ type: "rooms", rooms: [room] });
      relay?.emit({ type: "presence", users: presenceCatalog(["Bob"]).users });
    });
    mocks.FakeCipher.payloadIdOverride = "different-id";
    await act(async () => relay?.emit(stampedFrame({
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
    }, directoryStamp)));
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
        password: new TextEncoder().encode("password"),
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    const directoryStamp = presenceCatalog(["Bob"]).stamp;
    await act(async () => {
      relay?.emit({ type: "rooms", rooms: [room] });
      relay?.emit({ type: "presence", users: presenceCatalog(["Bob"]).users });
    });
    const frame = (messageId: string): IncomingFrame => stampedFrame({
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
    }, directoryStamp);

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
        password: new TextEncoder().encode("password"),
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    const directoryStamp = presenceCatalog(["Bob"]).stamp;
    await act(async () => {
      relay?.emit({ type: "rooms", rooms: [room] });
      relay?.emit({ type: "presence", users: presenceCatalog(["Bob"]).users });
    });
    await waitFor(() => expect(result.current.presence).toHaveLength(1));
    act(() => result.current.openRoom(room.id));
    await act(async () => expect(result.current.sendText("outgoing secret")).resolves.toBe(true));
    const ownMessageId = result.current.messages[room.id]?.[0]?.id;
    expect(ownMessageId).toBeDefined();

    const receiptFrame = (messageId: string): IncomingFrame => stampedFrame({
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
    }, directoryStamp);
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

  it("binds outbound text, attachment, and read-receipt plaintext to the outer checkpoint", async () => {
    const { result, unmount } = renderHook(() => useAbyssalSession());
    await act(async () => {
      await result.current.login({
        nodeUrl: "https://node.example.test",
        code: "ABCD-1234",
        password: new TextEncoder().encode("password"),
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    const stamp = presenceCatalog(["Bob"]).stamp;
    await act(async () => {
      relay?.emit({ type: "rooms", rooms: [room] });
      relay?.emit({ type: "presence", users: presenceCatalog(["Bob"]).users });
    });
    await waitFor(() => expect(result.current.presence).toHaveLength(1));
    act(() => result.current.openRoom(room.id));
    await act(async () => expect(result.current.sendText("checkpoint text")).resolves.toBe(true));
    await act(async () => expect(result.current.sendAttachment({
      file: new File([new Uint8Array([1, 2, 3])], "checkpoint.bin", { type: "application/octet-stream" }),
      options: { oneTime: false, deleteAfterDownload: false, ttlSec: 0 },
    })).resolves.toBe(true));
    const inbound = stampedFrame({
      type: "message",
      chat_id: room.id,
      version: 9,
      message_id: "checkpoint-inbound",
      nonce_b64: "AQ",
      ciphertext_b64: "Ag",
      signature_b64: "Aw",
      wrapped_key_b64: "BA",
      sender_username: "Bob",
      sender_public_key_b64: validPublicKeyB64,
      identity_public_b64: validPublicKeyB64,
      prekey_id: "prekey-one",
      is_prekey: false,
    }, stamp);
    await act(async () => relay?.emit(inbound));
    await waitFor(() => expect(mocks.FakeCipher.encryptedPlaintexts).toHaveLength(3));
    const outboundFrames = relay?.sent.filter(
      (item) => (item as { type?: string }).type === "message",
    ) as Array<Record<string, unknown>>;
    expect(outboundFrames).toHaveLength(3);
    outboundFrames.forEach((frame, index) => {
      const inner = JSON.parse(mocks.FakeCipher.encryptedPlaintexts[index] ?? "{}") as Record<string, unknown>;
      if (inner.kind !== "read_receipt") expect(inner.sender_client).toBe("web");
      expect(frame.directory_node_id).toBe(inner.directory_node_id);
      expect(frame.directory_revision).toBe(inner.directory_revision);
      expect(frame.directory_digest).toBe(inner.directory_digest);
      expect(frame.directory_node_id).toBe(stamp.directory_node_id);
      expect(frame.directory_revision).toBe(stamp.directory_revision);
      expect(frame.directory_digest).toBe(stamp.directory_digest);
    });
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
        password: new TextEncoder().encode("password"),
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    const presenceBatch = (batch: number) => presenceCatalog(
      Array.from({ length: 128 }, (_, index) => `User_${batch}_${index}`),
      DIRECTORY_NODE_ID,
      batch + 1,
    ).users;

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
        password: new TextEncoder().encode("password"),
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    expect(relay).not.toBeNull();

    await act(async () => {
      relay?.emit({ type: "rooms", rooms: [room] });
      relay?.emit({
        type: "presence",
        users: presenceCatalog([
          "Alice",
          { username: "Bob", identity_prekey_id: "prekey-two" },
        ]).users,
      });
    });

    await waitFor(() => expect(result.current.rooms).toHaveLength(1));
    await waitFor(() => expect(result.current.presence).toHaveLength(2));
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
        password: new TextEncoder().encode("password"),
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
    let uploadMessageId: string | undefined;
    mocks.uploadEncryptedAttachment.mockImplementationOnce((...args: unknown[]) => new Promise<string>((_resolve, reject) => {
      uploadMessageId = args[2] as string;
      uploadSignal = args[7] as AbortSignal;
      uploadSignal.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")), { once: true });
    }));
    const { result, unmount } = renderHook(() => useAbyssalSession());
    await act(async () => {
      await result.current.login({
        nodeUrl: "https://node.example.test",
        code: "ABCD-1234",
        password: new TextEncoder().encode("password"),
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    await act(async () => {
      relay?.emit({ type: "rooms", rooms: [room] });
      relay?.emit({ type: "presence", users: presenceCatalog(["Bob"]).users });
    });
    await waitFor(() => expect(result.current.presence).toHaveLength(1));
    act(() => result.current.openRoom(room.id));
    let pending: Promise<boolean> | undefined;
    act(() => {
      pending = result.current.sendAttachment({
        file: new File([new Uint8Array([1, 2, 3])], "secret.bin", { type: "application/octet-stream" }),
        options: { oneTime: false, deleteAfterDownload: false, ttlSec: 0 },
      });
    });
    await waitFor(() => {
      expect(uploadMessageId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
      expect(uploadSignal).toBeDefined();
    });

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
        password: new TextEncoder().encode("password"),
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    await act(async () => {
      relay?.emit({ type: "rooms", rooms: [room] });
      relay?.emit({ type: "presence", users: presenceCatalog(["Bob"]).users });
    });
    await waitFor(() => expect(result.current.presence).toHaveLength(1));
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
        password: new TextEncoder().encode("password"),
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    await act(async () => {
      relay?.emit({ type: "rooms", rooms: [room] });
      relay?.emit({ type: "presence", users: presenceCatalog(["Bob"]).users });
    });
    await waitFor(() => expect(result.current.presence).toHaveLength(1));
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
        password: new TextEncoder().encode("password"),
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    await act(async () => {
      relay?.emit({ type: "rooms", rooms: [room] });
      relay?.emit({ type: "presence", users: presenceCatalog(["Bob"]).users });
    });
    await waitFor(() => expect(result.current.rooms).toHaveLength(1));
    act(() => result.current.openRoom(room.id));
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
        password: new TextEncoder().encode("password"),
        retainWhenHidden: true,
      });
    });
    const secondRelay = mocks.getLastRelay();
    await act(async () => {
      secondRelay?.emit({ type: "rooms", rooms: [room] });
      secondRelay?.emit({ type: "presence", users: presenceCatalog(["Bob"]).users });
    });
    await waitFor(() => expect(result.current.rooms).toHaveLength(1));
    act(() => result.current.openRoom(room.id));
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
        password: new TextEncoder().encode("password"),
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
        password: new TextEncoder().encode("password"),
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
        password: new TextEncoder().encode("password"),
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    await act(async () => {
      relay?.emit({ type: "directs", directs: [{ id: "dm_bob", peer_username: "Bob" }] });
      relay?.emit({
        type: "presence",
        users: presenceCatalog([{ username: "Bob", identity_prekey_id: "catalog-key" }]).users,
      });
    });
    await waitFor(() => {
      expect(result.current.directs).toHaveLength(1);
      expect(result.current.presence).toHaveLength(1);
      expect(result.current.connection).toBe("connected");
    });
    act(() => result.current.openRoom("dm_bob"));
    await waitFor(() => expect(result.current.activeRoomId).toBe("dm_bob"));
    expect(result.current.safetyNumber).toBeTruthy();
    expect(result.current.verifyDirectSafetyNumber(result.current.safetyNumber!)).toBe(true);

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

  it("blocks direct text before IDs or encryption until the exact safety number is confirmed", async () => {
    const { result, unmount } = renderHook(() => useAbyssalSession());
    await act(async () => {
      await result.current.login({
        nodeUrl: "https://node.example.test",
        code: "ABCD-1234",
        password: new TextEncoder().encode("password"),
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    await act(async () => {
      relay?.emit({ type: "directs", directs: [{ id: "dm_bob", peer_username: "Bob" }] });
      relay?.emit({ type: "presence", users: presenceCatalog(["Bob"]).users });
    });
    await waitFor(() => expect(result.current.presence).toHaveLength(1));
    act(() => result.current.openRoom("dm_bob"));
    await waitFor(() => expect(result.current.activeRoomId).toBe("dm_bob"));

    await act(async () => expect(await result.current.sendText("blocked")).toBe(false));
    expect(mocks.FakeCipher.encryptedPlaintexts).toHaveLength(0);
    expect(relay?.sent.some((frame) => (frame as { type?: string }).type === "message")).toBe(false);
    expect(result.current.verifyDirectSafetyNumber("wrong safety number")).toBe(false);
    expect(result.current.verifyDirectSafetyNumber(result.current.safetyNumber!)).toBe(true);
    await act(async () => expect(await result.current.sendText("allowed")).toBe(true));
    unmount();
  });

  it("rejects every unverified direct data path before crypto, prekeys, or network side effects", async () => {
    const { result, unmount } = renderHook(() => useAbyssalSession());
    await act(async () => {
      await result.current.login({
        nodeUrl: "https://node.example.test",
        code: "ABCD-1234",
        password: new TextEncoder().encode("password"),
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    const catalog = presenceCatalog(["Bob"]);
    await act(async () => {
      relay?.emit({ type: "directs", directs: [{ id: "dm_bob", peer_username: "Bob" }] });
      relay?.emit({ type: "presence", users: catalog.users });
    });
    await waitFor(() => expect(result.current.presence).toHaveLength(1));
    act(() => result.current.openRoom("dm_bob"));
    await waitFor(() => expect(result.current.activeRoomId).toBe("dm_bob"));

    const uuidSpy = vi.spyOn(globalThis.crypto, "randomUUID");
    await act(async () => expect(await result.current.sendText("blocked")).toBe(false));
    await act(async () => expect(await result.current.sendAttachment({
      file: new File([new Uint8Array([1, 2, 3])], "secret.bin", { type: "application/octet-stream" }),
      options: { oneTime: false, deleteAfterDownload: false, ttlSec: 0 },
    })).toBe(false));
    const attachmentMessage = {
      id: "attachment-message",
      chatId: "dm_bob",
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
      await result.current.exportAttachment(attachmentMessage);
    });

    expect(uuidSpy).not.toHaveBeenCalled();
    expect(mocks.FakeCipher.encryptedPlaintexts).toHaveLength(0);
    expect(mocks.FakeCipher.lastAttachmentPlain).toBeNull();
    expect(relay?.leasesRequested).toEqual([]);
    expect(relay?.sent.filter((item) => (item as { type?: string }).type === "message")).toHaveLength(0);
    expect(mocks.uploadEncryptedAttachment).not.toHaveBeenCalled();
    expect(mocks.downloadEncryptedAttachment).not.toHaveBeenCalled();

    // An incoming message may be decrypted and acknowledged, but opening the
    // unverified direct chat must not emit a read receipt. Local read state is
    // allowed to update independently of that outbound authorization.
    const incoming = stampedFrame({
      type: "message",
      chat_id: "dm_bob",
      version: 9,
      message_id: "incoming-direct-message",
      nonce_b64: "AQ",
      ciphertext_b64: "Ag",
      signature_b64: "Aw",
      wrapped_key_b64: "BA",
      sender_username: "Bob",
      sender_public_key_b64: validPublicKeyB64,
      identity_public_b64: validPublicKeyB64,
      prekey_id: "prekey-one",
      is_prekey: false,
    }, catalog.stamp);
    await act(async () => relay?.emit(incoming));
    await waitFor(() => expect(result.current.messages.dm_bob).toHaveLength(1));
    act(() => result.current.openRoom("dm_bob"));
    await new Promise((resolve) => window.setTimeout(resolve, 400));
    // The local inbound frame is still rendered/read locally; the security
    // interlock requirement here is that no encrypted read receipt is sent.
    expect(result.current.messages.dm_bob?.[0]?.readAtMs).toEqual(expect.any(Number));
    expect(relay?.sent.filter((item) => (item as { type?: string }).type === "message")).toHaveLength(0);
    uuidSpy.mockRestore();
    unmount();
  });

  it("clears direct verification on reconnect while preserving room and direct catalogs", async () => {
    const { result, unmount } = renderHook(() => useAbyssalSession());
    await act(async () => {
      await result.current.login({
        nodeUrl: "https://node.example.test",
        code: "ABCD-1234",
        password: new TextEncoder().encode("password"),
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    const catalog = presenceCatalog(["Bob"]);
    await act(async () => {
      relay?.emit({ type: "rooms", rooms: [room] });
      relay?.emit({ type: "directs", directs: [{ id: "dm_bob", peer_username: "Bob" }] });
      relay?.emit({ type: "presence", users: catalog.users });
    });
    await waitFor(() => {
      expect(result.current.rooms).toEqual([room]);
      expect(result.current.directs).toEqual([{ id: "dm_bob", peer_username: "Bob" }]);
    });
    act(() => result.current.openRoom("dm_bob"));
    await waitFor(() => expect(result.current.activeRoomId).toBe("dm_bob"));
    expect(result.current.verifyDirectSafetyNumber(result.current.safetyNumber!)).toBe(true);
    await waitFor(() => expect(result.current.directTrust.verified).toBe(true));

    act(() => relay?.close());
    await waitFor(() => expect(result.current.directTrust.verified).toBe(false));
    expect(result.current.rooms).toEqual([room]);
    expect(result.current.directs).toEqual([{ id: "dm_bob", peer_username: "Bob" }]);

    act(() => relay?.connect());
    await waitFor(() => expect(result.current.connection).toBe("connected"));
    expect(result.current.directTrust.active).toBe(true);
    expect(result.current.directTrust.verified).toBe(false);
    unmount();
  });

  it("does not publish a verified operation after its connection generation is invalidated", async () => {
    const { result, unmount } = renderHook(() => useAbyssalSession());
    await act(async () => {
      await result.current.login({
        nodeUrl: "https://node.example.test",
        code: "ABCD-1234",
        password: new TextEncoder().encode("password"),
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    const catalog = presenceCatalog(["Bob"]);
    await act(async () => {
      relay?.emit({ type: "directs", directs: [{ id: "dm_bob", peer_username: "Bob" }] });
      relay?.emit({ type: "presence", users: catalog.users });
    });
    await waitFor(() => expect(result.current.presence).toHaveLength(1));
    act(() => result.current.openRoom("dm_bob"));
    await waitFor(() => expect(result.current.activeRoomId).toBe("dm_bob"));
    expect(result.current.verifyDirectSafetyNumber(result.current.safetyNumber!)).toBe(true);

    let resolveSend!: (result: "ACCEPTED" | "REJECTED" | "NOT_SENT" | "AMBIGUOUS") => void;
    mocks.FakeRelay.encryptedResult = new Promise((resolve) => { resolveSend = resolve; });
    let pending: Promise<boolean> | undefined;
    act(() => { pending = result.current.sendText("must not cross reconnect"); });
    await waitFor(() => expect(relay?.sent.some((item) => (item as { type?: string }).type === "message")).toBe(true));

    act(() => relay?.close());
    await waitFor(() => expect(result.current.directTrust.verified).toBe(false));
    act(() => resolveSend("ACCEPTED"));
    await act(async () => expect(pending).resolves.toBe(false));
    expect(result.current.messages.dm_bob).toBeUndefined();
    unmount();
  });

  it("releases partial timeout and rejected room leases but never ambiguous admission", async () => {
    const { result, unmount } = renderHook(() => useAbyssalSession());
    await act(async () => {
      await result.current.login({
        nodeUrl: "https://node.example.test",
        code: "ABCD-1234",
        password: new TextEncoder().encode("password"),
        retainWhenHidden: true,
      });
    });
    const relay = mocks.getLastRelay();
    await act(async () => {
      relay?.emit({ type: "rooms", rooms: [room] });
      relay?.emit({
        type: "presence",
        users: presenceCatalog([
          { username: "Bob", identity_prekey_id: "catalog-key" },
          { username: "Carol", identity_prekey_id: "catalog-key" },
        ]).users,
      });
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

  it("routes protocol-v10 room sends through MLS and fails closed on ambiguous admission", async () => {
    const { result, unmount } = renderHook(() => useAbyssalSession());
    await act(async () => { await result.current.login({ nodeUrl: "https://node.example.test", code: "ABCD-1234", password: new TextEncoder().encode("password"), retainWhenHidden: true }); });
    const relay = mocks.getLastRelay();
    await act(async () => relay?.emit({ type: "mls_rooms", protocol_version: 10, rooms: [{ room_id: "forum_mls", owner_username: "Alice", active: true }] } as unknown as IncomingFrame));
    await waitFor(() => expect(result.current.rooms[0]?.mlsActive).toBe(true));
    act(() => result.current.openRoom("forum_mls"));

    await act(async () => expect(result.current.sendText("MLS accepted")).resolves.toBe(true));
    expect(relay?.sent.at(-1)).toMatchObject({ type: "mls_application", room_id: "forum_mls" });
    expect(mocks.FakeMlsManager.instances[0]?.finishOutcomes).toEqual(["ACCEPTED"]);

    mocks.FakeRelay.encryptedOutcome = "REJECTED";
    await act(async () => expect(result.current.sendText("MLS rejected")).resolves.toBe(false));
    expect(mocks.FakeMlsManager.instances[0]?.finishOutcomes).toEqual(["ACCEPTED", "REJECTED"]);

    mocks.FakeRelay.encryptedOutcome = "AMBIGUOUS";
    await act(async () => expect(result.current.sendText("MLS ambiguous")).resolves.toBe(false));
    expect(result.current.session).toBeNull();
    expect(mocks.FakeMlsManager.instances[0]?.closed).toBe(true);
    unmount();
  });

  it("replays an accepted MLS snapshot transaction without decrypting or republishing the message", async () => {
    const { result, unmount } = renderHook(() => useAbyssalSession());
    await act(async () => { await result.current.login({ nodeUrl: "https://node.example.test", code: "ABCD-1234", password: new TextEncoder().encode("password"), retainWhenHidden: true }); });
    const relay = mocks.getLastRelay(); const manager = mocks.FakeMlsManager.instances[0];
    await act(async () => relay?.emit({ type: "mls_rooms", protocol_version: 10, rooms: [{ room_id: "forum_mls", owner_username: "Alice", active: true }] } as unknown as IncomingFrame));
    const incoming = {
      type: "mls_application", protocol_version: 10, room_id: "forum_mls", message_id: "incoming-mls",
      sender_username: "Bob", epoch: "0", revision: "3", membership_digest_b64: "x", ciphertext_b64: "x", authenticated_data_b64: "x",
    } as unknown as IncomingFrame;
    await act(async () => relay?.emit(incoming));
    await waitFor(() => expect(result.current.messages.forum_mls).toHaveLength(1));
    expect(manager?.receiveApplicationCount).toBe(1);
    await act(async () => relay?.emit(incoming));
    await waitFor(() => expect(manager?.snapshotOutcomes).toEqual(["ACCEPTED", "ACCEPTED"]));
    expect(manager?.receiveApplicationCount).toBe(1);
    expect(result.current.messages.forum_mls).toHaveLength(1);
    expect(relay?.sent.filter((frame) => (frame as { type?: string }).type === "mls_state_snapshot")).toHaveLength(2);
    unmount();
  });

  it("accepts generic protocol-safe room ids and retains join rejection state when send fails", async () => {
    const { result, unmount } = renderHook(() => useAbyssalSession());
    await act(async () => { await result.current.login({ nodeUrl: "https://node.example.test", code: "ABCD-1234", password: new TextEncoder().encode("password"), retainWhenHidden: true }); });
    const relay = mocks.getLastRelay();
    expect(result.current.joinRoom("general-room_1")).toBe(true);
    expect(relay?.sent.at(-1)).toMatchObject({ type: "mls_discover_room", room_id: "general-room_1" });
    expect(result.current.joinRoom("bad room")).toBe(false);

    await act(async () => relay?.emit({
      type: "mls_join_requested", protocol_version: 10, room_id: "general-room_1", request_id: "join-request",
      username: "Bob", stable_identity_b64: "AA", key_package_b64: "AA",
    } as unknown as IncomingFrame));
    await waitFor(() => expect(result.current.pendingMlsJoins).toHaveLength(1));
    mocks.FakeRelay.mlsControlResult = false;
    expect(result.current.rejectRoomJoin("join-request")).toBe(false);
    expect(result.current.pendingMlsJoins).toHaveLength(1);
    mocks.FakeRelay.mlsControlResult = true;
    expect(result.current.rejectRoomJoin("join-request")).toBe(true);
    await waitFor(() => expect(result.current.pendingMlsJoins).toHaveLength(0));
    unmount();
  });

  it("accepts only an exact rejection for this client's pending join", async () => {
    const { result, unmount } = renderHook(() => useAbyssalSession());
    await act(async () => { await result.current.login({ nodeUrl: "https://node.example.test", code: "ABCD-1234", password: new TextEncoder().encode("password"), retainWhenHidden: true }); });
    const relay = mocks.getLastRelay();
    await act(async () => relay?.emit({
      type: "mls_room_discovered", protocol_version: 10, room_id: "general-room", group_id_b64: "AA", owner_username: "Bob",
    } as unknown as IncomingFrame));
    expect(mocks.FakeMlsManager.instances[0]?.ownJoin).toEqual({ roomId: "general-room", requestId: "own-join-request" });
    await act(async () => relay?.emit({
      type: "mls_join_rejected", protocol_version: 10, room_id: "general-room", request_id: "own-join-request",
    } as unknown as IncomingFrame));
    expect(result.current.session).not.toBeNull();
    expect(mocks.FakeMlsManager.instances[0]?.ownJoin).toBeNull();
    unmount();

    const second = renderHook(() => useAbyssalSession());
    await act(async () => { await second.result.current.login({ nodeUrl: "https://node.example.test", code: "ABCD-1234", password: new TextEncoder().encode("password"), retainWhenHidden: true }); });
    const secondRelay = mocks.getLastRelay();
    await act(async () => secondRelay?.emit({
      type: "mls_room_discovered", protocol_version: 10, room_id: "other-room", group_id_b64: "AA", owner_username: "Bob",
    } as unknown as IncomingFrame));
    await act(async () => secondRelay?.emit({
      type: "mls_join_rejected", protocol_version: 10, room_id: "other-room", request_id: "wrong-request",
    } as unknown as IncomingFrame));
    await waitFor(() => expect(second.result.current.session).toBeNull());
    second.unmount();
  });

  it("routes owner leave approval and retains the request when rejection send fails", async () => {
    const { result, unmount } = renderHook(() => useAbyssalSession());
    await act(async () => { await result.current.login({ nodeUrl: "https://node.example.test", code: "ABCD-1234", password: new TextEncoder().encode("password"), retainWhenHidden: true }); });
    const relay = mocks.getLastRelay();
    await act(async () => relay?.emit({ type: "mls_rooms", protocol_version: 10, rooms: [{ room_id: "forum_mls", owner_username: "Alice", active: true }] } as unknown as IncomingFrame));
    const request = { type: "mls_leave_requested", protocol_version: 10, room_id: "forum_mls", request_id: "leave-request", username: "Bob", stable_identity_b64: "AA" } as unknown as IncomingFrame;
    await act(async () => relay?.emit(request));
    await waitFor(() => expect(result.current.pendingMlsLeaves).toEqual([{ roomId: "forum_mls", requestId: "leave-request", username: "Bob" }]));

    mocks.FakeRelay.mlsControlResult = false;
    await act(async () => expect(result.current.rejectRoomLeave("leave-request")).toBe(false));
    expect(result.current.pendingMlsLeaves).toHaveLength(1);
    mocks.FakeRelay.mlsControlResult = true;
    await act(async () => expect(result.current.rejectRoomLeave("leave-request")).toBe(true));
    await waitFor(() => expect(result.current.pendingMlsLeaves).toHaveLength(0));

    await act(async () => relay?.emit({ ...request, request_id: "leave-accept" } as unknown as IncomingFrame));
    await waitFor(() => expect(result.current.pendingMlsLeaves).toHaveLength(1));
    await act(async () => expect(result.current.acceptRoomLeave("leave-accept")).resolves.toBe(true));
    expect(relay?.sent.at(-1)).toMatchObject({ type: "mls_membership_commit", request_id: "leave-accept" });
    await waitFor(() => expect(result.current.pendingMlsLeaves).toHaveLength(0));
    unmount();
  });

  it("fails closed when a member leave acknowledgement is not bound to its pending request", async () => {
    const { result, unmount } = renderHook(() => useAbyssalSession());
    await act(async () => { await result.current.login({ nodeUrl: "https://node.example.test", code: "ABCD-1234", password: new TextEncoder().encode("password"), retainWhenHidden: true }); });
    const relay = mocks.getLastRelay();
    await act(async () => relay?.emit({ type: "mls_rooms", protocol_version: 10, rooms: [{ room_id: "forum_mls", owner_username: "Alice", active: true }] } as unknown as IncomingFrame));
    act(() => result.current.leaveRoom("forum_mls"));
    await waitFor(() => expect(result.current.pendingMlsLeaves).toHaveLength(1));
    await act(async () => relay?.emit({ type: "mls_leave_pending", protocol_version: 10, room_id: "forum_mls", request_id: "member-leave" } as unknown as IncomingFrame));
    expect(result.current.session).not.toBeNull();
    await act(async () => relay?.emit({ type: "mls_leave_pending", protocol_version: 10, room_id: "forum_mls", request_id: "wrong-request" } as unknown as IncomingFrame));
    await waitFor(() => expect(result.current.session).toBeNull());
    unmount();
  });

  it("removes MLS room state and plaintext messages after the relay confirms the member left", async () => {
    const { result, unmount } = renderHook(() => useAbyssalSession());
    await act(async () => { await result.current.login({ nodeUrl: "https://node.example.test", code: "ABCD-1234", password: new TextEncoder().encode("password"), retainWhenHidden: true }); });
    const relay = mocks.getLastRelay();
    await act(async () => relay?.emit({ type: "mls_rooms", protocol_version: 10, rooms: [{ room_id: "forum_mls", owner_username: "Alice", active: true }] } as unknown as IncomingFrame));
    act(() => result.current.openRoom("forum_mls"));
    await act(async () => expect(result.current.sendText("leave me")).resolves.toBe(true));
    await waitFor(() => expect(result.current.messages.forum_mls).toHaveLength(1));
    await act(async () => relay?.emit({ type: "mls_left", protocol_version: 10, room_id: "forum_mls" } as unknown as IncomingFrame));
    await waitFor(() => expect(result.current.rooms).toHaveLength(0));
    expect(result.current.messages).not.toHaveProperty("forum_mls");
    expect(result.current.activeRoomId).toBeNull();
    unmount();
  });
});

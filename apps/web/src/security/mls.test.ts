import { describe, expect, it, vi } from "vitest";
import type { WasmE2eeSession } from "../generated/abyssal_core/abyssal_core";
import type { RoomRecord } from "../domain/types";
import { decodeBase64Url, encodeBase64Url, type MlsIncomingFrame, type MlsRoomWire } from "../transport/mlsWire";
import { MlsRoomManager } from "./mls";

const bytes = (length: number, fill: number) => new Uint8Array(length).fill(fill);
const roomRecord: RoomRecord = {
  id: "forum_alpha", name: "Alpha", owner_username: "Alice", conversation_type: "room",
  self_destruct_timer_sec: 0, overall_expiry_sec: 60, allow_images: true, allow_videos: true,
  allow_files: true, enforce_text_absolute_expiry: true, image_read_timer_sec: 0,
  image_overall_expiry_sec: 60, enforce_image_absolute_expiry: true, video_read_timer_sec: 0,
  video_overall_expiry_sec: 60, enforce_video_absolute_expiry: true, file_read_timer_sec: 0,
  file_overall_expiry_sec: 60, enforce_file_absolute_expiry: true,
};

class FakeRoom {
  groupId = bytes(32, 1);
  free = vi.fn(); commitOutbound = vi.fn(); rollbackOutbound = vi.fn();
  sealState = vi.fn(() => bytes(80, 8)); keyPackage = vi.fn(() => bytes(90, 9));
  roomInfo = vi.fn(() => wrapper({ roomId: "forum_alpha", groupId: this.groupId.slice(), epoch: 0n, memberCount: 1, revision: 0n, membershipDigest: bytes(32, 2) }));
  encryptApplication = vi.fn((messageId: string, _plain: Uint8Array, aad: Uint8Array) => wrapper({
    messageId, revision: 2n, ciphertext: bytes(120, 4), stateEnvelope: bytes(90, 5), groupId: bytes(32, 1),
    epoch: 0n, membershipDigest: bytes(32, 2), senderIndex: 0, authenticatedData: aad.slice(),
  }));
  decryptApplication = vi.fn((_cipher: Uint8Array, _epoch: bigint, _message: string, aad: Uint8Array) => wrapper({
    plaintext: new TextEncoder().encode('{"kind":"text"}'), senderIndex: 0, epoch: 0n, groupId: bytes(32, 1),
    membershipDigest: bytes(32, 2), revision: 2n, stateEnvelope: bytes(90, 5), authenticatedData: aad.slice(),
  }));
  addMember = vi.fn((_key: Uint8Array, username: string, stable: Uint8Array, messageId: string) => wrapper({
    messageId, revision: 2n, groupId: bytes(32, 1), fromEpoch: 0n, toEpoch: 1n,
    fromMembershipDigest: bytes(32, 2), membershipDigest: bytes(32, 3),
    rosterJson: JSON.stringify([
      { username: "Alice", stable_identity: [...bytes(64, 7)] },
      { username, stable_identity: [...stable] },
      { username: "Carol", stable_identity: [...bytes(64, 5)] },
    ]),
    stateEnvelope: bytes(90, 5), authenticatedData: bytes(50, 6), commit: bytes(100, 4), welcome: bytes(100, 5),
  }));
  joinWelcome = vi.fn(() => wrapper({ roomId: "forum_alpha", groupId: bytes(32, 1), epoch: 1n, memberCount: 2, revision: 2n, membershipDigest: bytes(32, 3) }));
  processControl = vi.fn((_control: Uint8Array, _from: bigint, _to: bigint, _roster: string, digest: Uint8Array, messageId: string, aad: Uint8Array) => {
    void aad;
    return wrapper({
      roomId: "forum_alpha", messageId, groupId: bytes(32, 1), epoch: 1n, memberCount: 2, revision: 1n,
      membershipDigest: digest.slice(), stateEnvelope: bytes(90, 5),
    });
  });
  removeMember = vi.fn((_username: string, _stable: Uint8Array, messageId: string) => wrapper({
    messageId, revision: 3n, groupId: bytes(32, 1), fromEpoch: 1n, toEpoch: 2n,
    fromMembershipDigest: bytes(32, 3), membershipDigest: bytes(32, 4),
    rosterJson: JSON.stringify([{ username: "Alice", stable_identity: [...bytes(64, 7)] }]),
    stateEnvelope: bytes(90, 5), authenticatedData: bytes(50, 6), commit: bytes(100, 4), welcome: new Uint8Array(0),
  }));
}

function wrapper<T extends object>(value: T): T & { free: ReturnType<typeof vi.fn> } { return { ...value, free: vi.fn() }; }
function sessionWith(room = new FakeRoom()) {
  return {
    room,
    session: {
      mlsCreateRoom: vi.fn((_roomId: string, _username: string, _node: Uint8Array, groupId: Uint8Array) => {
        room.groupId.fill(0); room.groupId = groupId.slice(); return room;
      }),
      mlsPendingJoin: vi.fn(() => room), mlsRecoverRoom: vi.fn(() => room),
    } as unknown as WasmE2eeSession,
  };
}

function membershipFrame(fake: ReturnType<typeof sessionWith>, roster = [
  { username: "Alice", stable_identity_b64: encodeBase64Url(bytes(64, 7)) },
  { username: "Bob", stable_identity_b64: encodeBase64Url(bytes(64, 6)) },
]): Extract<MlsIncomingFrame, { type: "mls_membership" }> {
  return {
    type: "mls_membership", protocol_version: 10, room_id: roomRecord.id, message_id: "control",
    from_epoch: "0", to_epoch: "1", revision: "1", from_membership_digest_b64: encodeBase64Url(bytes(32, 2)),
    group_id_b64: encodeBase64Url(fake.room.groupId), membership_digest_b64: encodeBase64Url(bytes(32, 3)),
    roster, control_b64: encodeBase64Url(bytes(100, 4)), welcome_b64: "",
    authenticated_data_b64: encodeBase64Url(bytes(50, 6)),
  };
}

describe("MlsRoomManager", () => {
  it("derives rooms only through the account factory and emits canonical create state", () => {
    const fake = sessionWith(); const manager = new MlsRoomManager(fake.session, "Alice", "node-1", bytes(608, 7));
    const frame = manager.createRoom(roomRecord);
    expect(fake.session.mlsCreateRoom).toHaveBeenCalledOnce();
    expect(frame).toMatchObject({ type: "mls_create_room", protocol_version: 10, epoch: "0", revision: "0" });
    expect((frame.policy as Record<string, unknown>).overall_expiry_sec).toBe("60");
    manager.close(); expect(fake.room.free).toHaveBeenCalledOnce();
  });

  it("commits exact accepted revisions and rolls back explicit rejection", () => {
    const accepted = sessionWith(); const manager = new MlsRoomManager(accepted.session, "Alice", "node", bytes(608, 7));
    manager.createRoom(roomRecord);
    const first = manager.prepareApplication(roomRecord.id, "message-1", "Alice", bytes(3, 1));
    manager.finishTransaction(first, "ACCEPTED");
    expect(accepted.room.commitOutbound).toHaveBeenCalledWith("message-1", 2n);
    const second = manager.prepareApplication(roomRecord.id, "message-2", "Alice", bytes(3, 1));
    manager.finishTransaction(second, "REJECTED");
    expect(accepted.room.rollbackOutbound).toHaveBeenCalledWith("message-2", 2n);
  });

  it("destroys an ambiguous room and makes later use fail closed", () => {
    const fake = sessionWith(); const manager = new MlsRoomManager(fake.session, "Alice", "node", bytes(608, 7));
    manager.createRoom(roomRecord); const prepared = manager.prepareApplication(roomRecord.id, "message", "Alice", bytes(1, 1));
    manager.finishTransaction(prepared, "AMBIGUOUS");
    expect(fake.room.free).toHaveBeenCalledOnce();
    expect(() => manager.prepareApplication(roomRecord.id, "later", "Alice", bytes(1, 1))).toThrow("Room unavailable");
  });

  it("destroys state on an inexact transaction result tuple", () => {
    const fake = sessionWith(); const manager = new MlsRoomManager(fake.session, "Alice", "node", bytes(608, 7));
    manager.createRoom(roomRecord);
    const prepared = manager.prepareApplication(roomRecord.id, "message", "Alice", bytes(1, 1));
    expect(() => manager.finishTransaction({ ...prepared, messageId: "other" }, "ACCEPTED")).toThrow("Room unavailable");
    expect(fake.room.commitOutbound).not.toHaveBeenCalled();
    expect(() => manager.prepareApplication(roomRecord.id, "later", "Alice", bytes(1, 1))).toThrow("Room unavailable");
  });

  it("retains join request context until the exact accepted owner commit", () => {
    const fake = sessionWith(); const manager = new MlsRoomManager(fake.session, "Alice", "node", bytes(608, 7)); manager.createRoom(roomRecord);
    const join = { type: "mls_join_requested", protocol_version: 10, room_id: roomRecord.id, request_id: "request", username: "Bob", stable_identity_b64: encodeBase64Url(bytes(64, 6)), key_package_b64: encodeBase64Url(bytes(100, 8)) } as const;
    manager.rememberJoin(join); const prepared = manager.acceptJoin("request", "membership");
    expect(prepared.requestId).toBe("request"); expect(manager.pendingJoins()).toHaveLength(1);
    manager.finishTransaction(prepared, "ACCEPTED"); expect(manager.pendingJoins()).toHaveLength(0);
  });

  it("accepts only exact duplicate join context and wipes it with the room", () => {
    const fake = sessionWith(); const manager = new MlsRoomManager(fake.session, "Alice", "node", bytes(608, 7)); manager.createRoom(roomRecord);
    const join = { type: "mls_join_requested", protocol_version: 10, room_id: roomRecord.id, request_id: "request", username: "Bob", stable_identity_b64: encodeBase64Url(bytes(64, 6)), key_package_b64: encodeBase64Url(bytes(100, 8)) } as const;
    manager.rememberJoin(join); manager.rememberJoin(join);
    expect(manager.pendingJoins()).toEqual([{ roomId: roomRecord.id, requestId: "request", username: "Bob" }]);
    expect(manager.pendingJoins()[0]).not.toHaveProperty("keyPackage");
    expect(manager.pendingJoins()[0]).not.toHaveProperty("stableIdentity");
    expect(() => manager.rememberJoin({ ...join, username: "Carol" })).toThrow("Room unavailable");
    manager.removeRoom(roomRecord.id);
    expect(manager.pendingJoins()).toHaveLength(0);
  });

  it("keeps rejected join secrets until the exact rejection is confirmed sent", () => {
    const fake = sessionWith(); const manager = new MlsRoomManager(fake.session, "Alice", "node", bytes(608, 7)); manager.createRoom(roomRecord);
    const join = { type: "mls_join_requested", protocol_version: 10, room_id: roomRecord.id, request_id: "request", username: "Bob", stable_identity_b64: encodeBase64Url(bytes(64, 6)), key_package_b64: encodeBase64Url(bytes(100, 8)) } as const;
    manager.rememberJoin(join);
    expect(manager.rejectJoin(join.request_id)).toMatchObject({ request_id: join.request_id });
    expect(manager.pendingJoins()).toHaveLength(1);
    expect(() => manager.forgetJoin("wrong-room", join.request_id)).toThrow("Room unavailable");
    manager.forgetJoin(join.room_id, join.request_id);
    expect(manager.pendingJoins()).toHaveLength(0);
  });

  it("rejects nonowner membership decisions and current-member join requests", () => {
    const ownerRoom = new FakeRoom();
    ownerRoom.roomInfo = vi.fn(() => wrapper({
      roomId: roomRecord.id, groupId: ownerRoom.groupId.slice(), epoch: 0n, memberCount: 2, revision: 0n,
      membershipDigest: bytes(32, 2),
    }));
    const fake = sessionWith(ownerRoom);
    const manager = new MlsRoomManager(fake.session, "Alice", "node", bytes(608, 7));
    manager.recoverCatalog([{
      room_id: roomRecord.id, owner_username: "Bob", group_id_b64: encodeBase64Url(ownerRoom.groupId), active: true, synchronized: true,
      epoch: "0", revision: "0", membership_digest_b64: encodeBase64Url(bytes(32, 2)),
      roster: [
        { username: "Alice", stable_identity_b64: encodeBase64Url(bytes(64, 7)) },
        { username: "Bob", stable_identity_b64: encodeBase64Url(bytes(64, 6)) },
      ],
      recovery_snapshot: {
        active: true, epoch: "0", revision: "0", membership_digest_b64: encodeBase64Url(bytes(32, 2)),
        state_envelope_b64: encodeBase64Url(bytes(80, 8)), roster: [
          { username: "alice", stable_identity_b64: encodeBase64Url(bytes(64, 7)) },
          { username: "bob", stable_identity_b64: encodeBase64Url(bytes(64, 6)) },
        ],
      },
      policy: { self_destruct_timer_sec: "0", overall_expiry_sec: "60", allow_images: true, allow_videos: true, allow_files: true, enforce_text_absolute_expiry: true, image_read_timer_sec: "0", image_overall_expiry_sec: "60", enforce_image_absolute_expiry: true, video_read_timer_sec: "0", video_overall_expiry_sec: "60", enforce_video_absolute_expiry: true, file_read_timer_sec: "0", file_overall_expiry_sec: "60", enforce_file_absolute_expiry: true },
    }]);
    const request = { type: "mls_join_requested", protocol_version: 10, room_id: roomRecord.id, request_id: "request", username: "Carol", stable_identity_b64: encodeBase64Url(bytes(64, 5)), key_package_b64: encodeBase64Url(bytes(100, 8)) } as const;
    expect(() => manager.rememberJoin(request)).toThrow("Room unavailable");
    const ownLeave = manager.beginLeave(roomRecord.id);
    manager.forgetLeave(roomRecord.id, ownLeave.request_id as string);
    expect(manager.pendingLeaves()).toHaveLength(0);

    const owned = sessionWith(); const owner = new MlsRoomManager(owned.session, "Alice", "node", bytes(608, 7)); owner.createRoom(roomRecord);
    expect(() => owner.rememberJoin({ ...request, username: "alice", stable_identity_b64: encodeBase64Url(bytes(64, 9)) })).toThrow("Room unavailable");
    expect(() => owner.rememberJoin({ ...request, username: "Carol", stable_identity_b64: encodeBase64Url(bytes(64, 7)) })).toThrow("Room unavailable");
  });

  it("binds owner leave approval to the exact member identity and clears only after commit", () => {
    const fake = sessionWith(); const manager = new MlsRoomManager(fake.session, "Alice", "node", bytes(608, 7));
    manager.createRoom(roomRecord);
    const join = { type: "mls_join_requested", protocol_version: 10, room_id: roomRecord.id, request_id: "join-request", username: "Bob", stable_identity_b64: encodeBase64Url(bytes(64, 6)), key_package_b64: encodeBase64Url(bytes(100, 8)) } as const;
    manager.rememberJoin(join);
    manager.finishTransaction(manager.acceptJoin(join.request_id, "join-message"), "ACCEPTED");

    const leave = { type: "mls_leave_requested", protocol_version: 10, room_id: roomRecord.id, request_id: "leave-request", username: "Bob", stable_identity_b64: join.stable_identity_b64 } as const;
    manager.rememberLeave(leave);
    manager.rememberLeave(leave);
    expect(manager.pendingLeaves()).toEqual([{ roomId: roomRecord.id, requestId: leave.request_id, username: "Bob" }]);
    expect(() => manager.rememberLeave({ ...leave, username: "Carol" })).toThrow("Room unavailable");
    expect(manager.rejectLeave(leave.request_id)).toMatchObject({ type: "mls_leave_reject", request_id: leave.request_id });
    expect(manager.pendingLeaves()).toHaveLength(1);
    manager.forgetLeave(leave.room_id, leave.request_id);
    expect(manager.pendingLeaves()).toHaveLength(0);
    manager.rememberLeave(leave);

    const prepared = manager.acceptLeave(leave.request_id, "leave-message");
    expect(prepared.requestType).toBe("leave");
    expect(fake.room.removeMember).toHaveBeenCalledWith("Bob", bytes(64, 6), "leave-message");
    expect(manager.pendingLeaves()).toHaveLength(1);
    manager.finishTransaction(prepared, "REJECTED");
    expect(manager.pendingLeaves()).toHaveLength(1);

    const retry = manager.acceptLeave(leave.request_id, "leave-retry");
    manager.finishTransaction(retry, "ACCEPTED");
    expect(manager.pendingLeaves()).toHaveLength(0);
    expect(fake.room.commitOutbound).toHaveBeenCalledWith("leave-retry", 3n);
  });

  it("rejects owner leave initiation and wipes pending leaves on room removal", () => {
    const fake = sessionWith(); const manager = new MlsRoomManager(fake.session, "Alice", "node", bytes(608, 7));
    manager.createRoom(roomRecord);
    expect(() => manager.beginLeave(roomRecord.id)).toThrow("Room unavailable");
    manager.removeRoom(roomRecord.id);
    expect(manager.pendingLeaves()).toHaveLength(0);
  });

  it("enforces the bounded pending-leave capacity at the exact limit", () => {
    const fake = sessionWith(); const manager = new MlsRoomManager(fake.session, "Alice", "node", bytes(608, 7));
    for (let index = 0; index < 128; index += 1) {
      const room = { ...roomRecord, id: `forum_room_${index}` };
      manager.createRoom(room);
      const join = {
        type: "mls_join_requested", protocol_version: 10, room_id: room.id, request_id: `join-${index}`,
        username: "Bob", stable_identity_b64: encodeBase64Url(bytes(64, 6)), key_package_b64: encodeBase64Url(bytes(100, 8)),
      } as const;
      manager.rememberJoin(join);
      manager.finishTransaction(manager.acceptJoin(join.request_id, `join-message-${index}`), "ACCEPTED");
      manager.rememberLeave({
        type: "mls_leave_requested", protocol_version: 10, room_id: room.id, request_id: `leave-${index}`,
        username: "Bob", stable_identity_b64: join.stable_identity_b64,
      });
    }
    expect(manager.pendingLeaves()).toHaveLength(128);
    expect(() => manager.rememberLeave({
      type: "mls_leave_requested", protocol_version: 10, room_id: "forum_room_0", request_id: "leave-overflow",
      username: "Carol", stable_identity_b64: encodeBase64Url(bytes(64, 5)),
    })).toThrow("Room unavailable");
    expect(manager.pendingLeaves()).toHaveLength(128);
    manager.close();
  });

  it("rejects oversized recovery catalogs before creating handles", () => {
    const fake = sessionWith(); const manager = new MlsRoomManager(fake.session, "Alice", "node", bytes(608, 7));
    expect(() => manager.recoverCatalog(Array.from({ length: 129 }, () => ({} as never)))).toThrow("Room unavailable");
    expect(fake.session.mlsRecoverRoom).not.toHaveBeenCalled();
  });

  it("recovers historical active state but blocks outbound use until relay synchronization", () => {
    const fake = sessionWith();
    const manager = new MlsRoomManager(fake.session, "Alice", "node", bytes(608, 7));
    const catalog: MlsRoomWire = {
      room_id: roomRecord.id, owner_username: "Alice", group_id_b64: encodeBase64Url(fake.room.groupId),
      active: true, synchronized: false, epoch: "1", revision: "1",
      membership_digest_b64: encodeBase64Url(bytes(32, 3)),
      roster: [
        { username: "Alice", stable_identity_b64: encodeBase64Url(bytes(64, 7)) },
        { username: "Bob", stable_identity_b64: encodeBase64Url(bytes(64, 6)) },
      ],
      recovery_snapshot: {
        active: true, epoch: "0", revision: "0", membership_digest_b64: encodeBase64Url(bytes(32, 2)),
        state_envelope_b64: encodeBase64Url(bytes(80, 8)),
        roster: [{ username: "alice", stable_identity_b64: encodeBase64Url(bytes(64, 7)) }],
      },
      policy: { self_destruct_timer_sec: "0", overall_expiry_sec: "60", allow_images: true, allow_videos: true, allow_files: true, enforce_text_absolute_expiry: true, image_read_timer_sec: "0", image_overall_expiry_sec: "60", enforce_image_absolute_expiry: true, video_read_timer_sec: "0", video_overall_expiry_sec: "60", enforce_video_absolute_expiry: true, file_read_timer_sec: "0", file_overall_expiry_sec: "60", enforce_file_absolute_expiry: true },
    };

    expect(manager.recoverCatalog([catalog])).toHaveLength(1);
    expect(fake.session.mlsRecoverRoom).toHaveBeenCalledOnce();
    expect(() => manager.prepareApplication(roomRecord.id, "blocked", "Alice", bytes(1, 1))).toThrow("Room unavailable");
  });

  it("retains accepted inactive join recovery without exposing the room in the dashboard", () => {
    const room = new FakeRoom();
    room.roomInfo = vi.fn(() => wrapper({
      roomId: roomRecord.id, groupId: room.groupId.slice(), epoch: 0n, memberCount: 0, revision: 0n,
      membershipDigest: new Uint8Array(0),
    }));
    const fake = sessionWith(room);
    const manager = new MlsRoomManager(fake.session, "Alice", "node", bytes(608, 7));
    const catalog: MlsRoomWire = {
      room_id: roomRecord.id, owner_username: "Bob", group_id_b64: encodeBase64Url(room.groupId),
      active: false, synchronized: false, epoch: "1", revision: "1",
      membership_digest_b64: encodeBase64Url(bytes(32, 3)),
      roster: [
        { username: "Bob", stable_identity_b64: encodeBase64Url(bytes(64, 6)) },
        { username: "Alice", stable_identity_b64: encodeBase64Url(bytes(64, 7)) },
      ],
      recovery_snapshot: {
        active: false, epoch: "0", revision: "0", membership_digest_b64: "",
        state_envelope_b64: encodeBase64Url(bytes(80, 8)), roster: [],
      },
      policy: { self_destruct_timer_sec: "0", overall_expiry_sec: "60", allow_images: true, allow_videos: true, allow_files: true, enforce_text_absolute_expiry: true, image_read_timer_sec: "0", image_overall_expiry_sec: "60", enforce_image_absolute_expiry: true, video_read_timer_sec: "0", video_overall_expiry_sec: "60", enforce_video_absolute_expiry: true, file_read_timer_sec: "0", file_overall_expiry_sec: "60", enforce_file_absolute_expiry: true },
    };

    expect(manager.recoverCatalog([catalog])).toEqual([]);
    expect(fake.session.mlsRecoverRoom).toHaveBeenCalledOnce();
    expect(() => manager.prepareApplication(roomRecord.id, "blocked", "Alice", bytes(1, 1))).toThrow("Room unavailable");
  });

  it("rejects a noncanonical initial native checkpoint and frees its handle", () => {
    const room = new FakeRoom(); room.roomInfo = vi.fn(() => wrapper({
      roomId: "forum_alpha", groupId: room.groupId.slice(), epoch: 0n, memberCount: 1, revision: 1n,
      membershipDigest: bytes(32, 2),
    }));
    const fake = sessionWith(room); const manager = new MlsRoomManager(fake.session, "Alice", "node", bytes(608, 7));
    expect(() => manager.createRoom(roomRecord)).toThrow("Room unavailable");
    expect(room.free).toHaveBeenCalledOnce();
  });

  it("binds application AAD to outer room, message, and sender", () => {
    const fake = sessionWith(); const manager = new MlsRoomManager(fake.session, "Alice", "node", bytes(608, 7)); manager.createRoom(roomRecord);
    const outgoing = manager.prepareApplication(roomRecord.id, "message", "Alice", bytes(1, 3)); manager.finishTransaction(outgoing, "ACCEPTED");
    const frame = {
      type: "mls_application", protocol_version: 10, room_id: roomRecord.id, message_id: "incoming", sender_username: "Bob",
      epoch: "0", revision: "2", membership_digest_b64: encodeBase64Url(bytes(32, 2)), ciphertext_b64: encodeBase64Url(bytes(120, 4)),
      authenticated_data_b64: outgoing.frame.authenticated_data_b64 as string,
    } as Extract<MlsIncomingFrame, { type: "mls_application" }>;
    expect(() => manager.receiveApplication(frame)).toThrow("Payload unavailable");
    expect(fake.room.decryptApplication).not.toHaveBeenCalled();
  });

  it("copies generated output before freeing its wrapper", () => {
    const fake = sessionWith(); const manager = new MlsRoomManager(fake.session, "Alice", "node", bytes(608, 7)); manager.createRoom(roomRecord);
    const prepared = manager.prepareApplication(roomRecord.id, "message", "Alice", bytes(2, 1));
    expect(decodeBase64Url(prepared.frame.ciphertext_b64 as string)).toEqual(bytes(120, 4));
    const native = fake.room.encryptApplication.mock.results[0].value as { free: ReturnType<typeof vi.fn> };
    expect(native.free).toHaveBeenCalledOnce();
  });

  it("commits or rolls back processed controls only after the exact snapshot result", () => {
    const accepted = sessionWith(); const manager = new MlsRoomManager(accepted.session, "Alice", "node", bytes(608, 7)); manager.createRoom(roomRecord);
    manager.prepareApplication(roomRecord.id, "control", "Alice", bytes(1, 1));
    const snapshot = { roomId: roomRecord.id, messageId: "control", revision: 2n, nativePending: true, frame: {} };
    manager.finishSnapshot(snapshot, "ACCEPTED");
    expect(accepted.room.commitOutbound).toHaveBeenCalledWith("control", 2n);
    const rejected = sessionWith(); const second = new MlsRoomManager(rejected.session, "Alice", "node", bytes(608, 7)); second.createRoom(roomRecord);
    second.prepareApplication(roomRecord.id, "control", "Alice", bytes(1, 1));
    second.finishSnapshot(snapshot, "REJECTED");
    expect(rejected.room.rollbackOutbound).toHaveBeenCalledWith("control", 2n);
  });

  it("stages received membership until its relay snapshot is accepted", () => {
    const fake = sessionWith(); const manager = new MlsRoomManager(fake.session, "Alice", "node", bytes(608, 7)); manager.createRoom(roomRecord);
    const frame = {
      type: "mls_membership", protocol_version: 10, room_id: roomRecord.id, message_id: "control", from_epoch: "0", to_epoch: "1", revision: "1",
      from_membership_digest_b64: encodeBase64Url(bytes(32, 2)), group_id_b64: encodeBase64Url(fake.room.groupId), membership_digest_b64: encodeBase64Url(bytes(32, 3)),
      roster: [{ username: "Alice", stable_identity_b64: encodeBase64Url(bytes(64, 7)) }], control_b64: encodeBase64Url(bytes(100, 4)),
      welcome_b64: "", authenticated_data_b64: encodeBase64Url(bytes(50, 6)),
    } as Extract<MlsIncomingFrame, { type: "mls_membership" }>;
    const snapshot = manager.receiveMembership(frame);
    expect(snapshot.frame).toMatchObject({ type: "mls_state_snapshot", message_id: "control", revision: "1" });
    expect(fake.room.commitOutbound).not.toHaveBeenCalled();
    manager.finishSnapshot(snapshot, "ACCEPTED");
    expect(fake.room.commitOutbound).toHaveBeenCalledWith("control", 1n);
    expect(fake.room.processControl.mock.results[0].value.free).toHaveBeenCalledOnce();
  });

  it.each(["REJECTED", "NOT_SENT"] as const)("rolls back but remains inbound-only when membership snapshot is %s", (outcome) => {
    const fake = sessionWith(); const manager = new MlsRoomManager(fake.session, "Alice", "node", bytes(608, 7)); manager.createRoom(roomRecord);
    const snapshot = manager.receiveMembership(membershipFrame(fake));
    manager.finishSnapshot(snapshot, outcome);
    const join = { type: "mls_join_requested", protocol_version: 10, room_id: roomRecord.id, request_id: `retry-${outcome}`, username: "Bob", stable_identity_b64: encodeBase64Url(bytes(64, 6)), key_package_b64: encodeBase64Url(bytes(100, 8)) } as const;
    expect(() => manager.rememberJoin(join)).toThrow("Room unavailable");
    expect(fake.room.rollbackOutbound).toHaveBeenCalledWith("control", 1n);
  });

  it("installs a received roster only after acceptance and destroys ambiguous state", () => {
    const accepted = sessionWith(); const manager = new MlsRoomManager(accepted.session, "Alice", "node", bytes(608, 7)); manager.createRoom(roomRecord);
    manager.finishSnapshot(manager.receiveMembership(membershipFrame(accepted)), "ACCEPTED");
    const duplicate = { type: "mls_join_requested", protocol_version: 10, room_id: roomRecord.id, request_id: "duplicate", username: "bob", stable_identity_b64: encodeBase64Url(bytes(64, 9)), key_package_b64: encodeBase64Url(bytes(100, 8)) } as const;
    expect(() => manager.rememberJoin(duplicate)).toThrow("Room unavailable");

    const ambiguous = sessionWith(); const second = new MlsRoomManager(ambiguous.session, "Alice", "node", bytes(608, 7)); second.createRoom(roomRecord);
    second.finishSnapshot(second.receiveMembership(membershipFrame(ambiguous)), "AMBIGUOUS");
    expect(() => second.prepareApplication(roomRecord.id, "later", "Alice", bytes(1, 1))).toThrow("Room unavailable");
  });

  it("binds own join rejection to its exact pending request and room", () => {
    const fake = sessionWith(); const manager = new MlsRoomManager(fake.session, "Alice", "node", bytes(608, 7));
    const request = manager.beginJoin({ type: "mls_room_discovered", protocol_version: 10, room_id: "room_generic", group_id_b64: encodeBase64Url(bytes(32, 1)), owner_username: "Bob" });
    const requestId = request.request_id as string;
    expect(() => manager.rejectOwnJoin("room_generic", "wrong-request")).toThrow("Room unavailable");
    expect(() => manager.rejectOwnJoin("wrong-room", requestId)).toThrow("Room unavailable");
    manager.rejectOwnJoin("room_generic", requestId);
    expect(() => manager.rejectOwnJoin("room_generic", requestId)).toThrow("Room unavailable");
  });

  it("clears all manager state when catalog recovery conflicts with an established room", () => {
    const fake = sessionWith(); const manager = new MlsRoomManager(fake.session, "Alice", "node", bytes(608, 7)); manager.createRoom(roomRecord);
    const conflicting: MlsRoomWire = {
      room_id: roomRecord.id, owner_username: "Bob", group_id_b64: encodeBase64Url(fake.room.groupId), active: true, synchronized: true,
      epoch: "0", revision: "0", membership_digest_b64: encodeBase64Url(bytes(32, 2)),
      roster: [
        { username: "Alice", stable_identity_b64: encodeBase64Url(bytes(64, 7)) },
        { username: "Bob", stable_identity_b64: encodeBase64Url(bytes(64, 6)) },
      ],
      recovery_snapshot: {
        active: true, epoch: "0", revision: "0", membership_digest_b64: encodeBase64Url(bytes(32, 2)),
        state_envelope_b64: encodeBase64Url(bytes(80, 8)), roster: [
          { username: "alice", stable_identity_b64: encodeBase64Url(bytes(64, 7)) },
          { username: "bob", stable_identity_b64: encodeBase64Url(bytes(64, 6)) },
        ],
      },
      policy: { self_destruct_timer_sec: "0", overall_expiry_sec: "60", allow_images: true, allow_videos: true, allow_files: true, enforce_text_absolute_expiry: true, image_read_timer_sec: "0", image_overall_expiry_sec: "60", enforce_image_absolute_expiry: true, video_read_timer_sec: "0", video_overall_expiry_sec: "60", enforce_video_absolute_expiry: true, file_read_timer_sec: "0", file_overall_expiry_sec: "60", enforce_file_absolute_expiry: true },
    };
    expect(() => manager.recoverCatalog([conflicting])).toThrow("Room unavailable");
    expect(() => manager.prepareApplication(roomRecord.id, "later", "Alice", bytes(1, 1))).toThrow("Room unavailable");
    expect(fake.room.free).toHaveBeenCalledOnce();
  });

  it("returns decrypted plaintext only with a transaction-bound recovery snapshot", () => {
    const fake = sessionWith(); const manager = new MlsRoomManager(fake.session, "Alice", "node", bytes(608, 7)); manager.createRoom(roomRecord);
    const aadSource = manager.prepareApplication(roomRecord.id, "incoming", "Bob", bytes(1, 1));
    manager.finishTransaction(aadSource, "REJECTED");
    const frame = {
      type: "mls_application", protocol_version: 10, room_id: roomRecord.id, message_id: "incoming", sender_username: "Bob",
      epoch: "0", revision: "2", membership_digest_b64: encodeBase64Url(bytes(32, 2)), ciphertext_b64: encodeBase64Url(bytes(120, 4)),
      authenticated_data_b64: aadSource.frame.authenticated_data_b64 as string,
    } as Extract<MlsIncomingFrame, { type: "mls_application" }>;
    const result = manager.receiveApplication(frame);
    expect(new TextDecoder().decode(result.plaintext)).toBe('{"kind":"text"}');
    expect(result.snapshot.frame).toMatchObject({ message_id: "incoming", revision: "2" });
    expect(result.snapshot.nativePending).toBe(true);
    manager.finishSnapshot(result.snapshot, "ACCEPTED");
    expect(fake.room.commitOutbound).toHaveBeenLastCalledWith("incoming", 2n);
  });

  it("wipes decoded AAD and ciphertext when native decryption rejects", () => {
    const room = new FakeRoom(); let seenAad: Uint8Array | null = null; let seenCiphertext: Uint8Array | null = null;
    room.decryptApplication = vi.fn((ciphertext: Uint8Array, _epoch: bigint, _message: string, aad: Uint8Array) => {
      seenCiphertext = ciphertext; seenAad = aad; throw new Error("native rejection");
    });
    const fake = sessionWith(room); const manager = new MlsRoomManager(fake.session, "Alice", "node", bytes(608, 7)); manager.createRoom(roomRecord);
    const aadSource = manager.prepareApplication(roomRecord.id, "incoming", "Bob", bytes(1, 1));
    manager.finishTransaction(aadSource, "REJECTED");
    const frame = {
      type: "mls_application", protocol_version: 10, room_id: roomRecord.id, message_id: "incoming", sender_username: "Bob",
      epoch: "0", revision: "1", membership_digest_b64: encodeBase64Url(bytes(32, 2)), ciphertext_b64: encodeBase64Url(bytes(120, 4)),
      authenticated_data_b64: aadSource.frame.authenticated_data_b64 as string,
    } as Extract<MlsIncomingFrame, { type: "mls_application" }>;
    expect(() => manager.receiveApplication(frame)).toThrow("native rejection");
    expect(seenAad).toBeInstanceOf(Uint8Array);
    expect((seenAad ?? new Uint8Array([1])).every((byte) => byte === 0)).toBe(true);
    expect(seenCiphertext).toBeInstanceOf(Uint8Array);
    expect((seenCiphertext ?? new Uint8Array([1])).every((byte) => byte === 0)).toBe(true);
    expect(room.free).toHaveBeenCalledOnce();
  });

  it("wipes membership inputs when native control processing rejects", () => {
    const room = new FakeRoom(); let seenControl: Uint8Array | null = null; let seenDigest: Uint8Array | null = null; let seenAad: Uint8Array | null = null;
    room.processControl = vi.fn((control: Uint8Array, _from: bigint, _to: bigint, _roster: string, digest: Uint8Array, _messageId: string, aad: Uint8Array) => {
      seenControl = control; seenDigest = digest; seenAad = aad; throw new Error("native rejection");
    });
    const fake = sessionWith(room); const manager = new MlsRoomManager(fake.session, "Alice", "node", bytes(608, 7)); manager.createRoom(roomRecord);
    const frame = {
      type: "mls_membership", protocol_version: 10, room_id: roomRecord.id, message_id: "control", from_epoch: "0", to_epoch: "1", revision: "1",
      from_membership_digest_b64: encodeBase64Url(bytes(32, 2)), group_id_b64: encodeBase64Url(fake.room.groupId), membership_digest_b64: encodeBase64Url(bytes(32, 3)),
      roster: [{ username: "Alice", stable_identity_b64: encodeBase64Url(bytes(64, 7)) }], control_b64: encodeBase64Url(bytes(100, 4)),
      welcome_b64: "", authenticated_data_b64: encodeBase64Url(bytes(50, 6)),
    } as Extract<MlsIncomingFrame, { type: "mls_membership" }>;
    expect(() => manager.receiveMembership(frame)).toThrow("native rejection");
    expect(seenControl).toBeInstanceOf(Uint8Array);
    expect((seenControl ?? new Uint8Array([1])).every((byte) => byte === 0)).toBe(true);
    expect(seenDigest).toBeInstanceOf(Uint8Array);
    expect((seenDigest ?? new Uint8Array([1])).every((byte) => byte === 0)).toBe(true);
    expect(seenAad).toBeInstanceOf(Uint8Array);
    expect((seenAad ?? new Uint8Array([1])).every((byte) => byte === 0)).toBe(true);
    expect(room.free).toHaveBeenCalledOnce();
  });
});

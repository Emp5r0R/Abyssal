import { describe, expect, it } from "vitest";
import {
  decimalU64,
  encodeBase64Url,
  parseCanonicalU64,
  parseMlsIncomingFrame,
  roomFromMlsWire,
  validMlsControlFrame,
  type MlsRoomWire,
} from "./mlsWire";

const b64 = (bytes: number, fill = 1) => encodeBase64Url(new Uint8Array(bytes).fill(fill));
const policy = {
  self_destruct_timer_sec: "0", overall_expiry_sec: "86400", allow_images: true, allow_videos: true,
  allow_files: true, enforce_text_absolute_expiry: false, image_read_timer_sec: "5",
  image_overall_expiry_sec: "60", enforce_image_absolute_expiry: true, video_read_timer_sec: "5",
  video_overall_expiry_sec: "60", enforce_video_absolute_expiry: true, file_read_timer_sec: "5",
  file_overall_expiry_sec: "60", enforce_file_absolute_expiry: true,
};
const room = (): MlsRoomWire => ({
  room_id: "forum_alpha", owner_username: "Alice", group_id_b64: b64(32), active: true, synchronized: true,
  epoch: "0", revision: "1", membership_digest_b64: b64(32, 2),
  roster: [{ username: "Alice", stable_identity_b64: b64(64, 3) }],
  recovery_snapshot: {
    active: true, epoch: "0", revision: "1", membership_digest_b64: b64(32, 2),
    state_envelope_b64: b64(80, 8), roster: [{ username: "alice", stable_identity_b64: b64(64, 3) }],
  }, policy,
});

describe("protocol-v10 MLS wire", () => {
  it("accepts the full canonical catalog and converts counters without precision loss", () => {
    const frame = parseMlsIncomingFrame({ type: "mls_rooms", protocol_version: 10, rooms: [room()] });
    expect(frame?.type).toBe("mls_rooms");
    const record = roomFromMlsWire(room());
    expect(record.mlsEpoch).toBe(0n);
    expect(record.overall_expiry_sec).toBe(86400);
  });

  it.each(["", "00", "01", "+1", "-1", " 1", "1.0", "1".repeat(21), "18446744073709551616"])(
    "rejects noncanonical u64 %s", (value) => expect(parseCanonicalU64(value)).toBeNull(),
  );

  it("round-trips the maximum u64 and rejects unsafe number input", () => {
    expect(parseCanonicalU64(decimalU64(18_446_744_073_709_551_615n))).toBe(18_446_744_073_709_551_615n);
    expect(parseCanonicalU64(Number.MAX_SAFE_INTEGER)).toBeNull();
  });

  it("denies unknown fields at the outer, nested room, roster, snapshot, and policy levels", () => {
    const base = room();
    expect(parseMlsIncomingFrame({ type: "mls_rooms", protocol_version: 10, rooms: [{ ...base, extra: true }] })).toBeNull();
    expect(parseMlsIncomingFrame({ type: "mls_rooms", protocol_version: 10, rooms: [{ ...base, roster: [{ ...base.roster[0], extra: true }] }] })).toBeNull();
    expect(parseMlsIncomingFrame({ type: "mls_rooms", protocol_version: 10, rooms: [{ ...base, policy: { ...policy, extra: true } }] })).toBeNull();
  });

  it("rejects noncanonical base64url and wrong exact-length cryptographic fields", () => {
    expect(parseMlsIncomingFrame({ type: "mls_rooms", protocol_version: 10, rooms: [{ ...room(), group_id_b64: "AR" }] })).toBeNull();
    expect(parseMlsIncomingFrame({ type: "mls_rooms", protocol_version: 10, rooms: [{ ...room(), membership_digest_b64: b64(31) }] })).toBeNull();
  });

  it("validates transaction results as room/message/revision bound", () => {
    const result = { type: "mls_room_result", protocol_version: 10, room_id: "forum_alpha", message_id: "message", revision: "2", accepted: true };
    expect(parseMlsIncomingFrame(result)).toEqual(result);
    expect(parseMlsIncomingFrame({ ...result, revision: 2 })).toBeNull();
    expect(parseMlsIncomingFrame({ ...result, extra: true })).toBeNull();
  });

  it("enforces roster and policy bounds", () => {
    expect(parseMlsIncomingFrame({ type: "mls_rooms", protocol_version: 10, rooms: [{ ...room(), roster: [] }] })).toBeNull();
    expect(parseMlsIncomingFrame({ type: "mls_rooms", protocol_version: 10, rooms: [{ ...room(), policy: { ...policy, overall_expiry_sec: "86401" } }] })).toBeNull();
  });

  it("rejects canonical username collisions, stable-identity reuse, and an absent owner", () => {
    const base = room();
    const alice = base.roster[0];
    expect(parseMlsIncomingFrame({ type: "mls_rooms", protocol_version: 10, rooms: [{
      ...base, roster: [alice, { username: "alice", stable_identity_b64: b64(64, 4) }],
    }] })).toBeNull();
    expect(parseMlsIncomingFrame({ type: "mls_rooms", protocol_version: 10, rooms: [{
      ...base, roster: [alice, { username: "Bob", stable_identity_b64: alice.stable_identity_b64 }],
    }] })).toBeNull();
    expect(parseMlsIncomingFrame({ type: "mls_rooms", protocol_version: 10, rooms: [{
      ...base, roster: [{ username: "Bob", stable_identity_b64: b64(64, 4) }],
    }] })).toBeNull();
  });

  it("accepts only the relay's exact inactive pending-join catalog shape", () => {
    const pending = {
      ...room(), active: false, synchronized: false, epoch: "0", revision: "0", membership_digest_b64: "", roster: [],
      recovery_snapshot: {
        active: false, epoch: "0", revision: "0", membership_digest_b64: "", state_envelope_b64: b64(80, 8), roster: [],
      },
    };
    expect(parseMlsIncomingFrame({ type: "mls_rooms", protocol_version: 10, rooms: [pending] })).not.toBeNull();
    expect(parseMlsIncomingFrame({ type: "mls_rooms", protocol_version: 10, rooms: [{ ...pending, active: true }] })).toBeNull();
    expect(parseMlsIncomingFrame({ type: "mls_rooms", protocol_version: 10, rooms: [{ ...pending, epoch: "1" }] })).toBeNull();
    expect(parseMlsIncomingFrame({ type: "mls_rooms", protocol_version: 10, rooms: [{ ...pending, roster: room().roster }] })).toBeNull();
  });

  it("accepts an owner-approved inactive join with current outer roster and empty recovery state", () => {
    const accepted = {
      ...room(), active: false, synchronized: false, epoch: "1", revision: "1",
      membership_digest_b64: b64(32, 4),
      roster: [
        { username: "Alice", stable_identity_b64: b64(64, 3) },
        { username: "Bob", stable_identity_b64: b64(64, 4) },
      ],
      recovery_snapshot: {
        active: false, epoch: "0", revision: "0", membership_digest_b64: "",
        state_envelope_b64: b64(80, 8), roster: [],
      },
    };
    expect(parseMlsIncomingFrame({ type: "mls_rooms", protocol_version: 10, rooms: [accepted] })).not.toBeNull();
    expect(parseMlsIncomingFrame({ type: "mls_rooms", protocol_version: 10, rooms: [{ ...accepted, synchronized: true }] })).toBeNull();
  });

  it("allows only strict nontransactional MLS client controls", () => {
    const create = {
      type: "mls_create_room", protocol_version: 10, room_id: "forum_alpha", group_id_b64: b64(32),
      epoch: "0", revision: "0", membership_digest_b64: b64(32, 2), stable_identity_b64: b64(64, 3),
      state_envelope_b64: b64(96, 4), policy,
    };
    expect(validMlsControlFrame(create)).toBe(true);
    expect(validMlsControlFrame({ ...create, revision: "1" })).toBe(false);
    expect(validMlsControlFrame({ ...create, extra: true })).toBe(false);
    expect(validMlsControlFrame({ type: "mls_application", protocol_version: 10, room_id: "forum_alpha" })).toBe(false);
    expect(validMlsControlFrame({ type: "mls_state_snapshot", protocol_version: 10, room_id: "forum_alpha" })).toBe(false);
    expect(validMlsControlFrame({ type: "mls_discover_room", protocol_version: 10, room_id: "forum_alpha" })).toBe(true);
  });

  it("accepts only exact leave controls and bounded leave events", () => {
    const request = { type: "mls_leave_request", protocol_version: 10, room_id: "forum_alpha", request_id: "leave-request" };
    const reject = { type: "mls_leave_reject", protocol_version: 10, room_id: "forum_alpha", request_id: "leave-request" };
    expect(validMlsControlFrame(request)).toBe(true);
    expect(validMlsControlFrame(reject)).toBe(true);
    expect(validMlsControlFrame({ ...request, extra: true })).toBe(false);
    expect(parseMlsIncomingFrame({
      type: "mls_leave_requested", protocol_version: 10, room_id: "forum_alpha", request_id: "leave-request",
      username: "Bob", stable_identity_b64: b64(64, 7),
    })).toMatchObject({ type: "mls_leave_requested", username: "Bob" });
    expect(parseMlsIncomingFrame({ type: "mls_leave_pending", protocol_version: 10, room_id: "forum_alpha", request_id: "leave-request", extra: true })).toBeNull();
  });
});

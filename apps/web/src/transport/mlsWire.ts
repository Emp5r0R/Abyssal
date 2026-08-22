import type { RoomRecord } from "../domain/types";

export const MLS_PROTOCOL_VERSION = 10;
export const MLS_MAX_FRAME_BYTES = 16 * 1024 * 1024;
export const MLS_MAX_APPLICATION_BYTES = 1024 * 1024;
export const MLS_MAX_STATE_BYTES = 4 * 1024 * 1024;
export const MLS_MAX_CONTROL_BYTES = 2 * 1024 * 1024;
export const MLS_MAX_AAD_BYTES = 4096;
export const MLS_MAX_MEMBERS = 117;
const U64_MAX = 18_446_744_073_709_551_615n;
const ID = /^[A-Za-z0-9_-]{1,128}$/u;
const USERNAME = /^[A-Za-z0-9_-]{1,80}$/u;
const B64 = /^[A-Za-z0-9_-]*$/u;

export interface MlsRosterMemberWire {
  username: string;
  stable_identity_b64: string;
}

export interface MlsRecoverySnapshotWire {
  active: boolean;
  epoch: string;
  revision: string;
  membership_digest_b64: string;
  state_envelope_b64: string;
  roster: MlsRosterMemberWire[];
}

export interface MlsRoomWire {
  room_id: string;
  owner_username: string;
  group_id_b64: string;
  active: boolean;
  synchronized: boolean;
  epoch: string;
  revision: string;
  membership_digest_b64: string;
  roster: MlsRosterMemberWire[];
  recovery_snapshot: MlsRecoverySnapshotWire | null;
  policy: MlsRoomPolicyWire;
}

export interface MlsRoomPolicyWire {
  self_destruct_timer_sec: string;
  overall_expiry_sec: string;
  allow_images: boolean;
  allow_videos: boolean;
  allow_files: boolean;
  enforce_text_absolute_expiry: boolean;
  image_read_timer_sec: string;
  image_overall_expiry_sec: string;
  enforce_image_absolute_expiry: boolean;
  video_read_timer_sec: string;
  video_overall_expiry_sec: string;
  enforce_video_absolute_expiry: boolean;
  file_read_timer_sec: string;
  file_overall_expiry_sec: string;
  enforce_file_absolute_expiry: boolean;
}

export type MlsIncomingFrame =
  | { type: "mls_rooms"; protocol_version: 10; rooms: MlsRoomWire[] }
  | { type: "mls_room_discovered"; protocol_version: 10; room_id: string; group_id_b64: string; owner_username: string }
  | { type: "mls_room_created"; protocol_version: 10; room: MlsRoomWire }
  | { type: "mls_join_requested"; protocol_version: 10; room_id: string; request_id: string; username: string; stable_identity_b64: string; key_package_b64: string }
  | { type: "mls_join_rejected"; protocol_version: 10; room_id: string; request_id: string }
  | { type: "mls_leave_requested"; protocol_version: 10; room_id: string; request_id: string; username: string; stable_identity_b64: string }
  | { type: "mls_leave_pending"; protocol_version: 10; room_id: string; request_id: string }
  | { type: "mls_leave_rejected"; protocol_version: 10; room_id: string; request_id: string }
  | { type: "mls_left"; protocol_version: 10; room_id: string }
  | { type: "mls_membership"; protocol_version: 10; room_id: string; message_id: string; from_epoch: string; to_epoch: string; revision: string; from_membership_digest_b64: string; group_id_b64: string; membership_digest_b64: string; roster: MlsRosterMemberWire[]; control_b64: string; welcome_b64: string; authenticated_data_b64: string }
  | { type: "mls_application"; protocol_version: 10; room_id: string; message_id: string; sender_username: string; epoch: string; revision: string; membership_digest_b64: string; ciphertext_b64: string; authenticated_data_b64: string }
  | { type: "mls_room_result"; protocol_version: 10; room_id: string; message_id: string; revision: string; accepted: boolean }
  | { type: "mls_room_deleted"; protocol_version: 10; room_id: string }
  | { type: "mls_snapshot_result"; protocol_version: 10; room_id: string; message_id: string; revision: string; accepted: boolean };

export function parseCanonicalU64(value: unknown): bigint | null {
  if (typeof value !== "string" || value.length > 20 || !/^(?:0|[1-9][0-9]*)$/u.test(value)) return null;
  try {
    const result = BigInt(value);
    return result <= U64_MAX ? result : null;
  } catch {
    return null;
  }
}

export function decimalU64(value: bigint | number): string {
  const normalized = typeof value === "bigint" ? value : BigInt(value);
  if (normalized < 0n || normalized > U64_MAX) throw new Error("Room unavailable");
  return normalized.toString(10);
}

export function mlsPolicyFromRoom(room: RoomRecord): MlsRoomPolicyWire {
  return {
    self_destruct_timer_sec: decimalU64(room.self_destruct_timer_sec),
    overall_expiry_sec: decimalU64(room.overall_expiry_sec),
    allow_images: room.allow_images,
    allow_videos: room.allow_videos,
    allow_files: room.allow_files,
    enforce_text_absolute_expiry: room.enforce_text_absolute_expiry,
    image_read_timer_sec: decimalU64(room.image_read_timer_sec),
    image_overall_expiry_sec: decimalU64(room.image_overall_expiry_sec),
    enforce_image_absolute_expiry: room.enforce_image_absolute_expiry,
    video_read_timer_sec: decimalU64(room.video_read_timer_sec),
    video_overall_expiry_sec: decimalU64(room.video_overall_expiry_sec),
    enforce_video_absolute_expiry: room.enforce_video_absolute_expiry,
    file_read_timer_sec: decimalU64(room.file_read_timer_sec),
    file_overall_expiry_sec: decimalU64(room.file_overall_expiry_sec),
    enforce_file_absolute_expiry: room.enforce_file_absolute_expiry,
  };
}

export function roomFromMlsWire(room: MlsRoomWire): RoomRecord {
  const number = (value: string) => Number(parseCanonicalU64(value));
  return {
    id: room.room_id,
    name: room.room_id.replace(/^forum_/u, "").replace(/_[0-9a-f]{8}$/u, "").replace(/_/gu, " ").slice(0, 36) || "Secure room",
    owner_username: room.owner_username,
    conversation_type: "room",
    mlsActive: room.active,
    mlsEpoch: parseCanonicalU64(room.epoch)!,
    mlsRevision: parseCanonicalU64(room.revision)!,
    mlsMembers: room.roster.map((member) => member.username),
    self_destruct_timer_sec: number(room.policy.self_destruct_timer_sec),
    overall_expiry_sec: number(room.policy.overall_expiry_sec),
    allow_images: room.policy.allow_images,
    allow_videos: room.policy.allow_videos,
    allow_files: room.policy.allow_files,
    enforce_text_absolute_expiry: room.policy.enforce_text_absolute_expiry,
    image_read_timer_sec: number(room.policy.image_read_timer_sec),
    image_overall_expiry_sec: number(room.policy.image_overall_expiry_sec),
    enforce_image_absolute_expiry: room.policy.enforce_image_absolute_expiry,
    video_read_timer_sec: number(room.policy.video_read_timer_sec),
    video_overall_expiry_sec: number(room.policy.video_overall_expiry_sec),
    enforce_video_absolute_expiry: room.policy.enforce_video_absolute_expiry,
    file_read_timer_sec: number(room.policy.file_read_timer_sec),
    file_overall_expiry_sec: number(room.policy.file_overall_expiry_sec),
    enforce_file_absolute_expiry: room.policy.enforce_file_absolute_expiry,
  };
}

export function parseMlsIncomingFrame(value: Record<string, unknown>): MlsIncomingFrame | null {
  if (value.protocol_version !== MLS_PROTOCOL_VERSION || typeof value.type !== "string") return null;
  const exact = (keys: string[]) => exactKeys(value, ["type", "protocol_version", ...keys]);
  switch (value.type) {
    case "mls_rooms":
      return exact(["rooms"]) && Array.isArray(value.rooms) && value.rooms.length <= 1024 &&
        value.rooms.every(validRoom) ? value as unknown as MlsIncomingFrame : null;
    case "mls_room_created":
      return exact(["room"]) && validRoom(value.room) ? value as unknown as MlsIncomingFrame : null;
    case "mls_room_discovered":
      return exact(["room_id", "group_id_b64", "owner_username"]) && validId(value.room_id) &&
        validB64(value.group_id_b64, 32, 32) && validUsername(value.owner_username) ? value as MlsIncomingFrame : null;
    case "mls_join_requested":
      return exact(["room_id", "request_id", "username", "stable_identity_b64", "key_package_b64"]) &&
        validId(value.room_id) && validId(value.request_id) && validUsername(value.username) &&
        validB64(value.stable_identity_b64, 64, 64) && validB64(value.key_package_b64, 1, 64 * 1024)
        ? value as MlsIncomingFrame : null;
    case "mls_leave_requested":
      return exact(["room_id", "request_id", "username", "stable_identity_b64"]) && validId(value.room_id) &&
        validId(value.request_id) && validUsername(value.username) && validB64(value.stable_identity_b64, 64, 64)
        ? value as MlsIncomingFrame : null;
    case "mls_join_rejected": case "mls_leave_pending": case "mls_leave_rejected":
      return exact(["room_id", "request_id"]) && validId(value.room_id) && validId(value.request_id)
        ? value as MlsIncomingFrame : null;
    case "mls_left": case "mls_room_deleted":
      return exact(["room_id"]) && validId(value.room_id) ? value as MlsIncomingFrame : null;
    case "mls_membership":
      return exact(["room_id", "message_id", "from_epoch", "to_epoch", "revision", "from_membership_digest_b64", "group_id_b64", "membership_digest_b64", "roster", "control_b64", "welcome_b64", "authenticated_data_b64"]) &&
        validId(value.room_id) && validId(value.message_id) && validCounters(value, ["from_epoch", "to_epoch", "revision"]) &&
        validB64(value.from_membership_digest_b64, 32, 32) && validB64(value.group_id_b64, 32, 32) &&
        validB64(value.membership_digest_b64, 32, 32) && validRoster(value.roster, false) &&
        validB64(value.control_b64, 1, MLS_MAX_CONTROL_BYTES) && validB64(value.welcome_b64, 0, MLS_MAX_CONTROL_BYTES) &&
        validB64(value.authenticated_data_b64, 1, MLS_MAX_AAD_BYTES) ? value as MlsIncomingFrame : null;
    case "mls_application":
      return exact(["room_id", "message_id", "sender_username", "epoch", "revision", "membership_digest_b64", "ciphertext_b64", "authenticated_data_b64"]) &&
        validId(value.room_id) && validId(value.message_id) && validUsername(value.sender_username) &&
        validCounters(value, ["epoch", "revision"]) && validB64(value.membership_digest_b64, 32, 32) &&
        validB64(value.ciphertext_b64, 1, MLS_MAX_APPLICATION_BYTES) && validB64(value.authenticated_data_b64, 1, MLS_MAX_AAD_BYTES)
        ? value as MlsIncomingFrame : null;
    case "mls_room_result":
      return exact(["room_id", "message_id", "revision", "accepted"]) && validId(value.room_id) &&
        validId(value.message_id) && parseCanonicalU64(value.revision) !== null && typeof value.accepted === "boolean"
        ? value as MlsIncomingFrame : null;
    case "mls_snapshot_result":
      return exact(["room_id", "message_id", "revision", "accepted"]) && validId(value.room_id) && validId(value.message_id) &&
        parseCanonicalU64(value.revision) !== null && typeof value.accepted === "boolean"
        ? value as MlsIncomingFrame : null;
    default: return null;
  }
}

export function validMlsControlFrame(value: Record<string, unknown>): boolean {
  if (value.protocol_version !== MLS_PROTOCOL_VERSION || typeof value.type !== "string") return false;
  const exact = (keys: string[]) => exactKeys(value, ["type", "protocol_version", ...keys]);
  switch (value.type) {
    case "mls_create_room":
      return exact(["room_id", "group_id_b64", "epoch", "revision", "membership_digest_b64", "stable_identity_b64", "state_envelope_b64", "policy"]) &&
        validId(value.room_id) && validB64(value.group_id_b64, 32, 32) && value.epoch === "0" && value.revision === "0" &&
        validB64(value.membership_digest_b64, 32, 32) && validB64(value.stable_identity_b64, 64, 64) &&
        validB64(value.state_envelope_b64, 1, MLS_MAX_STATE_BYTES) && validPolicy(value.policy);
    case "mls_discover_room":
    case "mls_delete_room":
      return exact(["room_id"]) && validId(value.room_id);
    case "mls_join_request":
      return exact(["room_id", "request_id", "stable_identity_b64", "key_package_b64", "state_envelope_b64"]) &&
        validId(value.room_id) && validId(value.request_id) && validB64(value.stable_identity_b64, 64, 64) &&
        validB64(value.key_package_b64, 1, 64 * 1024) && validB64(value.state_envelope_b64, 1, MLS_MAX_STATE_BYTES);
    case "mls_join_reject":
    case "mls_leave_request":
    case "mls_leave_reject":
      return exact(["room_id", "request_id"]) && validId(value.room_id) && validId(value.request_id);
    default:
      return false;
  }
}

function validRoom(value: unknown): value is MlsRoomWire {
  if (!record(value) || !exactKeys(value, ["room_id", "owner_username", "group_id_b64", "active", "synchronized", "epoch", "revision", "membership_digest_b64", "roster", "recovery_snapshot", "policy"])) return false;
  if (!validId(value.room_id) || !validUsername(value.owner_username) || !validB64(value.group_id_b64, 32, 32) ||
    typeof value.active !== "boolean" || typeof value.synchronized !== "boolean" ||
    !validCounters(value, ["epoch", "revision"]) || !validRecovery(value.recovery_snapshot) ||
    value.recovery_snapshot.active !== value.active || !validPolicy(value.policy)) return false;
  const rosterEmpty = Array.isArray(value.roster) && value.roster.length === 0;
  if (rosterEmpty) {
    if (value.active || value.synchronized || value.epoch !== "0" || value.revision !== "0" ||
      value.membership_digest_b64 !== "" || !validRoster(value.roster, true)) return false;
  } else {
    if (!validB64(value.membership_digest_b64, 32, 32) || !validRoster(value.roster, false)) return false;
    const ownerUsername = value.owner_username as string;
    const owners = value.roster.filter((member) => canonicalUsername(member.username) === canonicalUsername(ownerUsername));
    if (owners.length !== 1 || owners[0].username !== ownerUsername) return false;
  }
  if (!value.synchronized) return true;
  return value.active && value.recovery_snapshot.epoch === value.epoch &&
    value.recovery_snapshot.revision === value.revision &&
    value.recovery_snapshot.membership_digest_b64 === value.membership_digest_b64 &&
    sameRoster(value.recovery_snapshot.roster, value.roster);
}

function validRecovery(value: unknown): value is MlsRecoverySnapshotWire {
  if (!record(value) || !exactKeys(value, ["active", "epoch", "revision", "membership_digest_b64", "state_envelope_b64", "roster"]) ||
    typeof value.active !== "boolean" || !validCounters(value, ["epoch", "revision"]) ||
    !validB64(value.state_envelope_b64, 1, MLS_MAX_STATE_BYTES)) return false;
  if (value.active) return validB64(value.membership_digest_b64, 32, 32) && validRoster(value.roster, false);
  return value.epoch === "0" && value.revision === "0" && value.membership_digest_b64 === "" &&
    validRoster(value.roster, true) && value.roster.length === 0;
}

function validRoster(value: unknown, allowEmpty: boolean): value is MlsRosterMemberWire[] {
  if (!Array.isArray(value) || (!allowEmpty && value.length === 0) || value.length > MLS_MAX_MEMBERS) return false;
  const usernames = new Set<string>();
  const identities = new Set<string>();
  for (const member of value) {
    if (!record(member) || !exactKeys(member, ["username", "stable_identity_b64"]) ||
      !validUsername(member.username) || !validB64(member.stable_identity_b64, 64, 64)) return false;
    const username = canonicalUsername(member.username);
    if (usernames.has(username) || identities.has(member.stable_identity_b64)) return false;
    usernames.add(username); identities.add(member.stable_identity_b64);
  }
  return true;
}

function validPolicy(value: unknown): value is MlsRoomPolicyWire {
  const timer = ["self_destruct_timer_sec", "overall_expiry_sec", "image_read_timer_sec", "image_overall_expiry_sec", "video_read_timer_sec", "video_overall_expiry_sec", "file_read_timer_sec", "file_overall_expiry_sec"];
  const flags = ["allow_images", "allow_videos", "allow_files", "enforce_text_absolute_expiry", "enforce_image_absolute_expiry", "enforce_video_absolute_expiry", "enforce_file_absolute_expiry"];
  return record(value) && exactKeys(value, [...timer, ...flags]) && timer.every((key) => {
    const parsed = parseCanonicalU64(value[key]); return parsed !== null && parsed <= 86_400n;
  }) && flags.every((key) => typeof value[key] === "boolean");
}

function validCounters(value: Record<string, unknown>, keys: string[]): boolean { return keys.every((key) => parseCanonicalU64(value[key]) !== null); }
function validId(value: unknown): value is string { return typeof value === "string" && ID.test(value); }
function validUsername(value: unknown): value is string { return typeof value === "string" && USERNAME.test(value); }
function canonicalUsername(value: string): string { return value.toLowerCase(); }
function sameRoster(left: MlsRosterMemberWire[], right: MlsRosterMemberWire[]): boolean {
  if (left.length !== right.length) return false;
  const byName = new Map(right.map((member) => [canonicalUsername(member.username), member.stable_identity_b64]));
  return left.every((member) => byName.get(canonicalUsername(member.username)) === member.stable_identity_b64);
}
function record(value: unknown): value is Record<string, unknown> { return !!value && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exactKeys(value: Record<string, unknown>, keys: string[]): boolean { const actual = Object.keys(value); return actual.length === keys.length && keys.every((key) => Object.prototype.hasOwnProperty.call(value, key)); }
function validB64(value: unknown, min: number, max: number): value is string {
  if (typeof value !== "string" || !B64.test(value) || value.length > Math.ceil(max / 3) * 4) return false;
  let bytes: Uint8Array | null = null;
  try { bytes = decodeBase64Url(value); return bytes.byteLength >= min && bytes.byteLength <= max && encodeBase64Url(bytes) === value; }
  catch { return false; }
  finally { bytes?.fill(0); }
}

export function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (let offset = 0; offset < bytes.byteLength; offset += 0x8000) binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  return btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/gu, "");
}

export function decodeBase64Url(value: string): Uint8Array {
  if (!B64.test(value) || value.length % 4 === 1) throw new Error("Room unavailable");
  const padded = value.replace(/-/gu, "+").replace(/_/gu, "/") + "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(padded); const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  if (encodeBase64Url(out) !== value) { out.fill(0); throw new Error("Room unavailable"); }
  return out;
}

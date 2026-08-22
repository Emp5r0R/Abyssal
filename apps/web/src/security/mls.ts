import type { WasmE2eeSession, WasmMlsProcessedControl, WasmMlsRoom, WasmMlsRoomInfo } from "../generated/abyssal_core/abyssal_core";
import type { RoomRecord } from "../domain/types";
import {
  decodeBase64Url,
  decimalU64,
  encodeBase64Url,
  MLS_PROTOCOL_VERSION,
  mlsPolicyFromRoom,
  parseCanonicalU64,
  roomFromMlsWire,
  type MlsIncomingFrame,
  type MlsRoomWire,
  type MlsRosterMemberWire,
} from "../transport/mlsWire";

const ENCODER = new TextEncoder();
const MAX_ROOMS = 128;
const MAX_PENDING_JOINS = 128;
const MAX_PENDING_LEAVES = 128;
const IDENTITY_PUBLIC_KEY_BYTES = 608;
const ID = /^[A-Za-z0-9_-]{1,128}$/u;
const USERNAME = /^[A-Za-z0-9_-]{1,80}$/u;
const NODE_ID = /^[A-Za-z0-9._:-]{1,128}$/u;

export type MlsTransactionOutcome = "ACCEPTED" | "REJECTED" | "NOT_SENT" | "AMBIGUOUS";

export interface PreparedMlsApplication {
  roomId: string;
  messageId: string;
  revision: bigint;
  frame: Record<string, unknown>;
}

export interface PreparedMlsMembership extends PreparedMlsApplication {
  requestId?: string;
  requestType?: "join" | "leave";
}

export interface DecryptedMlsApplication {
  plaintext: Uint8Array;
  snapshot: PreparedMlsSnapshot;
}

export interface PreparedMlsSnapshot extends PreparedMlsApplication {
  nativePending: boolean;
  membershipPending?: boolean;
}

export interface PendingMlsJoinSummary {
  roomId: string;
  requestId: string;
  username: string;
}

export interface PendingMlsLeaveSummary {
  roomId: string;
  requestId: string;
  username: string;
}

interface PendingMlsJoin extends PendingMlsJoinSummary {
  stableIdentity: Uint8Array;
  keyPackage: Uint8Array;
}

interface PendingMlsLeave extends PendingMlsLeaveSummary {
  stableIdentity: Uint8Array;
  own: boolean;
}

interface RoomSlot {
  handle: WasmMlsRoom;
  groupId: Uint8Array;
  ownerUsername: string;
  roster: MlsRosterMemberWire[];
  active: boolean;
  synchronized: boolean;
  pendingMessageId: string | null;
  pendingRevision: bigint | null;
  pendingRoster: MlsRosterMemberWire[] | null;
  ownJoinRequestId: string | null;
}

/** Owns every MLS handle derived from one authenticated account session. */
export class MlsRoomManager {
  readonly #session: WasmE2eeSession;
  readonly #username: string;
  readonly #nodeContext: Uint8Array;
  readonly #stableIdentity: Uint8Array;
  readonly #rooms = new Map<string, RoomSlot>();
  readonly #pendingJoins = new Map<string, PendingMlsJoin>();
  readonly #pendingLeaves = new Map<string, PendingMlsLeave>();
  #closed = false;

  constructor(session: WasmE2eeSession, username: string, nodeId: string, identityPublicKey: Uint8Array) {
    if (!USERNAME.test(username) || !NODE_ID.test(nodeId) || identityPublicKey.byteLength !== IDENTITY_PUBLIC_KEY_BYTES) {
      throw new Error("Room unavailable");
    }
    this.#session = session;
    this.#username = username;
    this.#nodeContext = ENCODER.encode(`ABYSSAL-MLS-V10-NODE:${nodeId}`);
    this.#stableIdentity = identityPublicKey.slice(0, 64);
  }

  createRoom(room: RoomRecord): Record<string, unknown> {
    this.assertOpen();
    if (!ID.test(room.id) || this.#rooms.has(room.id) || this.#rooms.size >= MAX_ROOMS) throw new Error("Room unavailable");
    const groupId = crypto.getRandomValues(new Uint8Array(32));
    let handle: WasmMlsRoom | null = null;
    let infoGroup: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let infoDigest: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let stateEnvelope: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    try {
      handle = this.#session.mlsCreateRoom(room.id, this.#username, this.#nodeContext, groupId);
      const info = readRoomInfo(handle);
      infoGroup = info.groupId;
      infoDigest = info.membershipDigest;
      if (info.epoch !== 0n || info.revision !== 0n || info.memberCount !== 1 ||
        infoGroup.byteLength !== 32 || !equal(infoGroup, groupId) || infoDigest.byteLength !== 32) {
        throw new Error("Room unavailable");
      }
      stateEnvelope = handle.sealState();
      const roster = [{ username: this.#username, stable_identity_b64: encodeBase64Url(this.#stableIdentity) }];
      this.#rooms.set(room.id, {
        handle, groupId: groupId.slice(), ownerUsername: this.#username, roster, active: true, synchronized: true,
        pendingMessageId: null, pendingRevision: null, pendingRoster: null, ownJoinRequestId: null,
      });
      handle = null;
      const frame = {
        type: "mls_create_room", protocol_version: MLS_PROTOCOL_VERSION, room_id: room.id,
        group_id_b64: encodeBase64Url(groupId), epoch: decimalU64(info.epoch), revision: decimalU64(info.revision),
        membership_digest_b64: encodeBase64Url(infoDigest),
        stable_identity_b64: encodeBase64Url(this.#stableIdentity), state_envelope_b64: encodeBase64Url(stateEnvelope),
        policy: mlsPolicyFromRoom(room),
      };
      return frame;
    } catch (error) {
      handle?.free();
      this.removeRoom(room.id);
      throw error;
    } finally {
      groupId.fill(0); infoGroup.fill(0); infoDigest.fill(0); stateEnvelope.fill(0);
    }
  }

  recoverCatalog(rooms: MlsRoomWire[]): RoomRecord[] {
    this.assertOpen();
    if (rooms.length > MAX_ROOMS) throw new Error("Room unavailable");
    const seen = new Set<string>();
    const output: RoomRecord[] = [];
    try {
      for (const room of rooms) {
        if (seen.has(room.room_id) || !validCatalogRoom(room, this.#username, this.#stableIdentity)) throw new Error("Room unavailable");
        seen.add(room.room_id);
        if (room.active) output.push(roomFromMlsWire(room));
        const recovery = room.recovery_snapshot;
        if (!recovery) throw new Error("Room unavailable");
        const existing = this.#rooms.get(room.room_id);
        if (existing) {
          const info = readRoomInfo(existing.handle);
          let digest: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
          let group: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
          let exact: boolean;
          try {
            digest = decodeBase64Url(recovery.membership_digest_b64);
            group = decodeBase64Url(room.group_id_b64);
            exact = recovery.revision === decimalU64(info.revision) && recovery.epoch === decimalU64(info.epoch) &&
              info.memberCount === recovery.roster.length && recovery.active === existing.active &&
              room.owner_username === existing.ownerUsername && sameRoster(recovery.roster, existing.roster) &&
              equal(info.membershipDigest, digest) && equal(info.groupId, group);
          } finally {
            info.membershipDigest.fill(0); info.groupId.fill(0); digest.fill(0); group.fill(0);
          }
          if (exact) {
            existing.synchronized = room.synchronized;
            if (room.synchronized) existing.roster = cloneRoster(room.roster);
            continue;
          }
          // An established room identity or roster cannot be silently replaced by a catalog replay.
          throw new Error("Room unavailable");
        }
        this.removeRoom(room.room_id);
        let groupId: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
        let envelope: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
        let digest: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
        let handle: WasmMlsRoom | null = null;
        try {
          groupId = decodeBase64Url(room.group_id_b64);
          envelope = decodeBase64Url(recovery.state_envelope_b64);
          digest = decodeBase64Url(recovery.membership_digest_b64);
          handle = this.#session.mlsRecoverRoom(
            room.room_id, this.#username, this.#nodeContext, groupId, envelope,
            recovery.active, parseU64(recovery.epoch), parseU64(recovery.revision),
            rosterJson(recovery.roster), digest,
          );
          const info = readRoomInfo(handle);
          try {
            if (info.epoch !== parseU64(recovery.epoch) || info.revision !== parseU64(recovery.revision) ||
              info.memberCount !== recovery.roster.length || !equal(info.groupId, groupId) || !equal(info.membershipDigest, digest)) {
              throw new Error("Room unavailable");
            }
          } finally { info.groupId.fill(0); info.membershipDigest.fill(0); }
          this.#rooms.set(room.room_id, {
            handle, groupId: groupId.slice(), ownerUsername: room.owner_username, roster: cloneRoster(recovery.roster),
            active: recovery.active, synchronized: room.synchronized,
            pendingMessageId: null, pendingRevision: null, pendingRoster: null, ownJoinRequestId: null,
          });
          handle = null;
        } finally {
          handle?.free(); envelope.fill(0); digest.fill(0); groupId.fill(0);
        }
      }
      for (const roomId of [...this.#rooms.keys()]) if (!seen.has(roomId)) this.removeRoom(roomId);
      return output;
    } catch (error) {
      for (const roomId of [...this.#rooms.keys()]) this.removeRoom(roomId);
      throw error;
    }
  }

  beginJoin(frame: Extract<MlsIncomingFrame, { type: "mls_room_discovered" }>): Record<string, unknown> {
    this.assertOpen();
    if (this.#rooms.has(frame.room_id) || this.#rooms.size >= MAX_ROOMS) throw new Error("Room unavailable");
    const groupId = decodeBase64Url(frame.group_id_b64);
    if (groupId.byteLength !== 32) { groupId.fill(0); throw new Error("Room unavailable"); }
    const requestId = crypto.randomUUID();
    let handle: WasmMlsRoom | null = null;
    let keyPackage: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let state: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    try {
      handle = this.#session.mlsPendingJoin(frame.room_id, this.#username, this.#nodeContext, groupId);
      keyPackage = handle.keyPackage();
      state = handle.sealState();
      this.#rooms.set(frame.room_id, {
        handle, groupId: groupId.slice(), ownerUsername: frame.owner_username, roster: [], active: false, synchronized: false,
        pendingMessageId: null, pendingRevision: null, pendingRoster: null, ownJoinRequestId: requestId,
      });
      handle = null;
      return {
        type: "mls_join_request", protocol_version: MLS_PROTOCOL_VERSION, room_id: frame.room_id,
        request_id: requestId, stable_identity_b64: encodeBase64Url(this.#stableIdentity),
        key_package_b64: encodeBase64Url(keyPackage), state_envelope_b64: encodeBase64Url(state),
      };
    } catch (error) {
      handle?.free(); this.removeRoom(frame.room_id); throw error;
    } finally { groupId.fill(0); keyPackage.fill(0); state.fill(0); }
  }

  rememberJoin(frame: Extract<MlsIncomingFrame, { type: "mls_join_requested" }>): void {
    this.assertOpen();
    const slot = this.ownerSlot(frame.room_id);
    let stableIdentity: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let keyPackage: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    try {
      stableIdentity = decodeBase64Url(frame.stable_identity_b64);
      keyPackage = decodeBase64Url(frame.key_package_b64);
      if (stableIdentity.byteLength !== 64 || keyPackage.byteLength === 0 || keyPackage.byteLength > 64 * 1024) {
        throw new Error("Room unavailable");
      }
      if (slot.roster.some((member) => sameUsername(member.username, frame.username) ||
        stableIdentityMatches(member.stable_identity_b64, stableIdentity))) throw new Error("Room unavailable");
      const existing = this.#pendingJoins.get(frame.request_id);
      if (existing) {
        const exact = existing.roomId === frame.room_id && sameUsername(existing.username, frame.username) &&
          equal(existing.stableIdentity, stableIdentity) && equal(existing.keyPackage, keyPackage);
        if (!exact) throw new Error("Room unavailable");
        return;
      }
      if ([...this.#pendingJoins.values()].some((pending) => pending.roomId === frame.room_id &&
        (sameUsername(pending.username, frame.username) || equal(pending.stableIdentity, stableIdentity)))) {
        throw new Error("Room unavailable");
      }
      if (this.#pendingJoins.size >= MAX_PENDING_JOINS) throw new Error("Room unavailable");
      this.#pendingJoins.set(frame.request_id, {
        roomId: frame.room_id, requestId: frame.request_id, username: frame.username,
        stableIdentity, keyPackage,
      });
      stableIdentity = new Uint8Array(0); keyPackage = new Uint8Array(0);
    } finally {
      stableIdentity.fill(0); keyPackage.fill(0);
    }
  }

  pendingJoins(): PendingMlsJoinSummary[] {
    return [...this.#pendingJoins.values()].map(({ roomId, requestId, username }) => ({ roomId, requestId, username }));
  }

  /** Starts a member leave request. Owners must use the owner approval path. */
  beginLeave(roomId: string): Record<string, unknown> {
    const slot = this.activeSlot(roomId);
    const self = uniqueMember(slot.roster, this.#username);
    if (!self || !stableIdentityMatches(self.stable_identity_b64, this.#stableIdentity) ||
      sameUsername(slot.ownerUsername, this.#username) || slot.roster.length <= 1 ||
      [...this.#pendingLeaves.values()].some((leave) => leave.roomId === roomId)) {
      throw new Error("Room unavailable");
    }
    const requestId = crypto.randomUUID();
    this.#pendingLeaves.set(requestId, {
      roomId, requestId, username: this.#username, stableIdentity: this.#stableIdentity.slice(), own: true,
    });
    return { type: "mls_leave_request", protocol_version: MLS_PROTOCOL_VERSION, room_id: roomId, request_id: requestId };
  }

  rememberLeave(frame: Extract<MlsIncomingFrame, { type: "mls_leave_requested" }>): void {
    this.assertOpen();
    const slot = this.ownerSlot(frame.room_id);
    if (sameUsername(frame.username, this.#username) || sameUsername(frame.username, slot.ownerUsername)) throw new Error("Room unavailable");
    let stableIdentity: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    try {
      stableIdentity = decodeBase64Url(frame.stable_identity_b64);
      if (stableIdentity.byteLength !== 64) throw new Error("Room unavailable");
      const member = uniqueMember(slot.roster, frame.username);
      if (!member || !stableIdentityMatches(member.stable_identity_b64, stableIdentity)) throw new Error("Room unavailable");
      const existing = this.#pendingLeaves.get(frame.request_id);
      if (existing) {
        if (existing.roomId !== frame.room_id || !sameUsername(existing.username, frame.username) || !equal(existing.stableIdentity, stableIdentity)) {
          throw new Error("Room unavailable");
        }
        return;
      }
      if ([...this.#pendingLeaves.values()].some((pending) => pending.roomId === frame.room_id &&
        sameUsername(pending.username, frame.username))) throw new Error("Room unavailable");
      if (this.#pendingLeaves.size >= MAX_PENDING_LEAVES) throw new Error("Room unavailable");
      this.#pendingLeaves.set(frame.request_id, {
        roomId: frame.room_id, requestId: frame.request_id, username: frame.username, stableIdentity, own: false,
      });
      stableIdentity = new Uint8Array(0);
    } finally {
      stableIdentity.fill(0);
    }
  }

  pendingLeaves(): PendingMlsLeaveSummary[] {
    return [...this.#pendingLeaves.values()].map(({ roomId, requestId, username }) => ({ roomId, requestId, username }));
  }

  acceptLeave(requestId: string, messageId: string = crypto.randomUUID()): PreparedMlsMembership {
    const request = this.#pendingLeaves.get(requestId);
    if (!request || request.own) throw new Error("Room unavailable");
    const slot = this.ownerSlot(request.roomId);
    this.assertPendingLeave(slot, request);
    const wrapper = slot.handle.removeMember(request.username, request.stableIdentity, messageId);
    try {
      const prepared = membershipFromWrapper(request.roomId, requestId, wrapper);
      const nextRoster = nativeRosterJson(wrapper.rosterJson);
      if (!validActiveRoster(nextRoster, slot.ownerUsername, this.#username, this.#stableIdentity)) throw new Error("Room unavailable");
      prepared.requestType = "leave";
      this.stage(slot, messageId, prepared.revision, nextRoster);
      return prepared;
    } catch (error) { this.removeRoom(request.roomId); throw error; }
    finally { wrapper.free(); }
  }

  rejectLeave(requestId: string): Record<string, unknown> {
    const request = this.#pendingLeaves.get(requestId);
    if (!request || request.own) throw new Error("Room unavailable");
    this.assertPendingLeave(this.ownerSlot(request.roomId), request);
    return { type: "mls_leave_reject", protocol_version: MLS_PROTOCOL_VERSION, room_id: request.roomId, request_id: request.requestId };
  }

  /** Clears a member's pending request after the owner rejects it. */
  forgetLeave(roomId: string, requestId: string): void {
    const request = this.#pendingLeaves.get(requestId);
    if (!request || request.roomId !== roomId) throw new Error("Room unavailable");
    if (request.own) {
      const slot = this.activeSlot(roomId); const self = uniqueMember(slot.roster, this.#username);
      if (!sameUsername(request.username, this.#username) || !self ||
        !equal(request.stableIdentity, this.#stableIdentity) || !stableIdentityMatches(self.stable_identity_b64, request.stableIdentity)) {
        throw new Error("Room unavailable");
      }
    } else this.assertPendingLeave(this.ownerSlot(roomId), request);
    this.takeLeave(requestId);
  }

  acceptJoin(requestId: string, messageId: string = crypto.randomUUID()): PreparedMlsMembership {
    const request = this.#pendingJoins.get(requestId); if (!request) throw new Error("Room unavailable");
    const slot = this.ownerSlot(request.roomId);
    this.assertPendingJoin(slot, request);
    const wrapper = slot.handle.addMember(request.keyPackage, request.username, request.stableIdentity, messageId);
    try {
      const prepared = membershipFromWrapper(request.roomId, requestId, wrapper);
      const nextRoster = nativeRosterJson(wrapper.rosterJson);
      if (!validActiveRoster(nextRoster, slot.ownerUsername, this.#username, this.#stableIdentity)) throw new Error("Room unavailable");
      this.stage(slot, messageId, prepared.revision, nextRoster);
      return prepared;
    } catch (error) { this.removeRoom(request.roomId); throw error; }
    finally { wrapper.free(); }
  }

  rejectJoin(requestId: string): Record<string, unknown> {
    const request = this.#pendingJoins.get(requestId);
    if (!request) throw new Error("Room unavailable");
    this.assertPendingJoin(this.ownerSlot(request.roomId), request);
    return { type: "mls_join_reject", protocol_version: MLS_PROTOCOL_VERSION, room_id: request.roomId, request_id: request.requestId };
  }

  /** Clears an incoming join only after the rejection frame was sent. */
  forgetJoin(roomId: string, requestId: string): void {
    const request = this.#pendingJoins.get(requestId);
    if (!request || request.roomId !== roomId) throw new Error("Room unavailable");
    this.assertPendingJoin(this.ownerSlot(roomId), request);
    this.takeJoin(requestId);
  }

  /** Applies only the exact rejection for this client's still-pending join. */
  rejectOwnJoin(roomId: string, requestId: string): void {
    const slot = this.#rooms.get(roomId);
    if (!slot || slot.active || slot.ownJoinRequestId !== requestId) throw new Error("Room unavailable");
    this.removeRoom(roomId);
  }

  prepareApplication(roomId: string, messageId: string, sender: string, plaintext: Uint8Array): PreparedMlsApplication {
    const slot = this.activeSlot(roomId);
    const aad = applicationAad(roomId, messageId, sender);
    let wrapper: ReturnType<WasmMlsRoom["encryptApplication"]> | undefined;
    let groupId: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let digest: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let ciphertext: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let authenticatedData: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let stateEnvelope: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    try {
      wrapper = slot.handle.encryptApplication(messageId, plaintext, aad);
      const revision = wrapper.revision;
      groupId = wrapper.groupId; digest = wrapper.membershipDigest; ciphertext = wrapper.ciphertext;
      authenticatedData = wrapper.authenticatedData; stateEnvelope = wrapper.stateEnvelope;
      const result = {
        roomId, messageId, revision,
        frame: {
          type: "mls_application", protocol_version: MLS_PROTOCOL_VERSION, room_id: roomId, message_id: messageId,
          group_id_b64: encodeBase64Url(groupId), epoch: decimalU64(wrapper.epoch), revision: decimalU64(revision),
          membership_digest_b64: encodeBase64Url(digest), ciphertext_b64: encodeBase64Url(ciphertext),
          authenticated_data_b64: encodeBase64Url(authenticatedData), state_envelope_b64: encodeBase64Url(stateEnvelope),
        },
      };
      this.stage(slot, messageId, revision);
      return result;
    } catch (error) {
      this.removeRoom(roomId);
      throw error;
    } finally {
      wrapper?.free(); aad.fill(0); groupId.fill(0); digest.fill(0); ciphertext.fill(0);
      authenticatedData.fill(0); stateEnvelope.fill(0);
    }
  }

  finishTransaction(prepared: PreparedMlsApplication, outcome: MlsTransactionOutcome): void {
    const slot = this.#rooms.get(prepared.roomId);
    if (!slot) throw new Error("Room unavailable");
    if (slot.pendingMessageId !== prepared.messageId || slot.pendingRevision !== prepared.revision) {
      this.removeRoom(prepared.roomId); throw new Error("Room unavailable");
    }
    try {
      if (outcome === "ACCEPTED") {
        slot.handle.commitOutbound(prepared.messageId, prepared.revision);
        if (slot.pendingRoster) slot.roster = slot.pendingRoster;
      }
      else if (outcome === "REJECTED" || outcome === "NOT_SENT") slot.handle.rollbackOutbound(prepared.messageId, prepared.revision);
      else { this.removeRoom(prepared.roomId); return; }
      const requestId = (prepared as Partial<PreparedMlsMembership>).requestId;
      if (requestId && outcome === "ACCEPTED") {
        if ((prepared as Partial<PreparedMlsMembership>).requestType === "leave") this.takeLeave(requestId);
        else this.takeJoin(requestId);
      }
    } catch (error) { this.removeRoom(prepared.roomId); throw error; }
    slot.pendingMessageId = null; slot.pendingRevision = null; slot.pendingRoster = null;
  }

  receiveApplication(frame: Extract<MlsIncomingFrame, { type: "mls_application" }>): DecryptedMlsApplication {
    const slot = this.inboundSlot(frame.room_id);
    let aad: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let expectedAad: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let ciphertext: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let wrapper: ReturnType<WasmMlsRoom["decryptApplication"]> | undefined;
    let digest: Uint8Array<ArrayBufferLike> = new Uint8Array(0); let expectedDigest: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let state: Uint8Array<ArrayBufferLike> = new Uint8Array(0); let plain: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    try {
      aad = decodeBase64Url(frame.authenticated_data_b64);
      expectedAad = applicationAad(frame.room_id, frame.message_id, frame.sender_username);
      if (!equal(aad, expectedAad)) throw new Error("Payload unavailable");
      ciphertext = decodeBase64Url(frame.ciphertext_b64);
      wrapper = slot.handle.decryptApplication(ciphertext, parseU64(frame.epoch), frame.message_id, aad);
      digest = wrapper.membershipDigest; expectedDigest = decodeBase64Url(frame.membership_digest_b64);
      state = wrapper.stateEnvelope; plain = wrapper.plaintext;
      if (wrapper.revision !== parseU64(frame.revision) || !equal(digest, expectedDigest)) throw new Error("Payload unavailable");
      const result = { plaintext: plain.slice(), snapshot: preparedSnapshot(frame.room_id, frame.message_id, wrapper.epoch, wrapper.revision, digest, state, true) };
      this.stage(slot, frame.message_id, wrapper.revision);
      slot.synchronized = false;
      return result;
    } catch (error) { this.removeRoom(frame.room_id); throw error; }
    finally { wrapper?.free(); aad.fill(0); expectedAad.fill(0); ciphertext.fill(0); digest.fill(0); expectedDigest.fill(0); state.fill(0); plain.fill(0); }
  }

  receiveMembership(frame: Extract<MlsIncomingFrame, { type: "mls_membership" }>): PreparedMlsSnapshot {
    const slot = this.#rooms.get(frame.room_id); if (!slot) throw new Error("Room unavailable");
    let roster: string;
    let digest: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let aad: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let welcome: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let control: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let frameGroup: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let priorDigest: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let currentGroup: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let currentDigest: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    let info: WasmMlsProcessedControl | WasmMlsRoomInfo | undefined;
    let infoDigest: Uint8Array<ArrayBufferLike> = new Uint8Array(0); let infoState: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    try {
      roster = rosterJson(frame.roster);
      digest = decodeBase64Url(frame.membership_digest_b64);
      aad = decodeBase64Url(frame.authenticated_data_b64);
      welcome = decodeBase64Url(frame.welcome_b64);
      control = decodeBase64Url(frame.control_b64);
      const joining = welcome.byteLength > 0 && !slot.active;
      if ((slot.active && welcome.byteLength !== 0) || (!slot.active && !joining) ||
        !validActiveRoster(frame.roster, slot.ownerUsername, this.#username, this.#stableIdentity)) {
        throw new Error("Room unavailable");
      }
      frameGroup = decodeBase64Url(frame.group_id_b64);
      if (!equal(slot.groupId, frameGroup)) throw new Error("Room unavailable");
      if (!joining) {
        const current = readRoomInfo(slot.handle);
        currentGroup = current.groupId; currentDigest = current.membershipDigest;
        priorDigest = decodeBase64Url(frame.from_membership_digest_b64);
        const exactPrior = current.epoch === parseU64(frame.from_epoch) && current.revision + 1n === parseU64(frame.revision) &&
          equal(currentGroup, slot.groupId) && equal(currentDigest, priorDigest);
        if (!exactPrior) throw new Error("Room unavailable");
      }
      info = joining
        ? slot.handle.joinWelcome(welcome, roster, digest)
        : slot.handle.processControl(control, parseU64(frame.from_epoch), parseU64(frame.to_epoch), roster, digest, frame.message_id, aad);
      infoDigest = info.membershipDigest;
      infoState = joining ? slot.handle.sealState() : (info as WasmMlsProcessedControl).stateEnvelope;
      if (info.revision !== parseU64(frame.revision) || !equal(infoDigest, digest)) throw new Error("Room unavailable");
      const result = preparedSnapshot(frame.room_id, frame.message_id, info.epoch, info.revision, infoDigest, infoState, !joining);
      result.membershipPending = true;
      this.stage(slot, frame.message_id, info.revision, cloneRoster(frame.roster));
      slot.synchronized = false;
      return result;
    } catch (error) { this.removeRoom(frame.room_id); throw error; }
    finally {
      info?.free(); digest.fill(0); aad.fill(0); welcome.fill(0); control.fill(0); frameGroup.fill(0);
      priorDigest.fill(0); currentGroup.fill(0); currentDigest.fill(0); infoDigest.fill(0); infoState.fill(0);
    }
  }

  finishSnapshot(prepared: PreparedMlsSnapshot, outcome: MlsTransactionOutcome): void {
    const slot = this.#rooms.get(prepared.roomId); if (!slot) throw new Error("Room unavailable");
    if ((prepared.nativePending || prepared.membershipPending) &&
      (slot.pendingMessageId !== prepared.messageId || slot.pendingRevision !== prepared.revision ||
        (prepared.membershipPending && !slot.pendingRoster))) {
      this.removeRoom(prepared.roomId); throw new Error("Room unavailable");
    }
    try {
      if (prepared.nativePending && outcome === "ACCEPTED") slot.handle.commitOutbound(prepared.messageId, prepared.revision);
      else if (prepared.nativePending && (outcome === "REJECTED" || outcome === "NOT_SENT")) slot.handle.rollbackOutbound(prepared.messageId, prepared.revision);
      else if (outcome !== "ACCEPTED") { this.removeRoom(prepared.roomId); return; }
      if (outcome === "ACCEPTED" && prepared.membershipPending && slot.pendingRoster) slot.roster = slot.pendingRoster;
      if (outcome === "ACCEPTED") { slot.active = true; slot.ownJoinRequestId = null; }
      slot.pendingMessageId = null; slot.pendingRevision = null; slot.pendingRoster = null;
    } catch (error) { this.removeRoom(prepared.roomId); throw error; }
  }

  removeRoom(roomId: string): void {
    const slot = this.#rooms.get(roomId); if (!slot) return;
    this.#rooms.delete(roomId); slot.groupId.fill(0); slot.roster = []; slot.pendingRoster = null; slot.ownJoinRequestId = null;
    for (const [requestId, join] of this.#pendingJoins) {
      if (join.roomId !== roomId) continue;
      this.#pendingJoins.delete(requestId); join.stableIdentity.fill(0); join.keyPackage.fill(0);
    }
    for (const [requestId, leave] of this.#pendingLeaves) {
      if (leave.roomId !== roomId) continue;
      this.#pendingLeaves.delete(requestId); leave.stableIdentity.fill(0);
    }
    try { slot.handle.free(); } catch { /* detached from manager */ }
  }

  close(): void {
    if (this.#closed) return; this.#closed = true;
    for (const roomId of [...this.#rooms.keys()]) this.removeRoom(roomId);
    for (const join of this.#pendingJoins.values()) { join.stableIdentity.fill(0); join.keyPackage.fill(0); }
    this.#pendingJoins.clear(); this.#nodeContext.fill(0); this.#stableIdentity.fill(0);
    for (const leave of this.#pendingLeaves.values()) leave.stableIdentity.fill(0);
    this.#pendingLeaves.clear();
  }

  private assertOpen(): void { if (this.#closed) throw new Error("Room unavailable"); }
  private activeSlot(roomId: string): RoomSlot { this.assertOpen(); const slot = this.#rooms.get(roomId); if (!slot?.active || !slot.synchronized || slot.pendingMessageId) throw new Error("Room unavailable"); return slot; }
  private inboundSlot(roomId: string): RoomSlot { this.assertOpen(); const slot = this.#rooms.get(roomId); if (!slot?.active || slot.pendingMessageId) throw new Error("Room unavailable"); return slot; }
  private ownerSlot(roomId: string): RoomSlot {
    const slot = this.activeSlot(roomId);
    const owner = uniqueMember(slot.roster, slot.ownerUsername);
    const self = uniqueMember(slot.roster, this.#username);
    if (!sameUsername(slot.ownerUsername, this.#username) || !owner || !self ||
      !stableIdentityMatches(self.stable_identity_b64, this.#stableIdentity)) throw new Error("Room unavailable");
    return slot;
  }
  private stage(slot: RoomSlot, messageId: string, revision: bigint, roster: MlsRosterMemberWire[] | null = null): void {
    if (slot.pendingMessageId) throw new Error("Room unavailable");
    slot.pendingMessageId = messageId; slot.pendingRevision = revision; slot.pendingRoster = roster;
  }
  private assertPendingJoin(slot: RoomSlot, request: PendingMlsJoin): void {
    if (slot.roster.some((member) => sameUsername(member.username, request.username) ||
      stableIdentityMatches(member.stable_identity_b64, request.stableIdentity))) throw new Error("Room unavailable");
  }
  private assertPendingLeave(slot: RoomSlot, request: PendingMlsLeave): void {
    if (sameUsername(request.username, slot.ownerUsername) || sameUsername(request.username, this.#username)) throw new Error("Room unavailable");
    const member = uniqueMember(slot.roster, request.username);
    if (!member || !stableIdentityMatches(member.stable_identity_b64, request.stableIdentity)) throw new Error("Room unavailable");
  }
  private takeJoin(requestId: string): PendingMlsJoin { const request = this.#pendingJoins.get(requestId); if (!request) throw new Error("Room unavailable"); this.#pendingJoins.delete(requestId); request.stableIdentity.fill(0); request.keyPackage.fill(0); return request; }
  private takeLeave(requestId: string): PendingMlsLeaveSummary { const request = this.#pendingLeaves.get(requestId); if (!request) throw new Error("Room unavailable"); this.#pendingLeaves.delete(requestId); request.stableIdentity.fill(0); return { roomId: request.roomId, requestId: request.requestId, username: request.username }; }
}

function membershipFromWrapper(roomId: string, requestId: string | undefined, wrapper: ReturnType<WasmMlsRoom["addMember"]>): PreparedMlsMembership {
  let group: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  let fromDigest: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  let digest: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  let control: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  let welcome: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  let aad: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  let state: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  try {
    group = wrapper.groupId; fromDigest = wrapper.fromMembershipDigest; digest = wrapper.membershipDigest;
    control = wrapper.commit; welcome = wrapper.welcome; aad = wrapper.authenticatedData; state = wrapper.stateEnvelope;
    return { roomId, messageId: wrapper.messageId, revision: wrapper.revision, requestId, frame: {
      type: "mls_membership_commit", protocol_version: MLS_PROTOCOL_VERSION, room_id: roomId, message_id: wrapper.messageId,
      request_id: requestId, from_epoch: decimalU64(wrapper.fromEpoch), to_epoch: decimalU64(wrapper.toEpoch), revision: decimalU64(wrapper.revision),
      group_id_b64: encodeBase64Url(group), from_membership_digest_b64: encodeBase64Url(fromDigest),
      membership_digest_b64: encodeBase64Url(digest), roster: nativeRosterJson(wrapper.rosterJson),
      control_b64: encodeBase64Url(control), welcome_b64: encodeBase64Url(welcome),
      authenticated_data_b64: encodeBase64Url(aad), state_envelope_b64: encodeBase64Url(state),
    } };
  } finally {
    group.fill(0); fromDigest.fill(0); digest.fill(0); control.fill(0); welcome.fill(0); aad.fill(0); state.fill(0);
  }
}

function preparedSnapshot(roomId: string, messageId: string, epoch: bigint, revision: bigint, digest: Uint8Array, state: Uint8Array, nativePending: boolean): PreparedMlsSnapshot {
  return { roomId, messageId, revision, nativePending, frame: { type: "mls_state_snapshot", protocol_version: MLS_PROTOCOL_VERSION, room_id: roomId, message_id: messageId, epoch: decimalU64(epoch), revision: decimalU64(revision), membership_digest_b64: encodeBase64Url(digest), state_envelope_b64: encodeBase64Url(state) } };
}

function applicationAad(roomId: string, messageId: string, sender: string): Uint8Array {
  if (!ID.test(roomId) || !ID.test(messageId) || !USERNAME.test(sender)) throw new Error("Payload unavailable");
  const fields = [ENCODER.encode("ABYSSAL-MLS-V10-APPLICATION"), ENCODER.encode(roomId), ENCODER.encode(messageId), ENCODER.encode(sender)];
  const length = fields.reduce((total, field) => total + 4 + field.byteLength, 0); const out = new Uint8Array(length); const view = new DataView(out.buffer); let offset = 0;
  for (const field of fields) { view.setUint32(offset, field.byteLength, false); offset += 4; out.set(field, offset); offset += field.byteLength; }
  fields.forEach((field) => field.fill(0)); return out;
}

function readRoomInfo(handle: WasmMlsRoom) {
  const info = handle.roomInfo();
  let groupId: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  let membershipDigest: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  try {
    groupId = info.groupId; membershipDigest = info.membershipDigest;
    return { epoch: info.epoch, revision: info.revision, memberCount: info.memberCount, groupId, membershipDigest };
  } catch (error) {
    groupId.fill(0); membershipDigest.fill(0); throw error;
  } finally { info.free(); }
}
function rosterJson(roster: MlsRosterMemberWire[]): string {
  const identities: Uint8Array[] = [];
  try {
    roster.forEach((member) => identities.push(decodeBase64Url(member.stable_identity_b64)));
    return JSON.stringify(roster.map((member, index) => ({ username: member.username, stable_identity: [...identities[index]] })));
  }
  finally { identities.forEach((identity) => identity.fill(0)); }
}
function cloneRoster(roster: MlsRosterMemberWire[]): MlsRosterMemberWire[] { return roster.map((member) => ({ ...member })); }
function sameUsername(left: string, right: string): boolean { return left.toLowerCase() === right.toLowerCase(); }
function uniqueMember(roster: MlsRosterMemberWire[], username: string): MlsRosterMemberWire | null {
  const matches = roster.filter((member) => sameUsername(member.username, username));
  return matches.length === 1 ? matches[0] : null;
}
function sameRoster(left: MlsRosterMemberWire[], right: MlsRosterMemberWire[]): boolean {
  if (left.length !== right.length) return false;
  return left.every((member) => {
    const match = uniqueMember(right, member.username);
    return match !== null && match.stable_identity_b64 === member.stable_identity_b64;
  });
}
function validCatalogRoom(room: MlsRoomWire, username: string, stableIdentity: Uint8Array): boolean {
  const snapshot = room.recovery_snapshot;
  if (!snapshot || snapshot.active !== room.active || room.synchronized && !room.active) return false;
  const pending = !room.active && room.roster.length === 0;
  if (pending) {
    if (room.synchronized || room.epoch !== "0" || room.revision !== "0" || room.membership_digest_b64 !== "" ||
      snapshot.active || snapshot.epoch !== "0" || snapshot.revision !== "0" ||
      snapshot.membership_digest_b64 !== "" || snapshot.roster.length !== 0) return false;
  } else if (!validActiveRoster(room.roster, room.owner_username, username, stableIdentity) ||
    uniqueMember(room.roster, room.owner_username)?.username !== room.owner_username) return false;
  if (snapshot.active && !validActiveRoster(snapshot.roster, room.owner_username, username, stableIdentity)) return false;
  if (!snapshot.active && (snapshot.epoch !== "0" || snapshot.revision !== "0" ||
    snapshot.membership_digest_b64 !== "" || snapshot.roster.length !== 0)) return false;
  return !room.synchronized || snapshot.epoch === room.epoch && snapshot.revision === room.revision &&
    snapshot.membership_digest_b64 === room.membership_digest_b64 && sameRoster(snapshot.roster, room.roster);
}
function validActiveRoster(roster: MlsRosterMemberWire[], owner: string, username: string, stableIdentity: Uint8Array): boolean {
  if (!isUniqueRoster(roster)) return false;
  const ownerMember = uniqueMember(roster, owner);
  const self = uniqueMember(roster, username);
  return ownerMember !== null && self !== null && stableIdentityMatches(self.stable_identity_b64, stableIdentity);
}
function stableIdentityMatches(encoded: string, expected: Uint8Array): boolean {
  let decoded: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  try { decoded = decodeBase64Url(encoded); return equal(decoded, expected); }
  finally { decoded.fill(0); }
}
function nativeRosterJson(value: string): MlsRosterMemberWire[] {
  let parsed: unknown;
  try { parsed = JSON.parse(value) as unknown; } catch { throw new Error("Room unavailable"); }
  if (!Array.isArray(parsed) || parsed.length === 0 || parsed.length > 117) throw new Error("Room unavailable");
  const roster = parsed.map((member) => {
    if (!member || typeof member !== "object" || Array.isArray(member)) throw new Error("Room unavailable");
    const candidate = member as Record<string, unknown>;
    if (typeof candidate.username !== "string" || !USERNAME.test(candidate.username) || !Array.isArray(candidate.stable_identity) || candidate.stable_identity.length !== 64 ||
      candidate.stable_identity.some((byte) => typeof byte !== "number" || !Number.isInteger(byte) || byte < 0 || byte > 255)) throw new Error("Room unavailable");
    const stableIdentity = Uint8Array.from(candidate.stable_identity as number[]);
    try { return { username: candidate.username, stable_identity_b64: encodeBase64Url(stableIdentity) }; }
    finally { stableIdentity.fill(0); }
  });
  assertUniqueRoster(roster);
  return roster;
}
function assertUniqueRoster(roster: MlsRosterMemberWire[]): void {
  if (!isUniqueRoster(roster)) throw new Error("Room unavailable");
}
function isUniqueRoster(roster: MlsRosterMemberWire[]): boolean {
  const names = new Set<string>(); const identities = new Set<string>();
  for (const member of roster) {
    const name = member.username.toLowerCase();
    if (names.has(name) || identities.has(member.stable_identity_b64)) return false;
    names.add(name); identities.add(member.stable_identity_b64);
  }
  return true;
}
function parseU64(value: string): bigint { const parsed = parseCanonicalU64(value); if (parsed === null) throw new Error("Room unavailable"); return parsed; }
function equal(left: Uint8Array, right: Uint8Array): boolean { if (left.byteLength !== right.byteLength) return false; let diff = 0; for (let i = 0; i < left.byteLength; i += 1) diff |= left[i] ^ right[i]; return diff === 0; }

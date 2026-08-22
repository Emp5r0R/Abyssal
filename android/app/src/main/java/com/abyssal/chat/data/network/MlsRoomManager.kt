package com.abyssal.chat.data.network

import com.abyssal.chat.domain.model.ChatSession
import com.abyssal.chat.domain.model.DecryptedMlsApplication
import com.abyssal.chat.domain.model.MLS_PROTOCOL_VERSION
import com.abyssal.chat.domain.model.MlsIncomingFrame
import com.abyssal.chat.domain.model.MlsRoomWire
import com.abyssal.chat.domain.model.MlsRosterMemberWire
import com.abyssal.chat.domain.model.PendingMlsJoinSummary
import com.abyssal.chat.domain.model.PendingMlsLeaveSummary
import com.abyssal.chat.domain.model.MlsTransactionKind
import com.abyssal.chat.domain.model.PreparedMlsSnapshot
import com.abyssal.chat.domain.model.PreparedMlsTransaction
import com.abyssal.chat.domain.repository.OutboundSendResult
import java.security.SecureRandom
import java.util.UUID
import java.util.Locale
import org.json.JSONArray
import org.json.JSONObject
import uniffi.abyssal_core.MlsRoom
import uniffi.abyssal_core.MlsRosterMember

internal interface MlsSessionBridge {
    fun createMlsRoom(roomId: String, username: String, nodeContext: ByteArray, groupId: ByteArray): MlsRoom
    fun pendingMlsJoin(roomId: String, username: String, nodeContext: ByteArray, groupId: ByteArray): MlsRoom
    fun recoverMlsRoom(
        roomId: String,
        username: String,
        nodeContext: ByteArray,
        groupId: ByteArray,
        envelope: ByteArray,
        expectedActive: Boolean,
        expectedEpoch: ULong,
        expectedRevision: ULong,
        expectedMembers: List<MlsRosterMember>,
        expectedDigest: ByteArray
    ): MlsRoom
}

internal class MlsRoomManager(
    private val session: MlsSessionBridge,
    private val username: String,
    nodeId: String,
    identityPublicKey: ByteArray,
    private val random: SecureRandom = SecureRandom()
) : AutoCloseable {
    private data class RoomSlot(
        val handle: MlsRoom,
        val groupId: ByteArray,
        val ownerUsername: String,
        var roster: List<MlsRosterMemberWire>,
        var active: Boolean,
        var synchronized: Boolean,
        var pendingJoinRequestId: String? = null,
        var pendingMessageId: String? = null,
        var pendingRevision: ULong? = null,
        var pendingRoster: List<MlsRosterMemberWire>? = null
    )
    private data class PendingJoin(
        val roomId: String,
        val requestId: String,
        val username: String,
        val stableIdentity: ByteArray,
        val keyPackage: ByteArray
    )
    private data class PendingLeave(val roomId: String, val requestId: String, val username: String, val stableIdentity: ByteArray)

    private val nodeContext = "ABYSSAL-MLS-V10-NODE:$nodeId".encodeToByteArray()
    private val stableIdentity: ByteArray
    private val rooms = LinkedHashMap<String, RoomSlot>()
    private val joins = LinkedHashMap<String, PendingJoin>()
    private val leaves = LinkedHashMap<String, PendingLeave>()
    private var closed = false

    init {
        require(USERNAME.matches(username) && NODE_ID.matches(nodeId) && identityPublicKey.size == 608)
        stableIdentity = identityPublicKey.copyOfRange(0, 64)
    }

    @Synchronized
    fun createRoom(room: ChatSession): JSONObject {
        checkOpen()
        require(ID.matches(room.id) && !rooms.containsKey(room.id) && rooms.size < MAX_ROOMS)
        require(room.ownerUsername == null || sameUsername(room.ownerUsername, username))
        val group = ByteArray(32).also(random::nextBytes)
        var handle: MlsRoom? = null
        var infoGroup = ByteArray(0)
        var digest = ByteArray(0)
        var state = ByteArray(0)
        return try {
            handle = session.createMlsRoom(room.id, username, nodeContext, group)
            val info = handle.roomInfo()
            infoGroup = info.groupId
            digest = info.membershipDigest
            require(info.epoch == 0uL && info.revision == 0uL && info.memberCount == 1u &&
                infoGroup.contentEquals(group) && digest.size == 32)
            state = handle.sealState()
            val roster = listOf(MlsRosterMemberWire(username, MlsWireCodec.encode(stableIdentity)))
            rooms[room.id] = RoomSlot(handle, group.clone(), username, roster, true, true)
            handle = null
            JSONObject().put("type", "mls_create_room").put("protocol_version", MLS_PROTOCOL_VERSION)
                .put("room_id", room.id).put("group_id_b64", MlsWireCodec.encode(group))
                .put("epoch", "0").put("revision", "0")
                .put("membership_digest_b64", MlsWireCodec.encode(digest))
                .put("stable_identity_b64", MlsWireCodec.encode(stableIdentity))
                .put("state_envelope_b64", MlsWireCodec.encode(state)).put("policy", MlsWireCodec.policy(room))
        } catch (error: Throwable) {
            handle?.close(); removeRoom(room.id); throw error
        } finally { group.fill(0); infoGroup.fill(0); digest.fill(0); state.fill(0) }
    }

    @Synchronized
    fun recoverCatalog(catalog: List<MlsRoomWire>): List<ChatSession> {
        checkOpen(); require(catalog.size <= MAX_ROOMS && catalog.map { it.roomId }.toSet().size == catalog.size)
        val seen = catalog.mapTo(HashSet()) { it.roomId }
        val output = ArrayList<ChatSession>(catalog.size)
        try {
            catalog.forEach { wire ->
                validateRoomWire(wire)
                val recovery = requireNotNull(wire.recoverySnapshot)
                if (wire.roster.isNotEmpty()) validateRoster(wire.roster, wire.ownerUsername, requireSelf = true)
                if (recovery.active) validateRoster(recovery.roster, wire.ownerUsername, requireSelf = true)
                if (wire.synchronized) {
                    require(recovery.epoch == wire.epoch && recovery.revision == wire.revision &&
                        recovery.membershipDigestB64 == wire.membershipDigestB64 && sameRoster(recovery.roster, wire.roster))
                }
                if (wire.active) output += MlsWireCodec.roomSession(wire)
                val existing = rooms[wire.roomId]
                if (existing != null && exactExisting(existing, wire)) {
                    existing.active = recovery.active
                    existing.synchronized = wire.synchronized
                    if (wire.synchronized) {
                        wipeRoster(existing.roster)
                        existing.roster = wire.roster.map { it.copy() }
                    }
                    return@forEach
                }
                removeRoom(wire.roomId)
                var group = ByteArray(0); var envelope = ByteArray(0); var digest = ByteArray(0); var handle: MlsRoom? = null
                try {
                    group = MlsWireCodec.decode(wire.groupIdB64); envelope = MlsWireCodec.decode(recovery.stateEnvelopeB64)
                    digest = MlsWireCodec.decode(recovery.membershipDigestB64)
                    handle = withNativeRoster(recovery.roster) { native ->
                        session.recoverMlsRoom(wire.roomId, username, nodeContext, group, envelope, recovery.active,
                            recovery.epoch, recovery.revision, native, digest)
                    }
                    val info = handle.roomInfo()
                    try {
                        require(info.epoch == recovery.epoch && info.revision == recovery.revision &&
                            info.groupId.contentEquals(group) && info.membershipDigest.contentEquals(digest))
                    } finally { info.groupId.fill(0); info.membershipDigest.fill(0) }
                    rooms[wire.roomId] = RoomSlot(handle, group.clone(), wire.ownerUsername, recovery.roster.map { it.copy() }, recovery.active, wire.synchronized)
                    handle = null
                } finally { handle?.close(); group.fill(0); envelope.fill(0); digest.fill(0) }
            }
            rooms.keys.toList().filterNot(seen::contains).forEach(::removeRoom)
            return output
        } catch (error: Throwable) {
            // Recovery is a catalog transaction. Never leave a partially trusted catalog installed.
            rooms.keys.toList().forEach(::removeRoom)
            throw error
        }
    }

    @Synchronized
    fun beginJoin(frame: MlsIncomingFrame.RoomDiscovered): JSONObject {
        checkOpen(); require(!rooms.containsKey(frame.roomId) && rooms.size < MAX_ROOMS)
        var group = ByteArray(0); var key = ByteArray(0); var state = ByteArray(0); var handle: MlsRoom? = null
        return try {
            group = MlsWireCodec.decode(frame.groupIdB64)
            handle = session.pendingMlsJoin(frame.roomId, username, nodeContext, group)
            key = handle.keyPackage(); state = handle.sealState()
            val requestId = UUID.randomUUID().toString()
            rooms[frame.roomId] = RoomSlot(handle, group.clone(), frame.ownerUsername, emptyList(), false, false, requestId)
            handle = null
            JSONObject().put("type", "mls_join_request").put("protocol_version", MLS_PROTOCOL_VERSION)
                .put("room_id", frame.roomId).put("request_id", requestId)
                .put("stable_identity_b64", MlsWireCodec.encode(stableIdentity))
                .put("key_package_b64", MlsWireCodec.encode(key)).put("state_envelope_b64", MlsWireCodec.encode(state))
        } catch (error: Throwable) { handle?.close(); removeRoom(frame.roomId); throw error }
        finally { group.fill(0); key.fill(0); state.fill(0) }
    }

    @Synchronized
    fun rememberJoin(frame: MlsIncomingFrame.JoinRequested) {
        checkOpen()
        val slot = rooms[frame.roomId] ?: error("Room unavailable")
        require(slot.active && slot.synchronized && sameUsername(slot.ownerUsername, username))
        require(!leaves.containsKey(frame.requestId))
        var stable = MlsWireCodec.decode(frame.stableIdentityB64)
        var key = MlsWireCodec.decode(frame.keyPackageB64)
        try {
            val old = joins[frame.requestId]
            if (old != null) {
                require(old.roomId == frame.roomId && sameUsername(old.username, frame.username) && old.stableIdentity.contentEquals(stable) && old.keyPackage.contentEquals(key))
                return
            }
            require(!sameUsername(frame.username, username) && slot.roster.none { sameUsername(it.username, frame.username) })
            require(joins.size < MAX_PENDING_JOINS)
            joins[frame.requestId] = PendingJoin(frame.roomId, frame.requestId, frame.username, stable, key)
            stable = ByteArray(0); key = ByteArray(0)
        } finally { stable.fill(0); key.fill(0) }
    }

    @Synchronized
    fun pendingJoins(): List<PendingMlsJoinSummary> = joins.values.map { PendingMlsJoinSummary(it.roomId, it.requestId, it.username) }

    @Synchronized
    fun rememberLeave(frame: MlsIncomingFrame.LeaveRequested) {
        checkOpen()
        val slot = rooms[frame.roomId] ?: error("Room unavailable")
        require(slot.active && slot.synchronized && sameUsername(slot.ownerUsername, username) && !sameUsername(frame.username, username))
        require(!joins.containsKey(frame.requestId))
        var stable = MlsWireCodec.decode(frame.stableIdentityB64)
        try {
            val member = slot.roster.firstOrNull { sameUsername(it.username, frame.username) }
            require(member != null && stableIdentityMatches(member, stable))
            val old = leaves[frame.requestId]
            if (old != null) {
                require(old.roomId == frame.roomId && sameUsername(old.username, frame.username) && old.stableIdentity.contentEquals(stable)); return
            }
            require(leaves.size < MAX_PENDING_JOINS)
            leaves[frame.requestId] = PendingLeave(frame.roomId, frame.requestId, frame.username, stable)
            stable = ByteArray(0)
        } finally { stable.fill(0) }
    }

    @Synchronized fun pendingLeaves(): List<PendingMlsLeaveSummary> = leaves.values.map { PendingMlsLeaveSummary(it.roomId, it.requestId, it.username) }

    @Synchronized
    fun beginLeave(roomId: String): JSONObject {
        val slot = activeSlot(roomId)
        require(!sameUsername(slot.ownerUsername, username) && slot.roster.size > 1 && slot.roster.any { sameUsername(it.username, username) && stableIdentityMatches(it) })
        require(leaves.size < MAX_PENDING_JOINS)
        require(leaves.values.none { it.roomId == roomId && sameUsername(it.username, username) })
        val requestId = UUID.randomUUID().toString()
        leaves[requestId] = PendingLeave(roomId, requestId, username, stableIdentity.clone())
        return JSONObject().put("type", "mls_leave_request").put("protocol_version", MLS_PROTOCOL_VERSION)
            .put("room_id", roomId).put("request_id", requestId)
    }

    @Synchronized
    fun joinRejected(roomId: String, requestId: String): Boolean {
        val slot = rooms[roomId] ?: return false
        if (slot.pendingJoinRequestId != requestId) return false
        removeRoom(roomId)
        return true
    }

    @Synchronized
    fun leavePending(roomId: String, requestId: String): Boolean =
        leaves[requestId]?.let { it.roomId == roomId && sameUsername(it.username, username) } == true

    @Synchronized
    fun forgetJoin(requestId: String) { takeJoin(requestId) }

    @Synchronized
    fun forgetLeave(roomId: String, requestId: String) {
        val request = leaves[requestId] ?: error("Room unavailable")
        require(request.roomId == roomId)
        takeLeave(requestId)
    }

    @Synchronized
    fun isActiveRoom(roomId: String): Boolean = rooms[roomId]?.let { it.active && it.synchronized && it.pendingMessageId == null } == true

    @Synchronized
    fun acceptLeave(requestId: String, messageId: String = UUID.randomUUID().toString()): PreparedMlsTransaction {
        val request = leaves[requestId] ?: error("Room unavailable")
        val slot = activeSlot(request.roomId)
        require(sameUsername(slot.ownerUsername, username) && !sameUsername(request.username, slot.ownerUsername))
        require(slot.roster.any { sameUsername(it.username, request.username) && stableIdentityMatches(it, request.stableIdentity) })
        val commit = slot.handle.removeMember(request.username, request.stableIdentity, messageId)
        return try {
            val nextRoster = nativeRosterWire(commit.roster)
            val frame = membershipFrame(request.roomId, requestId, commit)
            stage(slot, messageId, commit.revision, nextRoster)
            PreparedMlsTransaction(request.roomId, messageId, commit.revision, frame, requestId, MlsTransactionKind.LEAVE)
        } catch (error: Throwable) {
            runCatching { slot.handle.rollbackOutbound(messageId, commit.revision) }
            throw error
        }
    }

    @Synchronized
    fun rejectLeave(requestId: String): JSONObject {
        val request = leaves[requestId] ?: error("Room unavailable")
        return JSONObject().put("type", "mls_leave_reject").put("protocol_version", MLS_PROTOCOL_VERSION)
            .put("room_id", request.roomId).put("request_id", request.requestId)
    }

    @Synchronized
    fun acceptJoin(requestId: String, messageId: String = UUID.randomUUID().toString()): PreparedMlsTransaction {
        val request = joins[requestId] ?: error("Room unavailable")
        val slot = activeSlot(request.roomId)
        require(sameUsername(slot.ownerUsername, username) && !sameUsername(request.username, username) && slot.roster.none { sameUsername(it.username, request.username) })
        val commit = slot.handle.addMember(request.keyPackage, request.username, request.stableIdentity, messageId)
        return try {
            val nextRoster = nativeRosterWire(commit.roster)
            val frame = membershipFrame(request.roomId, requestId, commit)
            stage(slot, messageId, commit.revision, nextRoster)
            PreparedMlsTransaction(request.roomId, messageId, commit.revision, frame, requestId, MlsTransactionKind.JOIN)
        } catch (error: Throwable) {
            runCatching { slot.handle.rollbackOutbound(messageId, commit.revision) }
            throw error
        }
    }

    @Synchronized
    fun rejectJoin(requestId: String): JSONObject {
        val request = joins[requestId] ?: error("Room unavailable")
        return JSONObject().put("type", "mls_join_reject").put("protocol_version", MLS_PROTOCOL_VERSION)
            .put("room_id", request.roomId).put("request_id", request.requestId)
    }

    @Synchronized
    fun prepareApplication(roomId: String, messageId: String, sender: String, plaintext: ByteArray): PreparedMlsTransaction {
        val slot = activeSlot(roomId)
        val aad = MlsWireCodec.applicationAad(roomId, messageId, sender)
        val encrypted = slot.handle.encryptApplication(messageId, plaintext, aad)
        return try {
            val frame = JSONObject().put("type", "mls_application").put("protocol_version", MLS_PROTOCOL_VERSION)
                .put("room_id", roomId).put("message_id", messageId).put("group_id_b64", MlsWireCodec.encode(encrypted.groupId))
                .put("epoch", MlsWireCodec.decimal(encrypted.epoch)).put("revision", MlsWireCodec.decimal(encrypted.revision))
                .put("membership_digest_b64", MlsWireCodec.encode(encrypted.membershipDigest))
                .put("ciphertext_b64", MlsWireCodec.encode(encrypted.ciphertext))
                .put("authenticated_data_b64", MlsWireCodec.encode(encrypted.authenticatedData))
                .put("state_envelope_b64", MlsWireCodec.encode(encrypted.stateEnvelope))
            stage(slot, messageId, encrypted.revision)
            PreparedMlsTransaction(roomId, messageId, encrypted.revision, frame, kind = MlsTransactionKind.APPLICATION)
        } finally {
            aad.fill(0); encrypted.groupId.fill(0); encrypted.membershipDigest.fill(0); encrypted.ciphertext.fill(0)
            encrypted.authenticatedData.fill(0); encrypted.stateEnvelope.fill(0)
        }
    }

    @Synchronized
    fun finishTransaction(prepared: PreparedMlsTransaction, outcome: OutboundSendResult) {
        val slot = rooms[prepared.roomId] ?: error("Room unavailable")
        require(slot.pendingMessageId == prepared.messageId && slot.pendingRevision == prepared.revision)
        val stagedRoster = slot.pendingRoster
        var installedRoster = false
        try {
            when (outcome) {
                OutboundSendResult.ACCEPTED -> {
                    slot.handle.commitOutbound(prepared.messageId, prepared.revision)
                    stagedRoster?.let {
                        wipeRoster(slot.roster)
                        slot.roster = it
                        installedRoster = true
                    }
                }
                OutboundSendResult.REJECTED, OutboundSendResult.NOT_SENT -> slot.handle.rollbackOutbound(prepared.messageId, prepared.revision)
                OutboundSendResult.AMBIGUOUS -> { removeRoom(prepared.roomId); return }
            }
            if (outcome == OutboundSendResult.ACCEPTED && prepared.requestId != null) {
                when (prepared.kind) {
                    MlsTransactionKind.JOIN -> { takeJoin(prepared.requestId); slot.pendingJoinRequestId = null }
                    MlsTransactionKind.LEAVE -> takeLeave(prepared.requestId)
                    MlsTransactionKind.APPLICATION -> error("Room unavailable")
                }
            }
        } catch (error: Throwable) { removeRoom(prepared.roomId); throw error }
        finally {
            if (!installedRoster) stagedRoster?.let(::wipeRoster)
            slot.pendingMessageId = null; slot.pendingRevision = null; slot.pendingRoster = null
        }
    }

    @Synchronized
    fun receiveApplication(frame: MlsIncomingFrame.Application): DecryptedMlsApplication {
        val slot = inboundSlot(frame.roomId)
        var aad = ByteArray(0); var expected = ByteArray(0); var cipher = ByteArray(0); var digest = ByteArray(0)
        return try {
            aad = MlsWireCodec.decode(frame.authenticatedDataB64); expected = MlsWireCodec.applicationAad(frame.roomId, frame.messageId, frame.senderUsername)
            require(aad.contentEquals(expected)); cipher = MlsWireCodec.decode(frame.ciphertextB64)
            val clear = slot.handle.decryptApplication(cipher, frame.epoch, frame.messageId, aad)
            try {
                digest = MlsWireCodec.decode(frame.membershipDigestB64)
                require(clear.revision == frame.revision && clear.membershipDigest.contentEquals(digest))
                val prepared = snapshot(
                    frame.roomId, frame.messageId, clear.epoch, clear.revision,
                    clear.membershipDigest, clear.stateEnvelope, true
                )
                stage(slot, frame.messageId, clear.revision)
                slot.synchronized = false
                DecryptedMlsApplication(clear.plaintext.clone(), prepared)
            } finally {
                clear.plaintext.fill(0); clear.groupId.fill(0); clear.membershipDigest.fill(0)
                clear.stateEnvelope.fill(0); clear.authenticatedData.fill(0)
            }
        } catch (error: Throwable) { removeRoom(frame.roomId); throw error }
        finally { aad.fill(0); expected.fill(0); cipher.fill(0); digest.fill(0) }
    }

    @Synchronized
    fun receiveMembership(frame: MlsIncomingFrame.Membership): PreparedMlsSnapshot {
        val slot = rooms[frame.roomId] ?: error("Room unavailable")
        var digest = ByteArray(0); var aad = ByteArray(0); var welcome = ByteArray(0); var control = ByteArray(0); var group = ByteArray(0); var prior = ByteArray(0)
        return try {
            digest = MlsWireCodec.decode(frame.membershipDigestB64); aad = MlsWireCodec.decode(frame.authenticatedDataB64)
            welcome = MlsWireCodec.decode(frame.welcomeB64); control = MlsWireCodec.decode(frame.controlB64); group = MlsWireCodec.decode(frame.groupIdB64)
            require(slot.groupId.contentEquals(group))
            val joining = welcome.isNotEmpty() && !slot.active
            require((!slot.active) == welcome.isNotEmpty())
            validateRoster(frame.roster, slot.ownerUsername, requireSelf = joining)
            val prepared = if (joining) {
                val info = withNativeRoster(frame.roster) { slot.handle.joinWelcome(welcome, it, digest) }
                try {
                    require(info.revision == frame.revision && info.membershipDigest.contentEquals(digest))
                    val state = slot.handle.sealState()
                    try { snapshot(frame.roomId, frame.messageId, info.epoch, info.revision, info.membershipDigest, state, false) }
                    finally { state.fill(0) }
                } finally { info.groupId.fill(0); info.membershipDigest.fill(0) }
            } else {
                val info = slot.handle.roomInfo(); prior = MlsWireCodec.decode(frame.fromMembershipDigestB64)
                try {
                    require(info.epoch == frame.fromEpoch && info.revision + 1uL == frame.revision && info.groupId.contentEquals(slot.groupId) && info.membershipDigest.contentEquals(prior))
                } finally { info.groupId.fill(0); info.membershipDigest.fill(0) }
                val processed = withNativeRoster(frame.roster) {
                    slot.handle.processControl(control, frame.fromEpoch, frame.toEpoch, it, digest, frame.messageId, aad)
                }
                try {
                    val pd = processed.membershipDigest(); val state = processed.stateEnvelope()
                    try { require(processed.revision() == frame.revision && pd.contentEquals(digest)); snapshot(frame.roomId, frame.messageId, processed.epoch(), processed.revision(), pd, state, true) }
                    finally { pd.fill(0); state.fill(0) }
                } finally { processed.close() }
            }
            val nextRoster = frame.roster.map { it.copy() }
            if (!joining) stage(slot, frame.messageId, frame.revision, nextRoster) else slot.pendingRoster = nextRoster
            slot.synchronized = false
            prepared
        } catch (error: Throwable) { removeRoom(frame.roomId); throw error }
        finally { digest.fill(0); aad.fill(0); welcome.fill(0); control.fill(0); group.fill(0); prior.fill(0) }
    }

    @Synchronized
    fun finishSnapshot(prepared: PreparedMlsSnapshot, outcome: OutboundSendResult) {
        val slot = rooms[prepared.roomId] ?: error("Room unavailable")
        if (prepared.nativePending) require(slot.pendingMessageId == prepared.messageId && slot.pendingRevision == prepared.revision)
        val stagedRoster = slot.pendingRoster
        var installedRoster = false
        try {
            if (prepared.nativePending && outcome == OutboundSendResult.ACCEPTED) slot.handle.commitOutbound(prepared.messageId, prepared.revision)
            else if (prepared.nativePending && (outcome == OutboundSendResult.REJECTED || outcome == OutboundSendResult.NOT_SENT)) slot.handle.rollbackOutbound(prepared.messageId, prepared.revision)
            else if (!prepared.nativePending && outcome != OutboundSendResult.ACCEPTED) { removeRoom(prepared.roomId); return }
            else if (outcome == OutboundSendResult.AMBIGUOUS) { removeRoom(prepared.roomId); return }
            stagedRoster?.let {
                wipeRoster(slot.roster)
                slot.roster = it
                installedRoster = true
            }
            slot.active = true; slot.pendingMessageId = null; slot.pendingRevision = null; slot.pendingRoster = null
        } catch (error: Throwable) { removeRoom(prepared.roomId); throw error }
        finally {
            if (!installedRoster) stagedRoster?.let(::wipeRoster)
            slot.pendingMessageId = null; slot.pendingRevision = null; slot.pendingRoster = null
        }
    }

    @Synchronized fun removeRoom(roomId: String) {
        val slot = rooms.remove(roomId) ?: return
        slot.groupId.fill(0); wipeRoster(slot.roster); slot.roster = emptyList(); slot.pendingRoster?.let(::wipeRoster); slot.pendingRoster = null
        joins.filterValues { it.roomId == roomId }.keys.toList().forEach { takeJoin(it) }
        leaves.filterValues { it.roomId == roomId }.keys.toList().forEach { takeLeave(it) }
        runCatching { slot.handle.close() }
    }

    @Synchronized override fun close() {
        if (closed) return; closed = true
        rooms.keys.toList().forEach(::removeRoom)
        joins.keys.toList().forEach(::takeJoin)
        leaves.keys.toList().forEach(::takeLeave)
        nodeContext.fill(0); stableIdentity.fill(0)
    }

    private fun exactExisting(slot: RoomSlot, wire: MlsRoomWire): Boolean {
        val recovery = wire.recoverySnapshot ?: return false
        if (!sameUsername(slot.ownerUsername, wire.ownerUsername) || slot.active != recovery.active) return false
        val info = slot.handle.roomInfo(); var digest = ByteArray(0); var group = ByteArray(0)
        return try {
            digest = MlsWireCodec.decode(recovery.membershipDigestB64); group = MlsWireCodec.decode(wire.groupIdB64)
            info.revision == recovery.revision && info.epoch == recovery.epoch &&
                info.membershipDigest.contentEquals(digest) && info.groupId.contentEquals(group) &&
                sameRoster(slot.roster, recovery.roster)
        } finally { info.membershipDigest.fill(0); info.groupId.fill(0); digest.fill(0); group.fill(0) }
    }

    private fun membershipFrame(roomId: String, requestId: String?, c: uniffi.abyssal_core.MlsCommit): JSONObject = try {
        JSONObject().put("type", "mls_membership_commit").put("protocol_version", MLS_PROTOCOL_VERSION).put("room_id", roomId)
            .put("message_id", c.messageId).put("request_id", requestId ?: JSONObject.NULL)
            .put("from_epoch", MlsWireCodec.decimal(c.fromEpoch)).put("to_epoch", MlsWireCodec.decimal(c.toEpoch)).put("revision", MlsWireCodec.decimal(c.revision))
            .put("group_id_b64", MlsWireCodec.encode(c.groupId)).put("from_membership_digest_b64", MlsWireCodec.encode(c.fromMembershipDigest))
            .put("membership_digest_b64", MlsWireCodec.encode(c.membershipDigest)).put("roster", rosterJson(c.roster))
            .put("control_b64", MlsWireCodec.encode(c.commit)).put("welcome_b64", MlsWireCodec.encode(c.welcome))
            .put("authenticated_data_b64", MlsWireCodec.encode(c.authenticatedData)).put("state_envelope_b64", MlsWireCodec.encode(c.stateEnvelope))
    } finally { c.groupId.fill(0); c.fromMembershipDigest.fill(0); c.membershipDigest.fill(0); c.stateEnvelope.fill(0); c.authenticatedData.fill(0); c.commit.fill(0); c.welcome.fill(0); c.roster.forEach { it.stableIdentity.fill(0) } }

    private fun snapshot(roomId: String, messageId: String, epoch: ULong, revision: ULong, digest: ByteArray, state: ByteArray, pending: Boolean) = PreparedMlsSnapshot(
        roomId, messageId, revision,
        JSONObject().put("type", "mls_state_snapshot").put("protocol_version", MLS_PROTOCOL_VERSION).put("room_id", roomId).put("message_id", messageId)
            .put("epoch", MlsWireCodec.decimal(epoch)).put("revision", MlsWireCodec.decimal(revision))
            .put("membership_digest_b64", MlsWireCodec.encode(digest)).put("state_envelope_b64", MlsWireCodec.encode(state)), pending)

    private inline fun <T> withNativeRoster(roster: List<MlsRosterMemberWire>, block: (List<MlsRosterMember>) -> T): T {
        val native = roster.map { MlsRosterMember(it.username, MlsWireCodec.decode(it.stableIdentityB64)) }
        return try { block(native) } finally { native.forEach { it.stableIdentity.fill(0) } }
    }
    private fun nativeRosterWire(roster: List<MlsRosterMember>): List<MlsRosterMemberWire> =
        roster.map { MlsRosterMemberWire(it.username, MlsWireCodec.encode(it.stableIdentity)) }

    private fun wipeRoster(roster: List<MlsRosterMemberWire>) {
        roster.forEach { member ->
            var stable = ByteArray(0)
            try { stable = MlsWireCodec.decode(member.stableIdentityB64) }
            catch (_: Throwable) { return@forEach }
            finally { stable.fill(0) }
        }
    }

    private fun validateRoomWire(wire: MlsRoomWire) {
        require(ID.matches(wire.roomId) && USERNAME.matches(wire.ownerUsername))
        val recovery = requireNotNull(wire.recoverySnapshot)
        require(recovery.active == wire.active)
        if (wire.roster.isEmpty()) {
            require(!wire.active && !wire.synchronized && wire.epoch == 0uL && wire.revision == 0uL && wire.membershipDigestB64.isEmpty())
        } else {
            validateRoster(wire.roster, wire.ownerUsername, requireSelf = true)
        }
        if (!recovery.active) {
            require(recovery.epoch == 0uL && recovery.revision == 0uL && recovery.membershipDigestB64.isEmpty() && recovery.roster.isEmpty())
        } else {
            validateRoster(recovery.roster, wire.ownerUsername, requireSelf = true)
        }
        require(!wire.synchronized || recovery.epoch == wire.epoch && recovery.revision == wire.revision &&
            recovery.membershipDigestB64 == wire.membershipDigestB64 && sameRoster(recovery.roster, wire.roster))
    }

    private fun validateRoster(roster: List<MlsRosterMemberWire>, owner: String, requireSelf: Boolean) {
        val names = HashSet<String>(); val identities = HashSet<String>()
        require(roster.size in 1..MAX_MEMBERS && roster.count { sameUsername(it.username, owner) } == 1)
        roster.forEach {
            require(names.add(it.username.lowercase(Locale.ROOT)) && identities.add(it.stableIdentityB64))
            var identity = ByteArray(0)
            try {
                identity = MlsWireCodec.decode(it.stableIdentityB64)
                require(identity.size == 64)
            } finally { identity.fill(0) }
        }
        require(!requireSelf || roster.any { sameUsername(it.username, username) && stableIdentityMatches(it) })
    }

    private fun stableIdentityMatches(member: MlsRosterMemberWire): Boolean =
        stableIdentityMatches(member, stableIdentity)

    private fun stableIdentityMatches(member: MlsRosterMemberWire, expected: ByteArray): Boolean {
        var decoded = ByteArray(0)
        return try {
            decoded = MlsWireCodec.decode(member.stableIdentityB64)
            decoded.contentEquals(expected)
        } finally { decoded.fill(0) }
    }

    private fun sameUsername(left: String, right: String): Boolean = left.equals(right, ignoreCase = true)

    private fun sameRoster(left: List<MlsRosterMemberWire>, right: List<MlsRosterMemberWire>): Boolean {
        if (left.size != right.size) return false
        return left.all { member ->
            right.firstOrNull { sameUsername(it.username, member.username) }?.let {
                it.stableIdentityB64 == member.stableIdentityB64
            } == true
        }
    }

    private fun rosterJson(roster: List<MlsRosterMember>): JSONArray = JSONArray().apply { roster.forEach { put(JSONObject().put("username", it.username).put("stable_identity_b64", MlsWireCodec.encode(it.stableIdentity))) } }
    private fun activeSlot(roomId: String): RoomSlot { checkOpen(); return rooms[roomId]?.takeIf { it.active && it.synchronized && it.pendingMessageId == null } ?: error("Room unavailable") }
    private fun inboundSlot(roomId: String): RoomSlot { checkOpen(); return rooms[roomId]?.takeIf { it.active && it.pendingMessageId == null } ?: error("Room unavailable") }
    private fun stage(slot: RoomSlot, messageId: String, revision: ULong, roster: List<MlsRosterMemberWire>? = null) {
        check(slot.pendingMessageId == null)
        slot.pendingMessageId = messageId; slot.pendingRevision = revision; slot.pendingRoster = roster
    }
    private fun takeJoin(id: String): PendingJoin { val join = joins.remove(id) ?: error("Room unavailable"); join.stableIdentity.fill(0); join.keyPackage.fill(0); return join }
    private fun takeLeave(id: String): PendingLeave { val leave = leaves.remove(id) ?: error("Room unavailable"); leave.stableIdentity.fill(0); return leave }
    private fun checkOpen() = check(!closed) { "Room unavailable" }

    private companion object {
        const val MAX_ROOMS = 128
        const val MAX_PENDING_JOINS = 128
        const val MAX_MEMBERS = 117
        val ID = Regex("^[A-Za-z0-9_-]{1,128}$")
        val USERNAME = Regex("^[A-Za-z0-9_-]{1,80}$")
        val NODE_ID = Regex("^[A-Za-z0-9._:-]{1,128}$")
    }
}

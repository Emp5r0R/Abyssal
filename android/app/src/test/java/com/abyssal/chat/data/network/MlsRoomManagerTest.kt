package com.abyssal.chat.data.network

import com.abyssal.chat.domain.model.ChatSession
import com.abyssal.chat.domain.model.MlsIncomingFrame
import com.abyssal.chat.domain.model.MlsRecoverySnapshotWire
import com.abyssal.chat.domain.model.MlsRoomPolicyWire
import com.abyssal.chat.domain.model.MlsRoomWire
import com.abyssal.chat.domain.model.MlsRosterMemberWire
import com.abyssal.chat.domain.repository.OutboundSendResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MlsRoomManagerTest {
    @Test fun roomApplicationStagesAndExplicitRejectionRestoresUsableState() {
        val cipher = identity()
        val publicKey = cipher.publicKey()
        val manager = MlsRoomManager(cipher, "Alice", "node-1", publicKey)
        publicKey.fill(0)
        try {
            val create = manager.createRoom(room())
            assertEquals("mls_create_room", create.getString("type"))
            assertTrue(MlsWireCodec.isStrictControl(create))

            val plaintext = "secret".encodeToByteArray()
            val first = manager.prepareApplication("forum_alpha", "message_1", "Alice", plaintext)
            plaintext.fill(0)
            assertEquals("mls_application", first.frame.getString("type"))
            assertTrue(runCatching { manager.prepareApplication("forum_alpha", "message_2", "Alice", byteArrayOf(1)) }.isFailure)
            manager.finishTransaction(first, OutboundSendResult.REJECTED)

            val second = manager.prepareApplication("forum_alpha", "message_2", "Alice", byteArrayOf(2))
            manager.finishTransaction(second, OutboundSendResult.ACCEPTED)
        } finally {
            manager.close()
            cipher.clear()
        }
    }

    @Test fun ambiguousResultDropsRoomAndCloseIsIdempotentBeforeSessionClear() {
        val cipher = identity()
        val publicKey = cipher.publicKey()
        val manager = MlsRoomManager(cipher, "Alice", "node-1", publicKey)
        publicKey.fill(0)
        manager.createRoom(room())
        val prepared = manager.prepareApplication("forum_alpha", "message_1", "Alice", byteArrayOf(1))
        manager.finishTransaction(prepared, OutboundSendResult.AMBIGUOUS)
        assertTrue(runCatching { manager.prepareApplication("forum_alpha", "message_2", "Alice", byteArrayOf(2)) }.isFailure)
        manager.close()
        manager.close()
        cipher.clear()
        assertTrue(runCatching { cipher.publicKey() }.isFailure)
    }

    @Test fun constructorRejectsMalformedAccountContextWithoutRetainingIdentity() {
        val cipher = identity()
        val key = cipher.publicKey()
        assertTrue(runCatching { MlsRoomManager(cipher, "bad user", "node-1", key) }.isFailure)
        assertTrue(runCatching { MlsRoomManager(cipher, "Alice", "bad node!", key) }.isFailure)
        assertTrue(runCatching { MlsRoomManager(cipher, "Alice", "node-1", ByteArray(64)) }.isFailure)
        key.fill(0)
        cipher.clear()
    }

    @Test
    fun recoveryBindsOwnerAndSelfToBothCurrentAndHistoricalRosters() {
        val cipher = identity(7)
        val publicKey = cipher.publicKey()
        val manager = MlsRoomManager(cipher, "Alice", "node-1", publicKey)
        val stable = publicKey.copyOfRange(0, 64)
        publicKey.fill(0)
        try {
            val session = room("room_custom")
            val create = manager.createRoom(session)
            val roster = listOf(MlsRosterMemberWire("Alice", MlsWireCodec.encode(stable)))
            val wire = MlsRoomWire(
                roomId = "room_custom", ownerUsername = "Alice", groupIdB64 = create.getString("group_id_b64"),
                active = true, epoch = 0uL, revision = 0uL,
                membershipDigestB64 = create.getString("membership_digest_b64"), roster = roster,
                recoverySnapshot = MlsRecoverySnapshotWire(
                    active = true, epoch = 0uL, revision = 0uL,
                    membershipDigestB64 = create.getString("membership_digest_b64"),
                    stateEnvelopeB64 = create.getString("state_envelope_b64"), roster = roster
                ), policy = policy(session), synchronized = true
            )
            assertEquals(1, manager.recoverCatalog(listOf(wire)).size)
            assertTrue(manager.isActiveRoom("room_custom"))

            val spoofedOwner = wire.copy(ownerUsername = "Mallory")
            assertTrue(runCatching { manager.recoverCatalog(listOf(spoofedOwner)) }.isFailure)
            assertTrue(runCatching { manager.prepareApplication("room_custom", "message_1", "Alice", byteArrayOf(1)) }.isFailure)
        } finally {
            stable.fill(0)
            manager.close()
            cipher.clear()
        }
    }

    @Test
    fun unsynchronizedRecoveryUsesHistoricalRosterAndRemainsInboundOnly() {
        val ownerCipher = identity(7)
        val ownerKey = ownerCipher.publicKey()
        val ownerStable = ownerKey.copyOfRange(0, 64)
        val owner = MlsRoomManager(ownerCipher, "Alice", "node-1", ownerKey)
        ownerKey.fill(0)
        val memberCipher = identity(8)
        val memberKey = memberCipher.publicKey()
        val member = MlsRoomManager(memberCipher, "Bob", "node-1", memberKey)
        try {
            val session = room("room_custom")
            val create = owner.createRoom(session)
            val join = member.beginJoin(MlsIncomingFrame.RoomDiscovered("room_custom", create.getString("group_id_b64"), "Alice"))
            val request = joinRequest(join, memberKey)
            owner.rememberJoin(request)
            val prepared = owner.acceptJoin(request.requestId, "membership-current")
            owner.finishTransaction(prepared, OutboundSendResult.ACCEPTED)
            val lagging = MlsRoomWire(
                roomId = "room_custom", ownerUsername = "Alice", groupIdB64 = create.getString("group_id_b64"),
                active = true, epoch = prepared.frame.getString("to_epoch").toULong(),
                revision = prepared.revision, membershipDigestB64 = prepared.frame.getString("membership_digest_b64"),
                roster = roster(prepared.frame),
                recoverySnapshot = MlsRecoverySnapshotWire(
                    active = true, epoch = 0uL, revision = 0uL,
                    membershipDigestB64 = create.getString("membership_digest_b64"),
                    stateEnvelopeB64 = create.getString("state_envelope_b64"),
                    roster = listOf(MlsRosterMemberWire("Alice", MlsWireCodec.encode(ownerStable)))
                ),
                policy = policy(session), synchronized = false
            )
            assertEquals(1, owner.recoverCatalog(listOf(lagging)).size)
            assertFalse(owner.isActiveRoom("room_custom"))
            assertTrue(runCatching { owner.prepareApplication("room_custom", "message_2", "Alice", byteArrayOf(2)) }.isFailure)
        } finally {
            ownerStable.fill(0)
            owner.close(); member.close(); ownerCipher.clear(); memberCipher.clear(); memberKey.fill(0)
        }
    }

    @Test
    fun acceptedInboundApplicationCommitsNativeStateAndRejectsReplay() {
        val ownerCipher = identity(7)
        val ownerKey = ownerCipher.publicKey()
        val owner = MlsRoomManager(ownerCipher, "Alice", "node-1", ownerKey)
        ownerKey.fill(0)
        val memberCipher = identity(8)
        val memberKey = memberCipher.publicKey()
        val member = MlsRoomManager(memberCipher, "Bob", "node-1", memberKey)
        try {
            val create = owner.createRoom(room("room_custom"))
            val join = member.beginJoin(MlsIncomingFrame.RoomDiscovered("room_custom", create.getString("group_id_b64"), "Alice"))
            val request = joinRequest(join, memberKey)
            owner.rememberJoin(request)
            val membership = owner.acceptJoin(request.requestId, "membership-app")
            val welcome = member.receiveMembership(membershipFrame(membership.frame, revisionOverride = 0uL))
            member.finishSnapshot(welcome, OutboundSendResult.ACCEPTED)
            owner.finishTransaction(membership, OutboundSendResult.ACCEPTED)

            val first = owner.prepareApplication("room_custom", "message-a", "Alice", byteArrayOf(1))
            val firstFrame = applicationFrame(first.frame, "Alice", 1uL)
            owner.finishTransaction(first, OutboundSendResult.ACCEPTED)
            val firstSnapshot = member.receiveApplication(firstFrame)
            assertTrue(firstSnapshot.snapshot.nativePending)
            member.finishSnapshot(firstSnapshot.snapshot, OutboundSendResult.ACCEPTED)

            val second = owner.prepareApplication("room_custom", "message-b", "Alice", byteArrayOf(2))
            val secondFrame = applicationFrame(second.frame, "Alice", 2uL)
            owner.finishTransaction(second, OutboundSendResult.ACCEPTED)
            val secondSnapshot = member.receiveApplication(secondFrame)
            member.finishSnapshot(secondSnapshot.snapshot, OutboundSendResult.ACCEPTED)

            assertTrue(runCatching { member.receiveApplication(firstFrame) }.isFailure)
            assertTrue(runCatching { member.prepareApplication("room_custom", "message-c", "Bob", byteArrayOf(3)) }.isFailure)
        } finally {
            owner.close(); member.close(); ownerCipher.clear(); memberCipher.clear(); memberKey.fill(0)
        }
    }

    @Test
    fun inactiveJoinRecoverySurvivesReconnectAndProcessesWelcome() {
        val ownerCipher = identity(17)
        val ownerKey = ownerCipher.publicKey()
        val owner = MlsRoomManager(ownerCipher, "Alice", "node-1", ownerKey)
        ownerKey.fill(0)
        val memberCipher = identity(18)
        val memberKey = memberCipher.publicKey()
        var member = MlsRoomManager(memberCipher, "Bob", "node-1", memberKey)
        var recovered: MlsRoomManager? = null
        try {
            val create = owner.createRoom(room("room_reconnect"))
            val join = member.beginJoin(MlsIncomingFrame.RoomDiscovered("room_reconnect", create.getString("group_id_b64"), "Alice"))
            val request = joinRequest(join, memberKey)
            owner.rememberJoin(request)
            val membership = owner.acceptJoin(request.requestId, "membership-reconnect")
            member.close()
            val recoveredManager = MlsRoomManager(memberCipher, "Bob", "node-1", memberKey)
            recovered = recoveredManager
            val currentRoster = roster(membership.frame)
            val inactive = MlsRoomWire(
                roomId = "room_reconnect", ownerUsername = "Alice", groupIdB64 = create.getString("group_id_b64"),
                active = false, epoch = membership.frame.getString("to_epoch").toULong(), revision = 0uL,
                membershipDigestB64 = membership.frame.getString("membership_digest_b64"), roster = currentRoster,
                recoverySnapshot = MlsRecoverySnapshotWire(
                    active = false, epoch = 0uL, revision = 0uL, membershipDigestB64 = "",
                    stateEnvelopeB64 = join.getString("state_envelope_b64"), roster = emptyList()
                ), policy = policy(room("room_reconnect")), synchronized = false
            )
            assertTrue(recoveredManager.recoverCatalog(listOf(inactive)).isEmpty())
            val welcome = recoveredManager.receiveMembership(membershipFrame(membership.frame, revisionOverride = 0uL))
            recoveredManager.finishSnapshot(welcome, OutboundSendResult.ACCEPTED)
            assertFalse(recoveredManager.isActiveRoom("room_reconnect"))

            val synchronized = inactive.copy(
                active = true,
                recoverySnapshot = MlsRecoverySnapshotWire(
                    active = true, epoch = inactive.epoch, revision = 0uL,
                    membershipDigestB64 = inactive.membershipDigestB64,
                    stateEnvelopeB64 = welcome.frame.getString("state_envelope_b64"), roster = currentRoster
                ),
                synchronized = true
            )
            assertEquals(1, recoveredManager.recoverCatalog(listOf(synchronized)).size)
            assertTrue(recoveredManager.isActiveRoom("room_reconnect"))
            owner.finishTransaction(membership, OutboundSendResult.ACCEPTED)
        } finally {
            member.close(); recovered?.close(); owner.close()
            ownerCipher.clear(); memberCipher.clear(); memberKey.fill(0)
        }
    }

    @Test
    fun ownerApprovalRejectsSpoofedTargetsAndRejectControlRetainsRequestUntilExplicitForget() {
        val cipher = identity(7)
        val publicKey = cipher.publicKey()
        val manager = MlsRoomManager(cipher, "Alice", "node-1", publicKey)
        publicKey.fill(0)
        try {
            manager.createRoom(room("room_custom"))
            val stable = MlsWireCodec.encode(ByteArray(64) { 8 })
            val request = MlsIncomingFrame.JoinRequested("room_custom", "join-1", "Bob", stable, MlsWireCodec.encode(ByteArray(32) { 9 }))
            manager.rememberJoin(request)
            assertEquals(1, manager.pendingJoins().size)
            assertEquals("mls_join_reject", manager.rejectJoin("join-1").getString("type"))
            assertEquals(1, manager.pendingJoins().size)
            assertTrue(runCatching { manager.rememberJoin(request.copy(username = "Alice")) }.isFailure)
            manager.forgetJoin("join-1")
            assertTrue(manager.pendingJoins().isEmpty())
            assertTrue(runCatching { manager.rejectJoin("join-1") }.isFailure)
            assertTrue(runCatching { manager.beginLeave("room_custom") }.isFailure)
        } finally {
            manager.close()
            cipher.clear()
        }
    }

    @Test
    fun genericRoomIdsAreAuthoritativeAndJoinRejectionBindsExactRequest() {
        val ownerCipher = identity(7)
        val ownerKey = ownerCipher.publicKey()
        val owner = MlsRoomManager(ownerCipher, "Alice", "node-1", ownerKey)
        ownerKey.fill(0)
        val memberCipher = identity(8)
        val memberKey = memberCipher.publicKey()
        val member = MlsRoomManager(memberCipher, "Bob", "node-1", memberKey)
        try {
            val create = owner.createRoom(room("room_custom"))
            assertTrue(owner.isActiveRoom("room_custom"))
            val join = member.beginJoin(
                MlsIncomingFrame.RoomDiscovered("room_custom", create.getString("group_id_b64"), "Alice")
            )
            val requestId = join.getString("request_id")
            assertFalse(member.isActiveRoom("room_custom"))
            assertFalse(member.joinRejected("room_custom", "wrong-request"))
            assertTrue(runCatching { member.beginJoin(MlsIncomingFrame.RoomDiscovered("room_custom", create.getString("group_id_b64"), "Alice")) }.isFailure)
            assertTrue(member.joinRejected("room_custom", requestId))
            val retry = member.beginJoin(MlsIncomingFrame.RoomDiscovered("room_custom", create.getString("group_id_b64"), "Alice"))
            assertTrue(retry.getString("request_id").isNotBlank())
        } finally {
            owner.close(); member.close(); ownerCipher.clear(); memberCipher.clear(); memberKey.fill(0)
        }
    }

    @Test
    fun rejectedMembershipRestoresNativeStateAndKeepsApprovalContext() {
        val ownerCipher = identity(7)
        val ownerKey = ownerCipher.publicKey()
        val owner = MlsRoomManager(ownerCipher, "Alice", "node-1", ownerKey)
        ownerKey.fill(0)
        val memberCipher = identity(8)
        val memberKey = memberCipher.publicKey()
        val member = MlsRoomManager(memberCipher, "Bob", "node-1", memberKey)
        try {
            val create = owner.createRoom(room("room_custom"))
            val join = member.beginJoin(MlsIncomingFrame.RoomDiscovered("room_custom", create.getString("group_id_b64"), "Alice"))
            val request = joinRequest(join, memberKey)
            owner.rememberJoin(request)
            val prepared = owner.acceptJoin(request.requestId, "membership-rejected")
            owner.finishTransaction(prepared, OutboundSendResult.REJECTED)
            assertEquals(1, owner.pendingJoins().size)
            val retry = owner.acceptJoin(request.requestId, "membership-accepted")
            owner.finishTransaction(retry, OutboundSendResult.REJECTED)
            assertEquals(1, owner.pendingJoins().size)
        } finally {
            owner.close(); member.close(); ownerCipher.clear(); memberCipher.clear(); memberKey.fill(0)
        }
    }

    @Test
    fun acceptedMembershipStagesRosterUntilMemberSnapshotAcceptance() {
        val ownerCipher = identity(7)
        val ownerKey = ownerCipher.publicKey()
        val owner = MlsRoomManager(ownerCipher, "Alice", "node-1", ownerKey)
        ownerKey.fill(0)
        val memberCipher = identity(8)
        val memberKey = memberCipher.publicKey()
        val member = MlsRoomManager(memberCipher, "Bob", "node-1", memberKey)
        try {
            val create = owner.createRoom(room("room_custom"))
            val join = member.beginJoin(MlsIncomingFrame.RoomDiscovered("room_custom", create.getString("group_id_b64"), "Alice"))
            val request = joinRequest(join, memberKey)
            owner.rememberJoin(request)
            val prepared = owner.acceptJoin(request.requestId, "membership-accepted")
            // Relay assigns a fresh per-recipient revision to a first-contact
            // welcome delivery; the joining native room is still at revision 0.
            val membership = membershipFrame(prepared.frame, revisionOverride = 0uL)
            val pending = member.receiveMembership(membership)
            assertFalse(member.isActiveRoom("room_custom"))
            member.finishSnapshot(pending, OutboundSendResult.ACCEPTED)
            // First-contact state is active for inbound delivery but remains
            // outbound-gated until a synchronized catalog checkpoint arrives.
            assertFalse(member.isActiveRoom("room_custom"))
            owner.finishTransaction(prepared, OutboundSendResult.ACCEPTED)
            assertTrue(owner.pendingJoins().isEmpty())
            owner.rememberLeave(
                MlsIncomingFrame.LeaveRequested(
                    "room_custom", "leave-1", "Bob", MlsWireCodec.encode(memberKey.copyOfRange(0, 64))
                )
            )
            assertEquals("Bob", owner.pendingLeaves().single().username)
        } finally {
            owner.close(); member.close(); ownerCipher.clear(); memberCipher.clear(); memberKey.fill(0)
        }
    }

    private fun identity(seed: Int = 7) = InMemoryPayloadCipher().also {
        val export = ByteArray(64) { seed.toByte() }
        val context = "ABYSSAL_IDENTITY_V2:node:CODE-12345678".encodeToByteArray()
        try { it.createIdentity(export, context) } finally { export.fill(0); context.fill(0) }
    }

    private fun room(id: String = "forum_alpha") = ChatSession(
        id = id, name = "alpha", isForum = true, lastMessage = null,
        unreadCount = 0, selfDestructTimerSec = 5, ownerUsername = "Alice"
    )

    private fun joinRequest(frame: org.json.JSONObject, publicKey: ByteArray) = MlsIncomingFrame.JoinRequested(
        frame.getString("room_id"), frame.getString("request_id"), "Bob",
        MlsWireCodec.encode(publicKey.copyOfRange(0, 64)), frame.getString("key_package_b64")
    )

    private fun roster(frame: org.json.JSONObject): List<MlsRosterMemberWire> = frame.getJSONArray("roster").let { array ->
        (0 until array.length()).map { index ->
            val member = array.getJSONObject(index)
            MlsRosterMemberWire(member.getString("username"), member.getString("stable_identity_b64"))
        }
    }

    private fun applicationFrame(
        frame: org.json.JSONObject,
        sender: String,
        recipientRevision: ULong = frame.getString("revision").toULong()
    ) = MlsIncomingFrame.Application(
        roomId = frame.getString("room_id"), messageId = frame.getString("message_id"), senderUsername = sender,
        epoch = frame.getString("epoch").toULong(), revision = recipientRevision,
        membershipDigestB64 = frame.getString("membership_digest_b64"), ciphertextB64 = frame.getString("ciphertext_b64"),
        authenticatedDataB64 = frame.getString("authenticated_data_b64")
    )

    private fun policy(session: ChatSession) = MlsRoomPolicyWire(
        selfDestructTimerSec = session.selfDestructTimerSec.toULong(), overallExpirySec = session.overallExpirySec.toULong(),
        allowImages = session.allowImages, allowVideos = session.allowVideos, allowFiles = session.allowFiles,
        enforceTextAbsoluteExpiry = session.enforceTextAbsoluteExpiry,
        imageReadTimerSec = session.imageReadTimerSec.toULong(), imageOverallExpirySec = session.imageOverallExpirySec.toULong(),
        enforceImageAbsoluteExpiry = session.enforceImageAbsoluteExpiry,
        videoReadTimerSec = session.videoReadTimerSec.toULong(), videoOverallExpirySec = session.videoOverallExpirySec.toULong(),
        enforceVideoAbsoluteExpiry = session.enforceVideoAbsoluteExpiry,
        fileReadTimerSec = session.fileReadTimerSec.toULong(), fileOverallExpirySec = session.fileOverallExpirySec.toULong(),
        enforceFileAbsoluteExpiry = session.enforceFileAbsoluteExpiry
    )

    private fun membershipFrame(frame: org.json.JSONObject, revisionOverride: ULong? = null) = MlsIncomingFrame.Membership(
        roomId = frame.getString("room_id"), messageId = frame.getString("message_id"),
        fromEpoch = frame.getString("from_epoch").toULong(), toEpoch = frame.getString("to_epoch").toULong(),
        revision = revisionOverride ?: frame.getString("revision").toULong(), fromMembershipDigestB64 = frame.getString("from_membership_digest_b64"),
        groupIdB64 = frame.getString("group_id_b64"), membershipDigestB64 = frame.getString("membership_digest_b64"),
        roster = frame.getJSONArray("roster").let { array ->
            (0 until array.length()).map { index ->
                val member = array.getJSONObject(index)
                com.abyssal.chat.domain.model.MlsRosterMemberWire(member.getString("username"), member.getString("stable_identity_b64"))
            }
        },
        controlB64 = frame.getString("control_b64"), welcomeB64 = frame.getString("welcome_b64"),
        authenticatedDataB64 = frame.getString("authenticated_data_b64")
    )
}

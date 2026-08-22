package com.abyssal.chat.data.network

import com.abyssal.chat.domain.model.MlsIncomingFrame
import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class MlsWireCodecTest {
    @Test fun canonicalU64RejectsOverflowLeadingZeroAndNonStrings() {
        assertEquals(ULong.MAX_VALUE, MlsWireCodec.canonicalU64("18446744073709551615"))
        listOf("18446744073709551616", "00", "01", "-1", "+1", " 1", "1 ", "1.0", "123456789012345678901").forEach {
            assertNull(it, MlsWireCodec.canonicalU64(it))
        }
        assertNull(MlsWireCodec.canonicalU64(1L))
    }

    @Test fun base64UrlIsCanonicalUnpaddedAndRejectsAliases() {
        val bytes = ByteArray(32) { it.toByte() }
        val encoded = MlsWireCodec.encode(bytes)
        assertFalse(encoded.contains('='))
        assertArrayEquals(bytes, MlsWireCodec.decode(encoded))
        listOf("$encoded=", "+A", "A").forEach { invalid ->
            assertTrue(runCatching { MlsWireCodec.decode(invalid) }.isFailure)
        }
    }

    @Test fun applicationAadUsesExactBigEndianLengthPrefix() {
        val aad = MlsWireCodec.applicationAad("forum_a", "message_1", "Alice")
        val buffer = ByteBuffer.wrap(aad).order(ByteOrder.BIG_ENDIAN)
        listOf("ABYSSAL-MLS-V10-APPLICATION", "forum_a", "message_1", "Alice").forEach { expected ->
            val bytes = ByteArray(buffer.int); buffer.get(bytes); assertEquals(expected, bytes.decodeToString()); bytes.fill(0)
        }
        assertFalse(buffer.hasRemaining())
        aad.fill(0)
    }

    @Test fun applicationRequiresExactKeysAndBounds() {
        val valid = applicationFrame()
        assertTrue(MlsWireCodec.parse(valid) is MlsIncomingFrame.Application)
        assertNull(MlsWireCodec.parse(JSONObject(valid.toString()).put("extra", true)))
        assertNull(MlsWireCodec.parse(JSONObject(valid.toString()).put("epoch", "01")))
        assertNull(MlsWireCodec.parse(JSONObject(valid.toString()).put("ciphertext_b64", MlsWireCodec.encode(ByteArray(MlsWireCodec.MAX_APPLICATION_BYTES + 1)))))
        assertNull(MlsWireCodec.parse(JSONObject(valid.toString()).put("membership_digest_b64", MlsWireCodec.encode(ByteArray(31)))))
    }

    @Test fun catalogRejectsDuplicateRoomsEmptyRosterAndInvalidPolicyTimer() {
        val room = room()
        val duplicate = JSONObject().put("type", "mls_rooms").put("protocol_version", 10)
            .put("rooms", JSONArray().put(room).put(JSONObject(room.toString())))
        assertNull(MlsWireCodec.parse(duplicate))
        val emptyRoster = JSONObject(room.toString()).put("roster", JSONArray())
        assertNull(MlsWireCodec.parse(JSONObject().put("type", "mls_room_created").put("protocol_version", 10).put("room", emptyRoster)))
        val badPolicy = JSONObject(room.toString()).put("policy", JSONObject(room.getJSONObject("policy").toString()).put("overall_expiry_sec", "86401"))
        assertNull(MlsWireCodec.parse(JSONObject().put("type", "mls_room_created").put("protocol_version", 10).put("room", badPolicy)))
    }

    @Test fun catalogRequiresSynchronizedAndHistoricalRecoveryRosterFields() {
        val valid = room()
        assertTrue(MlsWireCodec.parse(JSONObject().put("type", "mls_room_created").put("protocol_version", 10).put("room", valid)) is MlsIncomingFrame.RoomCreated)
        assertNull(MlsWireCodec.parse(JSONObject().put("type", "mls_room_created").put("protocol_version", 10).put("room", JSONObject(valid.toString()).remove("synchronized"))))
        val missingRecoveryRoster = JSONObject(valid.toString())
            .put("recovery_snapshot", JSONObject(valid.getJSONObject("recovery_snapshot").toString()).remove("roster"))
        assertNull(MlsWireCodec.parse(JSONObject().put("type", "mls_room_created").put("protocol_version", 10).put("room", missingRecoveryRoster)))
    }

    @Test fun rosterRejectsAsciiCaseInsensitiveAndStableIdentityDuplicates() {
        val base = room()
        val duplicateName = JSONObject(base.toString()).put("roster", JSONArray()
            .put(JSONObject().put("username", "Alice").put("stable_identity_b64", MlsWireCodec.encode(ByteArray(64))))
            .put(JSONObject().put("username", "aLiCe").put("stable_identity_b64", MlsWireCodec.encode(ByteArray(64) { 1 }))))
        assertNull(MlsWireCodec.parse(JSONObject().put("type", "mls_room_created").put("protocol_version", 10).put("room", duplicateName)))
        val duplicateIdentity = JSONObject(base.toString()).put("roster", JSONArray()
            .put(JSONObject().put("username", "Alice").put("stable_identity_b64", MlsWireCodec.encode(ByteArray(64))))
            .put(JSONObject().put("username", "Bob").put("stable_identity_b64", MlsWireCodec.encode(ByteArray(64)))))
        assertNull(MlsWireCodec.parse(JSONObject().put("type", "mls_room_created").put("protocol_version", 10).put("room", duplicateIdentity)))
    }

    @Test fun inactivePendingRecoveryAllowsEmptyHistoricalRosterAndDigestOnly() {
        val pending = room().apply {
            put("active", false).put("synchronized", false).put("epoch", "0").put("revision", "0")
                .put("membership_digest_b64", "")
                .put("roster", JSONArray())
                .put("recovery_snapshot", JSONObject().put("active", false).put("epoch", "0").put("revision", "0")
                    .put("membership_digest_b64", "").put("state_envelope_b64", MlsWireCodec.encode(byteArrayOf(7))).put("roster", JSONArray()))
        }
        assertTrue(MlsWireCodec.parse(JSONObject().put("type", "mls_room_created").put("protocol_version", 10).put("room", pending)) is MlsIncomingFrame.RoomCreated)
        assertNull(MlsWireCodec.parse(JSONObject().put("type", "mls_room_created").put("protocol_version", 10).put("room", JSONObject(pending.toString()).put("membership_digest_b64", MlsWireCodec.encode(ByteArray(32))))))

        val acceptedJoin = room().apply {
            put("active", false).put("synchronized", false)
                .put("recovery_snapshot", pending.getJSONObject("recovery_snapshot"))
        }
        assertTrue(MlsWireCodec.parse(JSONObject().put("type", "mls_room_created").put("protocol_version", 10).put("room", acceptedJoin)) is MlsIncomingFrame.RoomCreated)
    }

    @Test fun controlWhitelistDoesNotAcceptTransactionsOrUnknownCommands() {
        assertFalse(MlsWireCodec.isStrictControl(applicationFrame()))
        assertFalse(MlsWireCodec.isStrictControl(JSONObject().put("type", "mls_magic").put("protocol_version", 10)))
        val discover = JSONObject().put("type", "mls_discover_room").put("protocol_version", 10).put("room_id", "forum_a")
        assertTrue(MlsWireCodec.isStrictControl(discover))
        assertFalse(MlsWireCodec.isStrictControl(JSONObject(discover.toString()).put("extra", true)))
    }

    @Test fun outboundTransactionAndSnapshotRequireExactSchemas() {
        val outbound = JSONObject().put("type", "mls_application").put("protocol_version", 10)
            .put("room_id", "forum_a").put("message_id", "message_1").put("group_id_b64", MlsWireCodec.encode(ByteArray(32)))
            .put("epoch", "0").put("revision", "1").put("membership_digest_b64", MlsWireCodec.encode(ByteArray(32)))
            .put("ciphertext_b64", MlsWireCodec.encode(byteArrayOf(1))).put("authenticated_data_b64", MlsWireCodec.encode(byteArrayOf(2)))
            .put("state_envelope_b64", MlsWireCodec.encode(byteArrayOf(3)))
        assertTrue(MlsWireCodec.isStrictTransaction(outbound))
        assertFalse(MlsWireCodec.isStrictTransaction(JSONObject(outbound.toString()).put("extra", true)))
        val snapshot = JSONObject().put("type", "mls_state_snapshot").put("protocol_version", 10)
            .put("room_id", "forum_a").put("message_id", "message_1").put("epoch", "0").put("revision", "1")
            .put("membership_digest_b64", MlsWireCodec.encode(ByteArray(32))).put("state_envelope_b64", MlsWireCodec.encode(byteArrayOf(4)))
        assertTrue(MlsWireCodec.isStrictSnapshot(snapshot))
        assertFalse(MlsWireCodec.isStrictSnapshot(JSONObject(snapshot.toString()).put("revision", "01")))
    }

    private fun applicationFrame() = JSONObject().put("type", "mls_application").put("protocol_version", 10)
        .put("room_id", "forum_a").put("message_id", "message_1").put("sender_username", "Alice")
        .put("epoch", "0").put("revision", "1").put("membership_digest_b64", MlsWireCodec.encode(ByteArray(32) { 1 }))
        .put("ciphertext_b64", MlsWireCodec.encode(byteArrayOf(1))).put("authenticated_data_b64", MlsWireCodec.encode(byteArrayOf(2)))

    private fun room(): JSONObject {
        val policy = JSONObject()
        listOf("self_destruct_timer_sec", "overall_expiry_sec", "image_read_timer_sec", "image_overall_expiry_sec", "video_read_timer_sec", "video_overall_expiry_sec", "file_read_timer_sec", "file_overall_expiry_sec").forEach { policy.put(it, "0") }
        listOf("allow_images", "allow_videos", "allow_files", "enforce_text_absolute_expiry", "enforce_image_absolute_expiry", "enforce_video_absolute_expiry", "enforce_file_absolute_expiry").forEach { policy.put(it, true) }
        return JSONObject().put("room_id", "forum_a").put("owner_username", "Alice")
            .put("group_id_b64", MlsWireCodec.encode(ByteArray(32))).put("active", true).put("synchronized", true).put("epoch", "0").put("revision", "0")
            .put("membership_digest_b64", MlsWireCodec.encode(ByteArray(32) { 1 }))
            .put("roster", JSONArray().put(JSONObject().put("username", "Alice").put("stable_identity_b64", MlsWireCodec.encode(ByteArray(64)))))
            .put("recovery_snapshot", JSONObject().put("active", true).put("epoch", "0").put("revision", "0")
                .put("membership_digest_b64", MlsWireCodec.encode(ByteArray(32) { 1 }))
                .put("state_envelope_b64", MlsWireCodec.encode(byteArrayOf(5)))
                .put("roster", JSONArray().put(JSONObject().put("username", "Alice").put("stable_identity_b64", MlsWireCodec.encode(ByteArray(64))))))
            .put("policy", policy)
    }
}

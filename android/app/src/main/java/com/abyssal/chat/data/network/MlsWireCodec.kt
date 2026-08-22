package com.abyssal.chat.data.network

import com.abyssal.chat.domain.model.ChatSession
import com.abyssal.chat.domain.model.MLS_PROTOCOL_VERSION
import com.abyssal.chat.domain.model.MlsIncomingFrame
import com.abyssal.chat.domain.model.MlsRecoverySnapshotWire
import com.abyssal.chat.domain.model.MlsRoomPolicyWire
import com.abyssal.chat.domain.model.MlsRoomWire
import com.abyssal.chat.domain.model.MlsRosterMemberWire
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.Locale
import org.json.JSONArray
import org.json.JSONObject

internal object MlsWireCodec {
    const val MAX_FRAME_BYTES = 16 * 1024 * 1024
    const val MAX_APPLICATION_BYTES = 1024 * 1024
    const val MAX_STATE_BYTES = 4 * 1024 * 1024
    const val MAX_CONTROL_BYTES = 2 * 1024 * 1024
    const val MAX_AAD_BYTES = 4096
    const val MAX_MEMBERS = 117
    const val MAX_ROOMS = 1024
    private val id = Regex("^[A-Za-z0-9_-]{1,128}$")
    private val username = Regex("^[A-Za-z0-9_-]{1,80}$")
    private val b64 = Regex("^[A-Za-z0-9_-]*$")

    fun parse(text: String): MlsIncomingFrame? {
        if (exceedsUtf8ByteLimit(text, MAX_FRAME_BYTES)) return null
        return runCatching { parse(JSONObject(text)) }.getOrNull()
    }

    fun parse(value: JSONObject): MlsIncomingFrame? {
        if (value.opt("protocol_version") != MLS_PROTOCOL_VERSION) return null
        return when (value.opt("type") as? String) {
            "mls_rooms" -> if (value.exact("type", "protocol_version", "rooms")) {
                val rooms = value.optJSONArray("rooms")?.rooms() ?: return null
                MlsIncomingFrame.Rooms(rooms)
            } else null
            "mls_room_created" -> if (value.exact("type", "protocol_version", "room")) {
                value.optJSONObject("room")?.room()?.let(MlsIncomingFrame::RoomCreated)
            } else null
            "mls_room_discovered" -> if (value.exact("type", "protocol_version", "room_id", "group_id_b64", "owner_username")) {
                val roomId = value.string("room_id")?.takeIf(id::matches) ?: return null
                val group = value.string("group_id_b64")?.takeIf { validB64(it, 32, 32) } ?: return null
                val owner = value.string("owner_username")?.takeIf(username::matches) ?: return null
                MlsIncomingFrame.RoomDiscovered(roomId, group, owner)
            } else null
            "mls_join_requested" -> parseJoinRequested(value)
            "mls_leave_requested" -> parseLeaveRequested(value)
            "mls_join_rejected", "mls_leave_pending", "mls_leave_rejected" -> parseRequestResult(value)
            "mls_left", "mls_room_deleted" -> parseRoomOnly(value)
            "mls_membership" -> parseMembership(value)
            "mls_application" -> parseApplication(value)
            "mls_room_result", "mls_snapshot_result" -> parseResult(value)
            else -> null
        }
    }

    fun isStrictControl(value: JSONObject): Boolean {
        if (value.opt("protocol_version") != MLS_PROTOCOL_VERSION) return false
        return when (value.opt("type") as? String) {
            "mls_create_room" -> value.exact("type", "protocol_version", "room_id", "group_id_b64", "epoch", "revision", "membership_digest_b64", "stable_identity_b64", "state_envelope_b64", "policy") &&
                validId(value, "room_id") && validB64Field(value, "group_id_b64", 32, 32) &&
                value.string("epoch") == "0" && value.string("revision") == "0" &&
                validB64Field(value, "membership_digest_b64", 32, 32) && validB64Field(value, "stable_identity_b64", 64, 64) &&
                validB64Field(value, "state_envelope_b64", 1, MAX_STATE_BYTES) && value.optJSONObject("policy")?.policy() != null
            "mls_discover_room", "mls_delete_room" -> value.exact("type", "protocol_version", "room_id") && validId(value, "room_id")
            "mls_join_request" -> value.exact("type", "protocol_version", "room_id", "request_id", "stable_identity_b64", "key_package_b64", "state_envelope_b64") &&
                validId(value, "room_id") && validId(value, "request_id") && validB64Field(value, "stable_identity_b64", 64, 64) &&
                validB64Field(value, "key_package_b64", 1, 64 * 1024) && validB64Field(value, "state_envelope_b64", 1, MAX_STATE_BYTES)
            "mls_join_reject", "mls_leave_request", "mls_leave_reject" -> value.exact("type", "protocol_version", "room_id", "request_id") && validId(value, "room_id") && validId(value, "request_id")
            else -> false
        }
    }

    fun isStrictTransaction(value: JSONObject): Boolean = when (value.opt("type") as? String) {
        "mls_application" -> value.opt("protocol_version") == MLS_PROTOCOL_VERSION &&
            value.exact("type", "protocol_version", "room_id", "message_id", "group_id_b64", "epoch", "revision", "membership_digest_b64", "ciphertext_b64", "authenticated_data_b64", "state_envelope_b64") &&
            validId(value, "room_id") && validId(value, "message_id") && validB64Field(value, "group_id_b64", 32, 32) &&
            canonicalU64(value.opt("epoch")) != null && canonicalU64(value.opt("revision")) != null &&
            validB64Field(value, "membership_digest_b64", 32, 32) && validB64Field(value, "ciphertext_b64", 1, MAX_APPLICATION_BYTES) &&
            validB64Field(value, "authenticated_data_b64", 1, MAX_AAD_BYTES) && validB64Field(value, "state_envelope_b64", 1, MAX_STATE_BYTES)
        "mls_membership_commit" -> value.opt("protocol_version") == MLS_PROTOCOL_VERSION &&
            value.exact("type", "protocol_version", "room_id", "message_id", "request_id", "from_epoch", "to_epoch", "revision", "group_id_b64", "from_membership_digest_b64", "membership_digest_b64", "roster", "control_b64", "welcome_b64", "authenticated_data_b64", "state_envelope_b64") &&
            validId(value, "room_id") && validId(value, "message_id") && validId(value, "request_id") &&
            canonicalU64(value.opt("from_epoch")) != null && canonicalU64(value.opt("to_epoch")) != null && canonicalU64(value.opt("revision")) != null &&
            validB64Field(value, "group_id_b64", 32, 32) && validB64Field(value, "from_membership_digest_b64", 32, 32) &&
            validB64Field(value, "membership_digest_b64", 32, 32) && value.optJSONArray("roster")?.roster() != null &&
            validB64Field(value, "control_b64", 1, MAX_CONTROL_BYTES) && validB64Field(value, "welcome_b64", 0, MAX_CONTROL_BYTES) &&
            validB64Field(value, "authenticated_data_b64", 1, MAX_AAD_BYTES) && validB64Field(value, "state_envelope_b64", 1, MAX_STATE_BYTES)
        else -> false
    }

    fun isStrictSnapshot(value: JSONObject): Boolean = value.opt("type") == "mls_state_snapshot" &&
        value.opt("protocol_version") == MLS_PROTOCOL_VERSION &&
        value.exact("type", "protocol_version", "room_id", "message_id", "epoch", "revision", "membership_digest_b64", "state_envelope_b64") &&
        validId(value, "room_id") && validId(value, "message_id") && canonicalU64(value.opt("epoch")) != null &&
        canonicalU64(value.opt("revision")) != null && validB64Field(value, "membership_digest_b64", 32, 32) &&
        validB64Field(value, "state_envelope_b64", 1, MAX_STATE_BYTES)

    fun canonicalU64(value: Any?): ULong? {
        val text = value as? String ?: return null
        if (text.length > 20 || !Regex("^(?:0|[1-9][0-9]*)$").matches(text)) return null
        return text.toULongOrNull()
    }

    fun decimal(value: ULong): String = value.toString(10)

    fun encode(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    fun decode(value: String): ByteArray {
        require(b64.matches(value) && value.length % 4 != 1) { "Room unavailable" }
        val out = Base64.getUrlDecoder().decode(value)
        if (encode(out) != value) {
            out.fill(0)
            throw IllegalArgumentException("Room unavailable")
        }
        return out
    }

    fun applicationAad(roomId: String, messageId: String, sender: String): ByteArray {
        require(id.matches(roomId) && id.matches(messageId) && username.matches(sender))
        val fields = listOf("ABYSSAL-MLS-V10-APPLICATION", roomId, messageId, sender)
            .map { it.toByteArray(StandardCharsets.UTF_8) }
        val buffer = ByteBuffer.allocate(fields.sumOf { 4 + it.size }).order(ByteOrder.BIG_ENDIAN)
        return try {
            fields.forEach { buffer.putInt(it.size).put(it) }
            buffer.array().clone()
        } finally {
            buffer.array().fill(0)
            fields.forEach { it.fill(0) }
        }
    }

    fun policy(room: ChatSession): JSONObject = JSONObject()
        .put("self_destruct_timer_sec", decimal(room.selfDestructTimerSec.toULong()))
        .put("overall_expiry_sec", decimal(room.overallExpirySec.toULong()))
        .put("allow_images", room.allowImages)
        .put("allow_videos", room.allowVideos)
        .put("allow_files", room.allowFiles)
        .put("enforce_text_absolute_expiry", room.enforceTextAbsoluteExpiry)
        .put("image_read_timer_sec", decimal(room.imageReadTimerSec.toULong()))
        .put("image_overall_expiry_sec", decimal(room.imageOverallExpirySec.toULong()))
        .put("enforce_image_absolute_expiry", room.enforceImageAbsoluteExpiry)
        .put("video_read_timer_sec", decimal(room.videoReadTimerSec.toULong()))
        .put("video_overall_expiry_sec", decimal(room.videoOverallExpirySec.toULong()))
        .put("enforce_video_absolute_expiry", room.enforceVideoAbsoluteExpiry)
        .put("file_read_timer_sec", decimal(room.fileReadTimerSec.toULong()))
        .put("file_overall_expiry_sec", decimal(room.fileOverallExpirySec.toULong()))
        .put("enforce_file_absolute_expiry", room.enforceFileAbsoluteExpiry)

    fun roomSession(room: MlsRoomWire): ChatSession = ChatSession(
        id = room.roomId,
        name = room.roomId.removePrefix("forum_").replace(Regex("_[0-9a-f]{8}$"), "").replace('_', ' ').take(36).ifBlank { "Secure room" },
        isForum = true,
        lastMessage = null,
        unreadCount = 0,
        selfDestructTimerSec = room.policy.selfDestructTimerSec.toInt(),
        overallExpirySec = room.policy.overallExpirySec.toInt(),
        allowImages = room.policy.allowImages,
        allowVideos = room.policy.allowVideos,
        allowFiles = room.policy.allowFiles,
        enforceTextAbsoluteExpiry = room.policy.enforceTextAbsoluteExpiry,
        imageReadTimerSec = room.policy.imageReadTimerSec.toInt(), imageOverallExpirySec = room.policy.imageOverallExpirySec.toInt(),
        enforceImageAbsoluteExpiry = room.policy.enforceImageAbsoluteExpiry,
        videoReadTimerSec = room.policy.videoReadTimerSec.toInt(), videoOverallExpirySec = room.policy.videoOverallExpirySec.toInt(),
        enforceVideoAbsoluteExpiry = room.policy.enforceVideoAbsoluteExpiry,
        fileReadTimerSec = room.policy.fileReadTimerSec.toInt(), fileOverallExpirySec = room.policy.fileOverallExpirySec.toInt(),
        enforceFileAbsoluteExpiry = room.policy.enforceFileAbsoluteExpiry,
        ownerUsername = room.ownerUsername
    )

    private fun parseJoinRequested(v: JSONObject): MlsIncomingFrame? {
        if (!v.exact("type", "protocol_version", "room_id", "request_id", "username", "stable_identity_b64", "key_package_b64")) return null
        val room = v.string("room_id")?.takeIf(id::matches) ?: return null
        val request = v.string("request_id")?.takeIf(id::matches) ?: return null
        val user = v.string("username")?.takeIf(username::matches) ?: return null
        val stable = v.string("stable_identity_b64")?.takeIf { validB64(it, 64, 64) } ?: return null
        val key = v.string("key_package_b64")?.takeIf { validB64(it, 1, 64 * 1024) } ?: return null
        return MlsIncomingFrame.JoinRequested(room, request, user, stable, key)
    }

    private fun parseLeaveRequested(v: JSONObject): MlsIncomingFrame? {
        if (!v.exact("type", "protocol_version", "room_id", "request_id", "username", "stable_identity_b64")) return null
        return MlsIncomingFrame.LeaveRequested(
            v.string("room_id")?.takeIf(id::matches) ?: return null,
            v.string("request_id")?.takeIf(id::matches) ?: return null,
            v.string("username")?.takeIf(username::matches) ?: return null,
            v.string("stable_identity_b64")?.takeIf { validB64(it, 64, 64) } ?: return null
        )
    }

    private fun parseRequestResult(v: JSONObject): MlsIncomingFrame? {
        if (!v.exact("type", "protocol_version", "room_id", "request_id")) return null
        val room = v.string("room_id")?.takeIf(id::matches) ?: return null
        val request = v.string("request_id")?.takeIf(id::matches) ?: return null
        return when (v.string("type")) {
            "mls_join_rejected" -> MlsIncomingFrame.JoinRejected(room, request)
            "mls_leave_pending" -> MlsIncomingFrame.LeavePending(room, request)
            else -> MlsIncomingFrame.LeaveRejected(room, request)
        }
    }

    private fun parseRoomOnly(v: JSONObject): MlsIncomingFrame? {
        if (!v.exact("type", "protocol_version", "room_id")) return null
        val room = v.string("room_id")?.takeIf(id::matches) ?: return null
        return if (v.string("type") == "mls_left") MlsIncomingFrame.Left(room) else MlsIncomingFrame.RoomDeleted(room)
    }

    private fun parseMembership(v: JSONObject): MlsIncomingFrame? {
        if (!v.exact("type", "protocol_version", "room_id", "message_id", "from_epoch", "to_epoch", "revision", "from_membership_digest_b64", "group_id_b64", "membership_digest_b64", "roster", "control_b64", "welcome_b64", "authenticated_data_b64")) return null
        return MlsIncomingFrame.Membership(
            v.string("room_id")?.takeIf(id::matches) ?: return null,
            v.string("message_id")?.takeIf(id::matches) ?: return null,
            canonicalU64(v.opt("from_epoch")) ?: return null, canonicalU64(v.opt("to_epoch")) ?: return null,
            canonicalU64(v.opt("revision")) ?: return null,
            v.string("from_membership_digest_b64")?.takeIf { validB64(it, 32, 32) } ?: return null,
            v.string("group_id_b64")?.takeIf { validB64(it, 32, 32) } ?: return null,
            v.string("membership_digest_b64")?.takeIf { validB64(it, 32, 32) } ?: return null,
            v.optJSONArray("roster")?.roster() ?: return null,
            v.string("control_b64")?.takeIf { validB64(it, 1, MAX_CONTROL_BYTES) } ?: return null,
            v.string("welcome_b64")?.takeIf { validB64(it, 0, MAX_CONTROL_BYTES) } ?: return null,
            v.string("authenticated_data_b64")?.takeIf { validB64(it, 1, MAX_AAD_BYTES) } ?: return null
        )
    }

    private fun parseApplication(v: JSONObject): MlsIncomingFrame? {
        if (!v.exact("type", "protocol_version", "room_id", "message_id", "sender_username", "epoch", "revision", "membership_digest_b64", "ciphertext_b64", "authenticated_data_b64")) return null
        return MlsIncomingFrame.Application(
            v.string("room_id")?.takeIf(id::matches) ?: return null,
            v.string("message_id")?.takeIf(id::matches) ?: return null,
            v.string("sender_username")?.takeIf(username::matches) ?: return null,
            canonicalU64(v.opt("epoch")) ?: return null, canonicalU64(v.opt("revision")) ?: return null,
            v.string("membership_digest_b64")?.takeIf { validB64(it, 32, 32) } ?: return null,
            v.string("ciphertext_b64")?.takeIf { validB64(it, 1, MAX_APPLICATION_BYTES) } ?: return null,
            v.string("authenticated_data_b64")?.takeIf { validB64(it, 1, MAX_AAD_BYTES) } ?: return null
        )
    }

    private fun parseResult(v: JSONObject): MlsIncomingFrame? {
        if (!v.exact("type", "protocol_version", "room_id", "message_id", "revision", "accepted")) return null
        return MlsIncomingFrame.RoomResult(
            v.string("room_id")?.takeIf(id::matches) ?: return null,
            v.string("message_id")?.takeIf(id::matches) ?: return null,
            canonicalU64(v.opt("revision")) ?: return null,
            v.opt("accepted") as? Boolean ?: return null,
            v.string("type") == "mls_snapshot_result"
        )
    }

    private fun JSONArray.rooms(): List<MlsRoomWire>? {
        if (length() > MAX_ROOMS) return null
        val result = ArrayList<MlsRoomWire>(length())
        val seen = HashSet<String>()
        for (i in 0 until length()) {
            val room = optJSONObject(i)?.room() ?: return null
            if (!seen.add(room.roomId)) return null
            result += room
        }
        return result
    }

    private fun JSONObject.room(): MlsRoomWire? {
        if (!exact("room_id", "owner_username", "group_id_b64", "active", "synchronized", "epoch", "revision", "membership_digest_b64", "roster", "recovery_snapshot", "policy")) return null
        val active = opt("active") as? Boolean ?: return null
        val synchronized = opt("synchronized") as? Boolean ?: return null
        val epoch = canonicalU64(opt("epoch")) ?: return null
        val revision = canonicalU64(opt("revision")) ?: return null
        val digest = string("membership_digest_b64") ?: return null
        val roster = optJSONArray("roster")?.roster(allowEmpty = !active) ?: return null
        val recovery = if (isNull("recovery_snapshot")) null else optJSONObject("recovery_snapshot")?.recovery() ?: return null
        if (recovery == null || recovery.active != active || (synchronized && !active)) return null
        if (roster.isEmpty()) {
            if (active || synchronized || epoch != 0uL || revision != 0uL || digest.isNotEmpty()) return null
        } else if (!validB64(digest, 32, 32)) return null
        if (synchronized && (recovery.epoch != epoch || recovery.revision != revision ||
                recovery.membershipDigestB64 != digest || !sameRoster(recovery.roster, roster))) return null
        return MlsRoomWire(
            roomId = string("room_id")?.takeIf(id::matches) ?: return null,
            ownerUsername = string("owner_username")?.takeIf(username::matches) ?: return null,
            groupIdB64 = string("group_id_b64")?.takeIf { validB64(it, 32, 32) } ?: return null,
            active = active,
            epoch = epoch,
            revision = revision,
            membershipDigestB64 = digest,
            roster = roster,
            recoverySnapshot = recovery,
            policy = optJSONObject("policy")?.policy() ?: return null,
            synchronized = synchronized
        )
    }

    private fun JSONArray.roster(allowEmpty: Boolean = false): List<MlsRosterMemberWire>? {
        if (length() !in (if (allowEmpty) 0 else 1)..MAX_MEMBERS) return null
        val result = ArrayList<MlsRosterMemberWire>(length())
        val seen = HashSet<String>(); val identities = HashSet<String>()
        for (i in 0 until length()) {
            val member = optJSONObject(i) ?: return null
            if (!member.exact("username", "stable_identity_b64")) return null
            val user = member.string("username")?.takeIf(username::matches) ?: return null
            if (!seen.add(user.lowercase(Locale.ROOT))) return null
            val stable = member.string("stable_identity_b64")?.takeIf { validB64(it, 64, 64) } ?: return null
            if (!identities.add(stable)) return null
            result += MlsRosterMemberWire(user, stable)
        }
        return result
    }

    private fun JSONObject.recovery(): MlsRecoverySnapshotWire? {
        if (!exact("active", "epoch", "revision", "membership_digest_b64", "state_envelope_b64", "roster")) return null
        val active = opt("active") as? Boolean ?: return null
        val epoch = canonicalU64(opt("epoch")) ?: return null
        val revision = canonicalU64(opt("revision")) ?: return null
        val digest = string("membership_digest_b64") ?: return null
        if (!validB64(digest, if (active) 32 else 0, 32)) return null
        if (!active && (epoch != 0uL || revision != 0uL || digest.isNotEmpty())) return null
        val roster = optJSONArray("roster")?.roster(allowEmpty = !active) ?: return null
        return MlsRecoverySnapshotWire(
            active = active,
            epoch = epoch,
            revision = revision,
            membershipDigestB64 = digest,
            stateEnvelopeB64 = string("state_envelope_b64")?.takeIf { validB64(it, 1, MAX_STATE_BYTES) } ?: return null,
            roster = roster
        )
    }

    private fun sameRoster(left: List<MlsRosterMemberWire>, right: List<MlsRosterMemberWire>): Boolean {
        if (left.size != right.size) return false
        return left.all { member ->
            right.firstOrNull { it.username.equals(member.username, ignoreCase = true) }
                ?.stableIdentityB64 == member.stableIdentityB64
        }
    }

    private fun JSONObject.policy(): MlsRoomPolicyWire? {
        val timer = listOf("self_destruct_timer_sec", "overall_expiry_sec", "image_read_timer_sec", "image_overall_expiry_sec", "video_read_timer_sec", "video_overall_expiry_sec", "file_read_timer_sec", "file_overall_expiry_sec")
        val flags = listOf("allow_images", "allow_videos", "allow_files", "enforce_text_absolute_expiry", "enforce_image_absolute_expiry", "enforce_video_absolute_expiry", "enforce_file_absolute_expiry")
        if (!exact(*(timer + flags).toTypedArray())) return null
        val values = timer.map { canonicalU64(opt(it))?.takeIf { value -> value <= 86_400uL } ?: return null }
        val bools = flags.map { opt(it) as? Boolean ?: return null }
        return MlsRoomPolicyWire(values[0], values[1], bools[0], bools[1], bools[2], bools[3], values[2], values[3], bools[4], values[4], values[5], bools[5], values[6], values[7], bools[6])
    }

    private fun JSONObject.exact(vararg keys: String): Boolean = keys().asSequence().toSet() == keys.toSet()
    private fun JSONObject.string(key: String): String? = if (has(key) && !isNull(key)) opt(key) as? String else null
    private fun validId(v: JSONObject, key: String) = v.string(key)?.let(id::matches) == true
    private fun validB64Field(v: JSONObject, key: String, min: Int, max: Int) = v.string(key)?.let { validB64(it, min, max) } == true
    private fun validB64(value: String, min: Int, max: Int): Boolean {
        if (!b64.matches(value) || value.length > ((max + 2) / 3) * 4) return false
        val bytes = runCatching { decode(value) }.getOrNull() ?: return false
        return try { bytes.size in min..max } finally { bytes.fill(0) }
    }
}

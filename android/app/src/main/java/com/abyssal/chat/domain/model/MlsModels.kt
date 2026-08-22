package com.abyssal.chat.domain.model

import org.json.JSONObject

const val MLS_PROTOCOL_VERSION = 10

data class MlsRosterMemberWire(val username: String, val stableIdentityB64: String)

data class MlsRoomPolicyWire(
    val selfDestructTimerSec: ULong,
    val overallExpirySec: ULong,
    val allowImages: Boolean,
    val allowVideos: Boolean,
    val allowFiles: Boolean,
    val enforceTextAbsoluteExpiry: Boolean,
    val imageReadTimerSec: ULong,
    val imageOverallExpirySec: ULong,
    val enforceImageAbsoluteExpiry: Boolean,
    val videoReadTimerSec: ULong,
    val videoOverallExpirySec: ULong,
    val enforceVideoAbsoluteExpiry: Boolean,
    val fileReadTimerSec: ULong,
    val fileOverallExpirySec: ULong,
    val enforceFileAbsoluteExpiry: Boolean
)

data class MlsRecoverySnapshotWire(
    val active: Boolean,
    val epoch: ULong,
    val revision: ULong,
    val membershipDigestB64: String,
    val stateEnvelopeB64: String,
    val roster: List<MlsRosterMemberWire>
)

data class MlsRoomWire(
    val roomId: String,
    val ownerUsername: String,
    val groupIdB64: String,
    val active: Boolean,
    val epoch: ULong,
    val revision: ULong,
    val membershipDigestB64: String,
    val roster: List<MlsRosterMemberWire>,
    val recoverySnapshot: MlsRecoverySnapshotWire?,
    val policy: MlsRoomPolicyWire,
    val synchronized: Boolean
)

sealed interface MlsIncomingFrame {
    data class Rooms(val rooms: List<MlsRoomWire>) : MlsIncomingFrame
    data class RoomCreated(val room: MlsRoomWire) : MlsIncomingFrame
    data class RoomDiscovered(val roomId: String, val groupIdB64: String, val ownerUsername: String) : MlsIncomingFrame
    data class JoinRequested(
        val roomId: String,
        val requestId: String,
        val username: String,
        val stableIdentityB64: String,
        val keyPackageB64: String
    ) : MlsIncomingFrame
    data class JoinRejected(val roomId: String, val requestId: String) : MlsIncomingFrame
    data class LeaveRequested(
        val roomId: String,
        val requestId: String,
        val username: String,
        val stableIdentityB64: String
    ) : MlsIncomingFrame
    data class LeavePending(val roomId: String, val requestId: String) : MlsIncomingFrame
    data class LeaveRejected(val roomId: String, val requestId: String) : MlsIncomingFrame
    data class Left(val roomId: String) : MlsIncomingFrame
    data class Membership(
        val roomId: String,
        val messageId: String,
        val fromEpoch: ULong,
        val toEpoch: ULong,
        val revision: ULong,
        val fromMembershipDigestB64: String,
        val groupIdB64: String,
        val membershipDigestB64: String,
        val roster: List<MlsRosterMemberWire>,
        val controlB64: String,
        val welcomeB64: String,
        val authenticatedDataB64: String
    ) : MlsIncomingFrame
    data class Application(
        val roomId: String,
        val messageId: String,
        val senderUsername: String,
        val epoch: ULong,
        val revision: ULong,
        val membershipDigestB64: String,
        val ciphertextB64: String,
        val authenticatedDataB64: String
    ) : MlsIncomingFrame
    data class RoomResult(
        val roomId: String,
        val messageId: String,
        val revision: ULong,
        val accepted: Boolean,
        val snapshot: Boolean
    ) : MlsIncomingFrame
    data class RoomDeleted(val roomId: String) : MlsIncomingFrame
}

data class MlsInboundEnvelope(val generation: Long, val frame: MlsIncomingFrame)

data class PendingMlsJoinSummary(val roomId: String, val requestId: String, val username: String)
data class PendingMlsLeaveSummary(val roomId: String, val requestId: String, val username: String)

enum class MlsTransactionKind {
    APPLICATION,
    JOIN,
    LEAVE
}

data class PreparedMlsTransaction(
    val roomId: String,
    val messageId: String,
    val revision: ULong,
    val frame: JSONObject,
    val requestId: String? = null,
    val kind: MlsTransactionKind = MlsTransactionKind.APPLICATION
)

data class PreparedMlsSnapshot(
    val roomId: String,
    val messageId: String,
    val revision: ULong,
    val frame: JSONObject,
    val nativePending: Boolean
)

data class DecryptedMlsApplication(val plaintext: ByteArray, val snapshot: PreparedMlsSnapshot)

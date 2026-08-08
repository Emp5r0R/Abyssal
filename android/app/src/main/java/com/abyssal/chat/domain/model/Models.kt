package com.abyssal.chat.domain.model

data class User(
    val username: String,
    val publicKey: ByteArray,
    val prekeyId: String = ""
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is User) return false
        return username == other.username &&
            prekeyId == other.prekeyId &&
            publicKey.contentEquals(other.publicKey)
    }

    override fun hashCode(): Int {
        var result = username.hashCode()
        result = 31 * result + publicKey.contentHashCode()
        result = 31 * result + prekeyId.hashCode()
        return result
    }
}

data class Message(
    val id: String,
    val sender: String,
    val receiver: String?, // Null indicates Public Forum
    val content: String,   // Plaintext (Decrypted at Domain/Presentation boundary)
    val timestampMs: Long,
    val selfDestructDurationSec: Int,
    val readTimestampMs: Long? = null,
    val isMedia: Boolean = false,
    val mediaType: String? = null, // "IMAGE", "VIDEO", "FILE"
    val mediaSizeMb: Int = 0,
    val attachmentId: String? = null,
    val attachmentCipherVersion: Int = 0,
    val attachmentKey: ByteArray? = null,
    val attachmentName: String? = null,
    val attachmentMimeType: String? = null,
    val attachmentSizeBytes: Long = 0L,
    val oneTimeView: Boolean = false,
    val saveAllowed: Boolean = true,
    val deleteAfterDownload: Boolean = false,
    val absoluteExpirySec: Int = 0,
    val replyToMessageId: String? = null,
    val reactionShortcode: String? = null,
    val mentionsCurrentUser: Boolean = false,
    val repliesToCurrentUser: Boolean = false,
    val senderPublicKey: ByteArray? = null
) {
    val isExpired: Boolean
        get() {
            val now = System.currentTimeMillis()
            val absoluteExpired = absoluteExpirySec > 0 &&
                now - timestampMs >= absoluteExpirySec * 1000L
            val readExpired = readTimestampMs?.takeIf { selfDestructDurationSec > 0 }?.let { readAt ->
                now - readAt >= selfDestructDurationSec * 1000L
            } ?: false
            return absoluteExpired || readExpired
        }

    val timeRemainingMs: Long
        get() = readTimestampMs?.takeIf { selfDestructDurationSec > 0 }?.let {
            val limit = selfDestructDurationSec * 1000L
            val elapsed = System.currentTimeMillis() - it
            (limit - elapsed).coerceAtLeast(0)
        } ?: if (selfDestructDurationSec > 0) selfDestructDurationSec * 1000L else Long.MAX_VALUE
}

data class ChatSession(
    val id: String,
    val name: String,
    val isForum: Boolean,
    val lastMessage: Message?,
    val unreadCount: Int,
    val selfDestructTimerSec: Int, // Read self-destruct timer
    val overallExpirySec: Int = 0, // Time-based self-destruct (regardless of read or not)
    val allowImages: Boolean = true,
    val allowVideos: Boolean = true,
    val allowFiles: Boolean = true,
    val enforceTextAbsoluteExpiry: Boolean = false,
    val imageReadTimerSec: Int = 5,
    val imageOverallExpirySec: Int = 0,
    val enforceImageAbsoluteExpiry: Boolean = false,
    val videoReadTimerSec: Int = 5,
    val videoOverallExpirySec: Int = 0,
    val enforceVideoAbsoluteExpiry: Boolean = false,
    val fileReadTimerSec: Int = 5,
    val fileOverallExpirySec: Int = 0,
    val enforceFileAbsoluteExpiry: Boolean = false,
    val ownerUsername: String? = null
)

data class ServerStatus(
    val state: String, // "CONNECTED", "RE-ROUTING", "DISCONNECTED", "WIPING"
    val nodeId: String,
    val latencyMs: Int
)

data class NodeEndpoint(
    val inputUrl: String,
    val apiBaseUrl: String,
    val wsBaseUrl: String,
    val displayHost: String
)

data class NodeSession(
    val endpoint: NodeEndpoint,
    val token: String,
    val nodeId: String,
    val maxRoomsPerUser: Int
)

data class IdentityValidationResult(
    val accepted: Boolean,
    val created: Boolean = false,
    val token: String? = null,
    val nodeId: String? = null,
    val username: String? = null,
    val maxRoomsPerUser: Int = 5,
    val sessionInactivitySec: Int = 15 * 60,
    val publicKey: ByteArray? = null,
    val prekeyId: String? = null,
    val error: String? = null
)

data class AvailableAppUpdate(
    val versionName: String,
    val apkDownloadUrl: String,
    val releasePageUrl: String
)

data class SessionSecurityState(
    val active: Boolean = false,
    val retainedInBackground: Boolean = false,
    val inactivityTimeoutSec: Int = 15 * 60,
    val remainingSec: Int = 0
)

data class IncomingTransportPayload(
    val chatId: String,
    val messageId: String,
    val version: Int,
    val identityPublicKey: ByteArray,
    val nonce: ByteArray,
    val ciphertext: ByteArray,
    val signature: ByteArray,
    val wrappedKey: ByteArray,
    val senderUsername: String,
    val senderPublicKey: ByteArray,
    val prekeyId: String = "",
    val isPrekey: Boolean = false
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is IncomingTransportPayload) return false
        return chatId == other.chatId &&
            messageId == other.messageId &&
            senderUsername == other.senderUsername &&
            version == other.version &&
            identityPublicKey.contentEquals(other.identityPublicKey) &&
            nonce.contentEquals(other.nonce) &&
            ciphertext.contentEquals(other.ciphertext) &&
            signature.contentEquals(other.signature) &&
            wrappedKey.contentEquals(other.wrappedKey) &&
            senderPublicKey.contentEquals(other.senderPublicKey) &&
            prekeyId == other.prekeyId &&
            isPrekey == other.isPrekey
    }

    override fun hashCode(): Int {
        var result = chatId.hashCode()
        result = 31 * result + messageId.hashCode()
        result = 31 * result + version
        result = 31 * result + identityPublicKey.contentHashCode()
        result = 31 * result + nonce.contentHashCode()
        result = 31 * result + ciphertext.contentHashCode()
        result = 31 * result + signature.contentHashCode()
        result = 31 * result + wrappedKey.contentHashCode()
        result = 31 * result + senderUsername.hashCode()
        result = 31 * result + senderPublicKey.contentHashCode()
        result = 31 * result + prekeyId.hashCode()
        result = 31 * result + isPrekey.hashCode()
        return result
    }
}

data class RecipientEnvelope(
    val recipientUsername: String,
    val wrappedKey: ByteArray,
    val prekeyId: String = "",
    val isPrekey: Boolean = false,
    val signature: ByteArray = ByteArray(0)
)

data class EncryptedTransportPayload(
    val version: Int,
    val messageId: String,
    val nonce: ByteArray,
    val ciphertext: ByteArray,
    val envelopes: List<RecipientEnvelope>,
    val stateRevision: ULong,
    val identityEnvelope: ByteArray,
    val identityPublicKey: ByteArray = ByteArray(0),
    val prekeyId: String = ""
)

data class IdentityStateSnapshot(
    val revision: ULong,
    val envelope: ByteArray,
    val identityPublicKey: ByteArray = ByteArray(0),
    val prekeyId: String = ""
)

data class RecipientIdentity(
    val username: String,
    val publicKey: ByteArray,
    val prekeyId: String = ""
)

data class RoomChange(
    val action: String,
    val session: ChatSession? = null,
    val chatId: String? = null
)

data class DisguiseSettings(
    val isDisguised: Boolean = false,
    val pin: String = "",
    val duressPin: String = ""
)

data class UserPresence(
    val username: String,
    val connected: Boolean,
    val publicKey: ByteArray,
    val prekeyId: String = "",
    val directoryDigest: String = ""
)

data class AttachmentUploadResult(
    val accepted: Boolean,
    val attachmentId: String? = null
)

data class EncryptedAttachmentDownload(
    val bytes: ByteArray,
    val claim: String? = null
)

data class AttachmentUploadProgress(
    val active: Boolean = false,
    val fileName: String = "",
    val mediaType: String = "FILE",
    val bytesSent: Long = 0L,
    val totalBytes: Long = 0L
) {
    val fraction: Float
        get() = if (totalBytes <= 0L) 0f else (bytesSent.toFloat() / totalBytes.toFloat()).coerceIn(0f, 1f)
}

data class DecryptedAttachment(
    val messageId: String,
    val name: String,
    val mediaType: String,
    val mimeType: String,
    val bytes: ByteArray,
    val oneTimeView: Boolean
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is DecryptedAttachment) return false
        return messageId == other.messageId &&
            name == other.name &&
            mediaType == other.mediaType &&
            mimeType == other.mimeType &&
            bytes.contentEquals(other.bytes) &&
            oneTimeView == other.oneTimeView
    }

    override fun hashCode(): Int {
        var result = messageId.hashCode()
        result = 31 * result + name.hashCode()
        result = 31 * result + mediaType.hashCode()
        result = 31 * result + mimeType.hashCode()
        result = 31 * result + bytes.contentHashCode()
        result = 31 * result + oneTimeView.hashCode()
        return result
    }
}

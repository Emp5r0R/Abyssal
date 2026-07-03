package com.abyssal.chat.domain.model

data class User(
    val username: String,
    val publicKey: ByteArray,
    val isAdmin: Boolean = false
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is User) return false
        return username == other.username && publicKey.contentEquals(other.publicKey)
    }

    override fun hashCode(): Int {
        var result = username.hashCode()
        result = 31 * result + publicKey.contentHashCode()
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
    val attachmentName: String? = null,
    val attachmentMimeType: String? = null,
    val attachmentSizeBytes: Long = 0L,
    val oneTimeView: Boolean = false,
    val saveAllowed: Boolean = true,
    val deleteAfterDownload: Boolean = false,
    val absoluteExpirySec: Int = 0
) {
    val isExpired: Boolean
        get() = readTimestampMs?.let {
            val elapsedMs = System.currentTimeMillis() - it
            elapsedMs >= selfDestructDurationSec * 1000L
        } ?: false

    val timeRemainingMs: Long
        get() = readTimestampMs?.let {
            val limit = selfDestructDurationSec * 1000L
            val elapsed = System.currentTimeMillis() - it
            (limit - elapsed).coerceAtLeast(0)
        } ?: (selfDestructDurationSec * 1000L)
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
    val enforceFileAbsoluteExpiry: Boolean = false
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
    val isAdmin: Boolean
)

data class IdentityValidationResult(
    val accepted: Boolean,
    val created: Boolean = false,
    val token: String? = null,
    val nodeId: String? = null,
    val username: String? = null,
    val isAdmin: Boolean = false,
    val error: String? = null
)

data class IncomingTransportPayload(
    val chatId: String,
    val payload: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is IncomingTransportPayload) return false
        return chatId == other.chatId && payload.contentEquals(other.payload)
    }

    override fun hashCode(): Int {
        var result = chatId.hashCode()
        result = 31 * result + payload.contentHashCode()
        return result
    }
}

data class RoomChange(
    val action: String,
    val session: ChatSession? = null,
    val chatId: String? = null
)

data class DisguiseSettings(
    val isDisguised: Boolean = false,
    val pin: String = "2026" // Default RAM-only unlock PIN
)

data class UserPresence(
    val username: String,
    val connected: Boolean
)

data class AttachmentUploadResult(
    val accepted: Boolean,
    val attachmentId: String? = null
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

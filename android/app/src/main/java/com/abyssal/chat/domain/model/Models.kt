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
    val mediaSizeMb: Int = 0
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
    val allowFiles: Boolean = true
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

data class DisguiseSettings(
    val isDisguised: Boolean = false,
    val pin: String = "2026" // Default RAM-only unlock PIN
)

data class UserPresence(
    val username: String,
    val connected: Boolean
)

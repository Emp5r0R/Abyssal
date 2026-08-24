package com.abyssal.chat.domain.model

data class DirectTrustContext(
    val chatId: String,
    val peerUsername: String,
    val safetyNumber: String,
    val verificationToken: String,
    val sessionGeneration: Long,
    val connectionGeneration: Long,
    val localIdentity: ByteArray,
    val peerIdentity: ByteArray
)

data class DirectTrustStatus(
    val active: Boolean = false,
    val peerUsername: String? = null,
    val safetyNumber: String? = null,
    val verificationToken: String? = null,
    val verified: Boolean = false
)

const val STABLE_IDENTITY_BYTES = 64

private data class VerifiedDirect(
    val chatId: String,
    val peerUsername: String,
    val safetyNumber: String,
    val verificationToken: String,
    val sessionGeneration: Long,
    val connectionGeneration: Long,
    val localIdentity: ByteArray,
    val peerIdentity: ByteArray
)

/** RAM-only direct-chat trust bound to stable identity fingerprints and socket epoch. */
class DirectChatTrustStore {
    companion object {
        const val MAX_PEERS = 128
    }

    private val verified = LinkedHashMap<String, VerifiedDirect>()

    @Synchronized
    fun markVerified(context: DirectTrustContext, presentedToken: String): Boolean {
        if (context.chatId.isBlank() || context.peerUsername.isBlank() ||
            context.safetyNumber.isBlank() || context.verificationToken.isBlank() ||
            presentedToken != context.verificationToken ||
            context.sessionGeneration < 0L || context.connectionGeneration < 0L ||
            context.localIdentity.size < STABLE_IDENTITY_BYTES ||
            context.peerIdentity.size < STABLE_IDENTITY_BYTES
        ) return false
        val key = trustKey(context)
        verified.remove(key)?.let(::wipeVerified)
        while (verified.size >= MAX_PEERS) {
            val oldest = verified.entries.firstOrNull() ?: break
            verified.remove(oldest.key)
            wipeVerified(oldest.value)
        }
        verified[key] = VerifiedDirect(
            chatId = context.chatId,
            peerUsername = context.peerUsername,
            safetyNumber = context.safetyNumber,
            verificationToken = context.verificationToken,
            sessionGeneration = context.sessionGeneration,
            connectionGeneration = context.connectionGeneration,
            localIdentity = context.localIdentity.copyOfRange(0, STABLE_IDENTITY_BYTES),
            peerIdentity = context.peerIdentity.copyOfRange(0, STABLE_IDENTITY_BYTES)
        )
        return true
    }

    @Synchronized
    fun isVerified(context: DirectTrustContext?): Boolean {
        val candidate = context?.let { verified[trustKey(it)] } ?: return false
        return candidate.chatId == context.chatId &&
            candidate.peerUsername == context.peerUsername &&
            candidate.safetyNumber == context.safetyNumber &&
            candidate.verificationToken == context.verificationToken &&
            candidate.sessionGeneration == context.sessionGeneration &&
            candidate.connectionGeneration == context.connectionGeneration &&
            context.localIdentity.size >= STABLE_IDENTITY_BYTES &&
            context.peerIdentity.size >= STABLE_IDENTITY_BYTES &&
            equalBytes(candidate.localIdentity, context.localIdentity, STABLE_IDENTITY_BYTES) &&
            equalBytes(candidate.peerIdentity, context.peerIdentity, STABLE_IDENTITY_BYTES)
    }

    @Synchronized
    fun invalidateIfIdentityChanged(context: DirectTrustContext?) {
        if (context == null || context.localIdentity.size < STABLE_IDENTITY_BYTES ||
            context.peerIdentity.size < STABLE_IDENTITY_BYTES
        ) return
        val key = trustKey(context)
        val candidate = verified[key] ?: return
        if (!equalBytes(candidate.localIdentity, context.localIdentity, STABLE_IDENTITY_BYTES) ||
            !equalBytes(candidate.peerIdentity, context.peerIdentity, STABLE_IDENTITY_BYTES)
        ) {
            verified.remove(key)
            wipeVerified(candidate)
        }
    }

    @Synchronized
    fun status(context: DirectTrustContext?): DirectTrustStatus = if (context == null) {
        DirectTrustStatus()
    } else {
        DirectTrustStatus(
            active = true,
            peerUsername = context.peerUsername,
            safetyNumber = context.safetyNumber,
            verificationToken = context.verificationToken,
            verified = isVerified(context)
        )
    }

    @Synchronized
    fun clear() {
        verified.values.forEach(::wipeVerified)
        verified.clear()
    }

    private fun trustKey(context: DirectTrustContext): String =
        "${context.chatId}\u0000${context.peerUsername.lowercase()}"

    private fun wipeVerified(value: VerifiedDirect) {
        value.localIdentity.fill(0)
        value.peerIdentity.fill(0)
    }

    private fun equalBytes(left: ByteArray, right: ByteArray, count: Int): Boolean {
        if (left.size < count || right.size < count) return false
        var difference = 0
        repeat(count) { index -> difference = difference or (left[index].toInt() xor right[index].toInt()) }
        return difference == 0
    }
}

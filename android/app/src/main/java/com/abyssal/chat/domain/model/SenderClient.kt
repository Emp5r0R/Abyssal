package com.abyssal.chat.domain.model

/**
 * Sender-client origin disclosure carried inside authenticated, encrypted
 * message payloads. The relay only ever sees ciphertext, so it cannot forge,
 * strip, or observe this tag. It is a claim asserted by the sending client
 * build rather than an attestation: receivers treat it as advisory context
 * and fail closed when it is missing or unknown.
 */
enum class SenderClient(val wireName: String) {
    ANDROID("android"),
    WEB("web");

    companion object {
        /** Strict allowlist lookup; null for missing, mistyped, or unknown values. */
        fun fromWire(value: String?): SenderClient? = entries.firstOrNull { it.wireName == value }
    }

    /** Advisory text shown next to a received message on this device. */
    fun originNotice(): String = when (this) {
        WEB -> "Sent from the web client: that device may lack screenshot protection, and its browser cannot guarantee memory wiping."
        ANDROID -> "Sent from the Android app: the sending device enforces screen-capture and memory protections."
    }
}

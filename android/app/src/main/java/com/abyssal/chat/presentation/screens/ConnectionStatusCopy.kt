package com.abyssal.chat.presentation.screens

/**
 * User-facing copy for transport states. Keeps raw transport identifiers out of
 * the UI and matches the web client's LIVE/OFFLINE wording.
 */
internal object ConnectionStatusCopy {
    fun isLive(state: String): Boolean = state == "CONNECTED"

    fun pillLabel(state: String): String = when (state) {
        "CONNECTED" -> "LIVE"
        "CONNECTING" -> "CONNECTING"
        "SECURITY_REJECTED" -> "UPDATE REQUIRED"
        else -> "OFFLINE"
    }

    fun composerPlaceholder(state: String): String = when (state) {
        "CONNECTED" -> "Message"
        "SECURITY_REJECTED" -> "Update the app to reconnect"
        else -> "Reconnecting"
    }

    /** Explains a rejected build; null for states that recover automatically. */
    fun rejectionNotice(state: String): String? =
        if (state == "SECURITY_REJECTED") {
            "This node only admits the current signed release. Update Abyssal to reconnect."
        } else {
            null
        }
}

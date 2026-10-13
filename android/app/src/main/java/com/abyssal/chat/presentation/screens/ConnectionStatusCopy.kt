package com.abyssal.chat.presentation.screens

/**
 * User-facing copy for transport states. Keeps raw transport identifiers out of
 * the UI and matches the web client's wording.
 */
internal object ConnectionStatusCopy {
    fun isLive(state: String): Boolean = state == "CONNECTED"

    fun statusLabel(state: String): String = when (state) {
        "CONNECTED" -> "Connected"
        "CONNECTING" -> "Connecting"
        "SECURITY_REJECTED" -> "Update required"
        "PLATFORM_CONFLICT" -> "Web account"
        "SESSION_EXPIRED" -> "Signed out"
        else -> "Offline"
    }

    fun composerPlaceholder(state: String): String = when (state) {
        "CONNECTED" -> "Write a message"
        "SECURITY_REJECTED" -> "Update the app to reconnect"
        "PLATFORM_CONFLICT" -> "This account belongs to the web app"
        "SESSION_EXPIRED" -> "Sign in again"
        else -> "Reconnecting"
    }

    /** Explains a terminal state; null for states that recover automatically. */
    fun rejectionNotice(state: String): String? = when (state) {
        "SECURITY_REJECTED" ->
            "This node only admits the current signed release. Update Abyssal to reconnect."
        "PLATFORM_CONFLICT" ->
            "This account was first used in the web app. Each account works on one platform; use a new invite to create an Android account."
        else -> null
    }
}

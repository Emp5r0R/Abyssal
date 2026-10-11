package com.abyssal.chat.domain.model

/** What happens to the session when Abyssal leaves the foreground. */
enum class BackgroundAction {
    /** Lock behind the calculator when the cover is on; otherwise keep the session. */
    LOCK,
    SIGN_OUT,
    STAY
}

/** How much a message notification reveals, from nothing to a text preview. */
enum class NotificationLevel { OFF, PRIVATE, SENDER, PREVIEW }

enum class BackgroundResponse { LOCK, SIGN_OUT, NONE }

/**
 * In-memory display and privacy preferences, matching the web client's Settings.
 * Nothing here is written to disk.
 */
data class WorkspacePreferences(
    val blurEnabled: Boolean = false,
    val backgroundAction: BackgroundAction = BackgroundAction.LOCK,
    val notificationLevel: NotificationLevel = NotificationLevel.OFF
)

data class NotificationContent(val title: String, val body: String)

object WorkspacePreferencePolicy {
    private const val PREVIEW_LENGTH = 120

    /** The sign-in "keep session" choice expressed as a background action. */
    fun fromSignInChoice(keepSession: Boolean): BackgroundAction =
        if (keepSession) BackgroundAction.LOCK else BackgroundAction.SIGN_OUT

    fun backgroundResponse(action: BackgroundAction, disguised: Boolean): BackgroundResponse = when (action) {
        BackgroundAction.LOCK -> if (disguised) BackgroundResponse.LOCK else BackgroundResponse.NONE
        BackgroundAction.SIGN_OUT -> BackgroundResponse.SIGN_OUT
        BackgroundAction.STAY -> BackgroundResponse.NONE
    }

    /** Whether a stored incoming message raises a notification. */
    fun shouldNotify(
        level: NotificationLevel,
        mine: Boolean,
        locked: Boolean,
        appInForeground: Boolean,
        messageChatId: String,
        activeChatId: String?
    ): Boolean {
        if (level == NotificationLevel.OFF || mine || locked) return false
        // A conversation already on screen is being read.
        return !appInForeground || messageChatId != activeChatId
    }

    /**
     * What the notification says. [conversation] names a room, or is null for a
     * direct chat; [sender] is the sender's display label.
     */
    fun content(level: NotificationLevel, message: Message, sender: String, conversation: String?): NotificationContent {
        require(level != NotificationLevel.OFF)
        if (level == NotificationLevel.PRIVATE) return NotificationContent("Abyssal", "New message")
        val title = if (conversation != null) "$sender in $conversation" else sender
        if (level == NotificationLevel.SENDER) return NotificationContent(title, "New message")
        return NotificationContent(title, preview(message))
    }

    private fun preview(message: Message): String {
        message.reactionShortcode?.let { return "Reacted $it" }
        if (message.isMedia) {
            return when (message.mediaType) {
                "IMAGE" -> "Sent a photo"
                "VIDEO" -> "Sent a video"
                else -> "Sent a file"
            }
        }
        val text = message.content.replace(Regex("\\s+"), " ").trim()
        if (text.isEmpty()) return "New message"
        return if (text.length > PREVIEW_LENGTH) text.take(PREVIEW_LENGTH - 1) + "…" else text
    }
}

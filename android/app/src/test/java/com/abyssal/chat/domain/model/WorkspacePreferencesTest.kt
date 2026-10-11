package com.abyssal.chat.domain.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class WorkspacePreferencesTest {
    private fun message(content: String = "Meet at   the usual place", mediaType: String? = null, reaction: String? = null) = Message(
        id = "m1",
        sender = "acct_peer",
        receiver = "me",
        content = content,
        timestampMs = 1L,
        selfDestructDurationSec = 0,
        isMedia = mediaType != null,
        mediaType = mediaType,
        reactionShortcode = reaction
    )

    @Test fun defaultsAreBlurOffLockAndNoNotifications() {
        assertEquals(WorkspacePreferences(false, BackgroundAction.LOCK, NotificationLevel.OFF), WorkspacePreferences())
    }

    @Test fun backgroundActionsKeepTheExistingSignInBehaviour() {
        assertEquals(BackgroundAction.LOCK, WorkspacePreferencePolicy.fromSignInChoice(true))
        assertEquals(BackgroundAction.SIGN_OUT, WorkspacePreferencePolicy.fromSignInChoice(false))
        assertEquals(BackgroundResponse.LOCK, WorkspacePreferencePolicy.backgroundResponse(BackgroundAction.LOCK, disguised = true))
        assertEquals(BackgroundResponse.NONE, WorkspacePreferencePolicy.backgroundResponse(BackgroundAction.LOCK, disguised = false))
        assertEquals(BackgroundResponse.SIGN_OUT, WorkspacePreferencePolicy.backgroundResponse(BackgroundAction.SIGN_OUT, disguised = true))
        assertEquals(BackgroundResponse.NONE, WorkspacePreferencePolicy.backgroundResponse(BackgroundAction.STAY, disguised = true))
    }

    @Test fun notifiesOnlyAboutOthersMessagesThatAreNotOnScreen() {
        fun notify(level: NotificationLevel = NotificationLevel.SENDER, mine: Boolean = false, locked: Boolean = false, foreground: Boolean = true, active: String? = "dm_2") =
            WorkspacePreferencePolicy.shouldNotify(level, mine, locked, foreground, "dm_1", active)
        assertTrue(notify())
        assertTrue(notify(active = "dm_1", foreground = false))
        assertFalse(notify(active = "dm_1"))
        assertFalse(notify(level = NotificationLevel.OFF))
        assertFalse(notify(mine = true))
        assertFalse(notify(locked = true, foreground = false))
    }

    @Test fun eachLevelRevealsLess() {
        val policy = WorkspacePreferencePolicy
        assertEquals(NotificationContent("Abyssal", "New message"), policy.content(NotificationLevel.PRIVATE, message(), "Silver", "Ops"))
        assertEquals(NotificationContent("Silver in Ops", "New message"), policy.content(NotificationLevel.SENDER, message(), "Silver", "Ops"))
        assertEquals(NotificationContent("Silver", "Meet at the usual place"), policy.content(NotificationLevel.PREVIEW, message(), "Silver", null))
        assertEquals("Sent a photo", policy.content(NotificationLevel.PREVIEW, message(mediaType = "IMAGE"), "S", null).body)
        assertEquals("Sent a video", policy.content(NotificationLevel.PREVIEW, message(mediaType = "VIDEO"), "S", null).body)
        assertEquals("Sent a file", policy.content(NotificationLevel.PREVIEW, message(mediaType = "FILE"), "S", null).body)
        assertEquals("Reacted :fire:", policy.content(NotificationLevel.PREVIEW, message(mediaType = "IMAGE", reaction = ":fire:"), "S", null).body)
        val long = policy.content(NotificationLevel.PREVIEW, message(content = "x".repeat(500)), "S", null).body
        assertEquals(120, long.length)
        assertTrue(long.endsWith("…"))
    }
}

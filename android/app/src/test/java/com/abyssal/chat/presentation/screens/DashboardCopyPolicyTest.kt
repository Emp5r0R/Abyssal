package com.abyssal.chat.presentation.screens

import com.abyssal.chat.domain.model.ChatSession
import org.junit.Assert.assertEquals
import org.junit.Test

class DashboardCopyPolicyTest {
    @Test
    fun roomActionsKeepTargetIdentityForOwnersAndMembers() {
        assertEquals("Delete room operations", roomActionContentDescription(isOwner = true, roomName = "operations"))
        assertEquals("Leave room operations", roomActionContentDescription(isOwner = false, roomName = "operations"))
    }

    @Test
    fun presenceLabelsIdentifyTheCurrentUserAndConnectionState() {
        assertEquals("YOU · ONLINE", presenceStatusLabel(isCurrentUser = true, connected = true))
        assertEquals("YOU · OFFLINE", presenceStatusLabel(isCurrentUser = true, connected = false))
        assertEquals("ONLINE", presenceStatusLabel(isCurrentUser = false, connected = true))
        assertEquals("OFFLINE", presenceStatusLabel(isCurrentUser = false, connected = false))
    }

    @Test
    fun retentionUsesOverallExpiryBeforeReadExpiryAndRendersZeroAsNever() {
        assertEquals("20s", session(readExpiry = 5, overallExpiry = 20, enforceAbsolute = true).retentionSecondsLabel())
        assertEquals("5s", session(readExpiry = 5, overallExpiry = 20).retentionSecondsLabel())
        assertEquals("5s", session(readExpiry = 5, overallExpiry = 0).retentionSecondsLabel())
        assertEquals("Never", session(readExpiry = 0, overallExpiry = 0).retentionSecondsLabel())
    }

    private fun session(readExpiry: Int, overallExpiry: Int, enforceAbsolute: Boolean = false) = ChatSession(
        id = "room",
        name = "operations",
        isForum = true,
        lastMessage = null,
        unreadCount = 0,
        selfDestructTimerSec = readExpiry,
        overallExpirySec = overallExpiry,
        enforceTextAbsoluteExpiry = enforceAbsolute
    )
}

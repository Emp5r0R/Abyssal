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
        assertEquals("You · Online", presenceStatusLabel(isCurrentUser = true, connected = true))
        assertEquals("You · Offline", presenceStatusLabel(isCurrentUser = true, connected = false))
        assertEquals("Online", presenceStatusLabel(isCurrentUser = false, connected = true))
        assertEquals("Offline", presenceStatusLabel(isCurrentUser = false, connected = false))
    }

    @Test
    fun retentionUsesOverallExpiryBeforeReadExpiryAndRendersZeroAsNever() {
        assertEquals("20s", session(readExpiry = 5, overallExpiry = 20, enforceAbsolute = true).retentionSecondsLabel())
        assertEquals("5s", session(readExpiry = 5, overallExpiry = 20).retentionSecondsLabel())
        assertEquals("5s", session(readExpiry = 5, overallExpiry = 0).retentionSecondsLabel())
        assertEquals("Never", session(readExpiry = 0, overallExpiry = 0).retentionSecondsLabel())
    }

    @Test
    fun durationsUseTheLargestExactUnit() {
        assertEquals("45s", durationLabel(45))
        assertEquals("90s", durationLabel(90))
        assertEquals("5m", durationLabel(300))
        assertEquals("2h", durationLabel(7_200))
        assertEquals("1d", durationLabel(86_400))
    }

    @Test
    fun conversationPreviewsNameMediaAndMarkOwnMessages() {
        val base = com.abyssal.chat.domain.model.Message("m", "acct_1", null, "first line\nsecond", 0L, 5)
        assertEquals("first line", conversationPreview(base))
        assertEquals("You: first line", conversationPreview(base.copy(sender = "You")))
        assertEquals("Photo · cat.jpg", conversationPreview(base.copy(isMedia = true, mediaType = "IMAGE", attachmentName = "cat.jpg")))
        assertEquals("GIF :wave:", conversationPreview(base.copy(isMedia = true, mediaType = "IMAGE", reactionShortcode = ":wave:")))
        assertEquals("One-time media", conversationPreview(base.copy(isMedia = true, oneTimeView = true)))
    }

    @Test
    fun previewsShowTheReadersOwnMentionAsYou() {
        val me = "acct_1ede2b0e83c042fea28590d0c4444ff3"
        assertEquals("@you hi, @you", mentionsAsYou("@$me hi, @$me", me))
        assertEquals("@acct_other hi", mentionsAsYou("@acct_other hi", me))
        assertEquals("plain", mentionsAsYou("plain", null))
        val message = com.abyssal.chat.domain.model.Message("m", "acct_1", null, "@$me look", 0L, 5)
        assertEquals("@you look", conversationPreview(message, me))
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

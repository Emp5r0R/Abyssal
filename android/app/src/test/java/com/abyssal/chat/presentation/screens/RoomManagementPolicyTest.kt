package com.abyssal.chat.presentation.screens

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RoomManagementPolicyTest {
    @Test
    fun membersListOwnerFirstThenYouThenOthersByName() {
        val members = listOf("acct_cccccccccccc", "acct_bbbbbbbbbbbb", "acct_aaaaaaaaaaaa", "acct_dddddddddddd")
        val sorted = sortedRoomMembers(
            members,
            ownerUsername = "ACCT_DDDDDDDDDDDD",
            currentUsername = "acct_cccccccccccc",
            displayNames = mapOf("acct_bbbbbbbbbbbb" to "Alice", "acct_aaaaaaaaaaaa" to "Zed")
        )
        assertEquals(listOf("acct_dddddddddddd", "acct_cccccccccccc", "acct_bbbbbbbbbbbb", "acct_aaaaaaaaaaaa"), sorted)
    }

    @Test
    fun roomNamesFollowTheEncryptedProfileRules() {
        assertTrue(validRoomName("Weekend plans"))
        assertTrue(validRoomName("  padded  "))
        assertTrue(validRoomName("x".repeat(MAX_ROOM_NAME)))
        assertFalse(validRoomName("   "))
        assertFalse(validRoomName("x".repeat(MAX_ROOM_NAME + 1)))
        assertFalse(validRoomName("bad\u0000name"))
    }
}

class RoomDraftTimerTest {
    @Test
    fun mediaTimersFollowTheMainTimerUnlessChangedSeparately() {
        val draft = RoomDraft(videos = MediaRuleDraft(readSec = "30")).withReadSec("0")
        assertEquals("0", draft.readSec)
        assertEquals("0", draft.images.readSec)
        assertEquals("0", draft.files.readSec)
        assertEquals("30", draft.videos.readSec)
    }
}

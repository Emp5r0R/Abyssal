package com.abyssal.chat.presentation.screens

import com.abyssal.chat.domain.model.ChatSession
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class DashboardRoomPolicyTest {
    @Test
    fun noEnabledAttachmentMediaFallsBackToTextAndNeverTimers() {
        assertEquals(
            "Text only · stays until the session ends",
            room(allowImages = false, allowVideos = false, allowFiles = false).roomPolicySummary()
        )
    }

    @Test
    fun someEnabledAttachmentMediaListsOnlyThoseTypesAndReadRetention() {
        assertEquals(
            "Text, images, files · vanish 5s after reading",
            room(allowImages = true, allowVideos = false, allowFiles = true, readExpiry = 5).roomPolicySummary()
        )
    }

    @Test
    fun allEnabledAttachmentMediaShowsEnforcedAbsoluteRetention() {
        assertEquals(
            "Text, images, videos, files · vanish 10s after reading · deleted 1m after sending",
            room(
                allowImages = true,
                allowVideos = true,
                allowFiles = true,
                readExpiry = 10,
                overallExpiry = 60,
                enforceAbsolute = true
            ).roomPolicySummary()
        )
    }

    @Test
    fun unenforcedAbsoluteValueIsNotPresentedAsActivePolicy() {
        assertEquals(
            "Text only · vanish 5s after reading",
            room(
                allowImages = false,
                allowVideos = false,
                allowFiles = false,
                readExpiry = 5,
                overallExpiry = 60
            ).roomPolicySummary()
        )
    }

    @Test
    fun directSessionsHaveNoRoomPolicySummary() {
        assertNull(room(isForum = false).roomPolicySummary())
    }

    private fun room(
        isForum: Boolean = true,
        allowImages: Boolean = false,
        allowVideos: Boolean = false,
        allowFiles: Boolean = false,
        readExpiry: Int = 0,
        overallExpiry: Int = 0,
        enforceAbsolute: Boolean = false
    ) = ChatSession(
        id = "room",
        name = "operations",
        isForum = isForum,
        lastMessage = null,
        unreadCount = 0,
        selfDestructTimerSec = readExpiry,
        overallExpirySec = overallExpiry,
        allowImages = allowImages,
        allowVideos = allowVideos,
        allowFiles = allowFiles,
        enforceTextAbsoluteExpiry = enforceAbsolute
    )
}

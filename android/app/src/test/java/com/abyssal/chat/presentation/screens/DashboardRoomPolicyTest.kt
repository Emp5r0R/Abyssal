package com.abyssal.chat.presentation.screens

import com.abyssal.chat.domain.model.ChatSession
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class DashboardRoomPolicyTest {
    @Test
    fun noEnabledAttachmentMediaFallsBackToTextAndNeverTimers() {
        assertEquals(
            "PRIVATE · TEXT · READ Never · ABS Never",
            room(allowImages = false, allowVideos = false, allowFiles = false).roomPolicySummary()
        )
    }

    @Test
    fun someEnabledAttachmentMediaListsOnlyThoseTypesAndReadRetention() {
        assertEquals(
            "PRIVATE · IMG · FILE · READ 5s · ABS Never",
            room(allowImages = true, allowVideos = false, allowFiles = true, readExpiry = 5).roomPolicySummary()
        )
    }

    @Test
    fun allEnabledAttachmentMediaShowsEnforcedAbsoluteRetention() {
        assertEquals(
            "PRIVATE · IMG · VID · FILE · READ 10s · ABS 60s",
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
            "PRIVATE · TEXT · READ 5s · ABS Never",
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

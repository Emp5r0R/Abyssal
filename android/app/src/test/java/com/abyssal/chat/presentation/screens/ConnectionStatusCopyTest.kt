package com.abyssal.chat.presentation.screens

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ConnectionStatusCopyTest {
    @Test
    fun transportStatesMapToUserFacingCopyWithoutRawIdentifiers() {
        assertEquals("LIVE", ConnectionStatusCopy.pillLabel("CONNECTED"))
        assertEquals("CONNECTING", ConnectionStatusCopy.pillLabel("CONNECTING"))
        assertEquals("OFFLINE", ConnectionStatusCopy.pillLabel("DISCONNECTED"))
        assertEquals("UPDATE REQUIRED", ConnectionStatusCopy.pillLabel("SECURITY_REJECTED"))
        assertEquals("OFFLINE", ConnectionStatusCopy.pillLabel("UNEXPECTED"))
        assertEquals("WEB ACCOUNT", ConnectionStatusCopy.pillLabel("PLATFORM_CONFLICT"))
        assertEquals("SIGNED OUT", ConnectionStatusCopy.pillLabel("SESSION_EXPIRED"))
        listOf(
            "CONNECTED", "CONNECTING", "DISCONNECTED", "SECURITY_REJECTED",
            "PLATFORM_CONFLICT", "SESSION_EXPIRED"
        ).forEach { state ->
            assertFalse(ConnectionStatusCopy.pillLabel(state).contains('_'))
            assertFalse(ConnectionStatusCopy.composerPlaceholder(state).contains('_'))
        }
    }

    @Test
    fun onlyRejectedBuildsAskForAnUpdateInsteadOfReconnecting() {
        assertTrue(ConnectionStatusCopy.isLive("CONNECTED"))
        assertFalse(ConnectionStatusCopy.isLive("CONNECTING"))
        assertEquals("Message", ConnectionStatusCopy.composerPlaceholder("CONNECTED"))
        assertEquals("Reconnecting", ConnectionStatusCopy.composerPlaceholder("DISCONNECTED"))
        assertEquals("Update the app to reconnect", ConnectionStatusCopy.composerPlaceholder("SECURITY_REJECTED"))
        assertNotNull(ConnectionStatusCopy.rejectionNotice("SECURITY_REJECTED"))
        assertNull(ConnectionStatusCopy.rejectionNotice("DISCONNECTED"))
        assertNull(ConnectionStatusCopy.rejectionNotice("CONNECTED"))
        assertTrue(
            requireNotNull(ConnectionStatusCopy.rejectionNotice("PLATFORM_CONFLICT")).contains("web app")
        )
        assertNull(ConnectionStatusCopy.rejectionNotice("SESSION_EXPIRED"))
    }
}

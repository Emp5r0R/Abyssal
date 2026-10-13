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
        assertEquals("Connected", ConnectionStatusCopy.statusLabel("CONNECTED"))
        assertEquals("Connecting", ConnectionStatusCopy.statusLabel("CONNECTING"))
        assertEquals("Offline", ConnectionStatusCopy.statusLabel("DISCONNECTED"))
        assertEquals("Update required", ConnectionStatusCopy.statusLabel("SECURITY_REJECTED"))
        assertEquals("Offline", ConnectionStatusCopy.statusLabel("UNEXPECTED"))
        assertEquals("Web account", ConnectionStatusCopy.statusLabel("PLATFORM_CONFLICT"))
        assertEquals("Signed out", ConnectionStatusCopy.statusLabel("SESSION_EXPIRED"))
        listOf(
            "CONNECTED", "CONNECTING", "DISCONNECTED", "SECURITY_REJECTED",
            "PLATFORM_CONFLICT", "SESSION_EXPIRED"
        ).forEach { state ->
            assertFalse(ConnectionStatusCopy.statusLabel(state).contains('_'))
            assertFalse(ConnectionStatusCopy.composerPlaceholder(state).contains('_'))
        }
    }

    @Test
    fun onlyRejectedBuildsAskForAnUpdateInsteadOfReconnecting() {
        assertTrue(ConnectionStatusCopy.isLive("CONNECTED"))
        assertFalse(ConnectionStatusCopy.isLive("CONNECTING"))
        assertEquals("Write a message", ConnectionStatusCopy.composerPlaceholder("CONNECTED"))
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

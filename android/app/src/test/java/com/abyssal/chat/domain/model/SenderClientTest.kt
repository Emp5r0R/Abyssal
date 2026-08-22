package com.abyssal.chat.domain.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SenderClientTest {
    @Test
    fun `accepts only exact canonical wire values`() {
        assertEquals(SenderClient.ANDROID, SenderClient.fromWire("android"))
        assertEquals(SenderClient.WEB, SenderClient.fromWire("web"))
    }

    @Test
    fun `fails closed on missing mistyped or unknown values`() {
        assertNull(SenderClient.fromWire(null))
        assertNull(SenderClient.fromWire(""))
        assertNull(SenderClient.fromWire("ANDROID"))
        assertNull(SenderClient.fromWire("Web"))
        assertNull(SenderClient.fromWire("desktop"))
        assertNull(SenderClient.fromWire(" web"))
        assertNull(SenderClient.fromWire("android "))
    }

    @Test
    fun `wire names round trip through the allowlist`() {
        SenderClient.entries.forEach { client ->
            assertEquals(client, SenderClient.fromWire(client.wireName))
        }
    }

    @Test
    fun `origin notices distinguish the weaker web environment`() {
        val web = SenderClient.WEB.originNotice()
        val android = SenderClient.ANDROID.originNotice()
        assertTrue(web.contains("web client", ignoreCase = true))
        assertTrue(web.contains("screenshot", ignoreCase = true))
        assertTrue(android.contains("Android app", ignoreCase = true))
        assertTrue(web != android)
    }
}

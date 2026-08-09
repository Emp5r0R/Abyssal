package com.abyssal.chat.data.network

import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.WebSocket
import okio.ByteString
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RealChatTransportSecurityTest {
    @Test
    fun oversizedInboundTextClosesWithPolicyViolationAndDisconnects() = runBlocking {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val socket = RecordingWebSocket()

        assertFalse(
            transport.disconnectForOversizedTextFrame(
                socket,
                "x".repeat(1 * 1024 * 1024),
                "node-1"
            )
        )
        assertEquals(null, socket.closeCode)

        assertTrue(
            transport.disconnectForOversizedTextFrame(
                socket,
                "\u20ac".repeat(400_000),
                "node-1"
            )
        )
        assertEquals(1009, socket.closeCode)
        assertEquals("message too big", socket.closeReason)
        assertEquals("DISCONNECTED", transport.getServerStatus().first().state)
    }

    @Test
    fun utf8LimitCountsMultibyteAndSurrogateInputWithoutAllocation() {
        assertFalse(exceedsUtf8ByteLimit("\u20ac".repeat(349_525), 1 * 1024 * 1024))
        assertTrue(exceedsUtf8ByteLimit("\u20ac".repeat(349_526), 1 * 1024 * 1024))
        assertFalse(exceedsUtf8ByteLimit("\ud83d\ude00", 4))
        assertTrue(exceedsUtf8ByteLimit("\ud83d\ude00", 3))
        assertFalse(exceedsUtf8ByteLimit("\ud83d", 1))
    }

    private class RecordingWebSocket : WebSocket {
        var closeCode: Int? = null
        var closeReason: String? = null
        var cancelled = false

        override fun request(): Request = Request.Builder().url("https://node.example/v1/ws").build()

        override fun queueSize(): Long = 0L

        override fun send(text: String): Boolean = true

        override fun send(bytes: ByteString): Boolean = true

        override fun close(code: Int, reason: String?): Boolean {
            closeCode = code
            closeReason = reason
            return true
        }

        override fun cancel() {
            cancelled = true
        }
    }
}

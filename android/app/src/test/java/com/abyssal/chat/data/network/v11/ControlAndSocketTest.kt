package com.abyssal.chat.data.network.v11

import com.abyssal.chat.domain.model.TransportKeys
import com.abyssal.chat.testTransportKeys
import kotlinx.coroutines.runBlocking
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okio.Buffer
import okio.ByteString
import okio.ByteString.Companion.toByteString
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.abyssal_core.ControlAttestationInput
import uniffi.abyssal_core.ControlResponse

class ControlAndSocketTest {
    private fun reply(code: Int = 200, bytes: Int = CONTROL_RECORD_BYTES.toInt()) = Response.Builder()
        .request(Request.Builder().url("https://relay.test/v1/control").build())
        .protocol(Protocol.HTTP_1_1)
        .code(code)
        .message("")
        .body(ByteArray(bytes) { 1 }.toResponseBody("application/octet-stream".toMediaType()))
        .build()

    private fun outcome(answer: () -> ControlResponse, response: Response = reply()): TicketOutcome {
        val control = ScriptedControlExchanges(answer)
        return ControlTicketRequest("https://relay.test", testTransportKeys(), "android", "4.0.0", "sig", control)
            .use { it.readOutcome(response) }
    }

    @Test
    fun ticketRequestIsOneSealedRecordWithTheAttestationInside() {
        val control = ScriptedControlExchanges { ControlResponse.Failure }
        val request = ControlTicketRequest("https://relay.test", testTransportKeys(), "android", "4.0.0", "sig", control)
        val http = request.httpRequest()
        assertEquals("https://relay.test/v1/control", http.url.toString())
        assertEquals("POST", http.method)
        assertNull(http.header("Authorization"))
        assertEquals(ControlAttestationInput("android", "4.0.0", "sig"), control.attestation)
        assertEquals(CONTROL_RECORD_BYTES, http.body?.contentLength())
        request.close()
        assertTrue(control.request.all { it == 0.toByte() })
        assertEquals(1, control.closed)
    }

    @Test
    fun ticketRepliesMapToIssuedTerminalOrTransientOutcomes() {
        val ticket = "A".repeat(43)
        val issued = outcome({ ControlResponse.WsTicket(ticket, 30u) }) as TicketOutcome.Issued
        assertEquals(ticket, issued.ticket)
        assertEquals(30, issued.expiresInSec)

        assertEquals("SECURITY_REJECTED", (outcome({ ControlResponse.BuildRejected }) as TicketOutcome.Terminal).state)
        assertEquals("PLATFORM_CONFLICT", (outcome({ ControlResponse.PlatformConflict }) as TicketOutcome.Terminal).state)
        // A reply that does not open under the session keys: the relay forgot the session.
        assertEquals("SESSION_EXPIRED", (outcome({ error("aead") }) as TicketOutcome.Terminal).state)

        val transient = listOf(
            outcome({ ControlResponse.Failure }),
            outcome({ ControlResponse.LoggedOut }),
            outcome({ ControlResponse.WsTicket("A".repeat(42), 30u) }),
            outcome({ ControlResponse.WsTicket("$ticket=".drop(1), 30u) }),
            outcome({ ControlResponse.WsTicket(ticket, 0u) }),
            outcome({ ControlResponse.WsTicket(ticket, 31u) }),
            // Proxy errors and oversized bodies never reach the record layer.
            outcome({ error("not reached") }, reply(code = 502)),
            outcome({ error("not reached") }, reply(bytes = CONTROL_RECORD_BYTES.toInt() + 1))
        )
        assertTrue(transient.all { it === TicketOutcome.Transient })
    }

    @Test
    fun logoutSucceedsOnlyForAnAuthenticatedLoggedOutReply() = runBlocking {
        val server = MockWebServer()
        repeat(3) { server.enqueue(MockResponse().setBody(Buffer().write(ByteArray(CONTROL_RECORD_BYTES.toInt())))) }
        server.enqueue(MockResponse().setResponseCode(503))
        server.start()
        try {
            val base = server.url("/").toString().removeSuffix("/")
            val client = OkHttpClient()
            assertTrue(logoutV11(client, base, testTransportKeys(), ScriptedControlExchanges { ControlResponse.LoggedOut }))
            assertFalse(logoutV11(client, base, testTransportKeys(), ScriptedControlExchanges { ControlResponse.Failure }))
            assertFalse(logoutV11(client, base, testTransportKeys(), ScriptedControlExchanges { error("aead") }))
            val control = ScriptedControlExchanges { ControlResponse.LoggedOut }
            assertFalse(logoutV11(client, base, testTransportKeys(), control))
            assertEquals(1, control.closed)
            assertTrue(control.request.all { it == 0.toByte() })
            assertEquals("/v1/control", server.takeRequest().path)
        } finally {
            server.shutdown()
        }
    }

    private class RawSocket : WebSocket {
        val binary = mutableListOf<ByteString>()
        var cancelled = false
        var closedWith: Int? = null
        override fun request() = Request.Builder().url("https://relay.test/v1/ws").build()
        override fun queueSize() = 0L
        override fun send(text: String) = error("plaintext text frames are never sent")
        override fun send(bytes: ByteString): Boolean = binary.add(bytes)
        override fun close(code: Int, reason: String?): Boolean {
            closedWith = code
            return true
        }
        override fun cancel() {
            cancelled = true
        }
    }

    private class RecordingListener : WebSocketListener() {
        val events = mutableListOf<String>()
        var socket: WebSocket? = null
        override fun onOpen(webSocket: WebSocket, response: Response) {
            socket = webSocket
            events += "open"
            webSocket.send("join")
        }
        override fun onMessage(webSocket: WebSocket, text: String) {
            events += "text:$text"
        }
        override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
            events += "closed:$code"
        }
        override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
            events += "failure"
        }
    }

    private fun upgrade() = Response.Builder()
        .request(Request.Builder().url("https://relay.test/v1/ws").build())
        .protocol(Protocol.HTTP_1_1)
        .code(101)
        .message("")
        .build()

    @Test
    fun socketReportsOpenOnlyAfterTheServerHelloAndSealsFramesInOrder() {
        val layer = TaggedRecordLayer()
        val inner = RecordingListener()
        val unauthenticated = mutableListOf<WebSocket>()
        val adapter = SealedWebSocketListener(layer, inner) { unauthenticated += it }
        val raw = RawSocket()
        val sealed = adapter.wrap(raw)

        // Frames sent before the handshake wait, like OkHttp's own pre-open queue.
        assertTrue(sealed.send("early"))
        adapter.onOpen(raw, upgrade())
        assertEquals(listOf(byteArrayOf(0x48).toByteString()), raw.binary)
        assertTrue(inner.events.isEmpty())

        adapter.onMessage(raw, byteArrayOf(0x53).toByteString())
        assertEquals(listOf("open"), inner.events)
        assertTrue(inner.socket === sealed)
        assertEquals(
            listOf("H", "Rearly", "Rjoin"),
            raw.binary.map { String(it.toByteArray(), Charsets.ISO_8859_1) }
        )

        adapter.onMessage(raw, (byteArrayOf(0x52) + "hello".toByteArray()).toByteString())
        assertEquals("text:hello", inner.events.last())
        assertFalse(sealed.send(ByteString.EMPTY))
        assertTrue(unauthenticated.isEmpty())

        adapter.onClosed(raw, 1000, "")
        assertEquals("closed:1000", inner.events.last())
        assertTrue(layer.closed)
        assertFalse(sealed.send("late"))
    }

    @Test
    fun socketFailsClosedOnForgedRecordsPlaintextAndBadUtf8() {
        fun connected(): Triple<TaggedRecordLayer, RawSocket, Pair<SealedWebSocketListener, MutableList<WebSocket>>> {
            val layer = TaggedRecordLayer()
            val bad = mutableListOf<WebSocket>()
            val adapter = SealedWebSocketListener(layer, RecordingListener()) { bad += it }
            val raw = RawSocket()
            adapter.onOpen(raw, upgrade())
            adapter.onMessage(raw, byteArrayOf(0x53).toByteString())
            return Triple(layer, raw, adapter to bad)
        }

        val (_, raw1, pair1) = connected()
        pair1.first.onMessage(raw1, "{\"type\":\"presence\"}")
        assertEquals(1, pair1.second.size)

        val (layer2, raw2, pair2) = connected()
        layer2.rejectNext = true
        pair2.first.onMessage(raw2, byteArrayOf(0x52, 0x41).toByteString())
        assertEquals(1, pair2.second.size)

        val (_, raw3, pair3) = connected()
        pair3.first.onMessage(raw3, byteArrayOf(0x52, 0xff.toByte()).toByteString())
        assertEquals(1, pair3.second.size)

        val layer = TaggedRecordLayer()
        val bad = mutableListOf<WebSocket>()
        val inner = RecordingListener()
        val adapter = SealedWebSocketListener(layer, inner) { bad += it }
        val raw = RawSocket()
        adapter.onOpen(raw, upgrade())
        adapter.onMessage(raw, byteArrayOf(0x00).toByteString())
        assertEquals(1, bad.size)
        assertTrue(inner.events.isEmpty())

        adapter.onFailure(raw, IllegalStateException("gone"), null)
        assertEquals(listOf("failure"), inner.events)
        assertTrue(layer.closed)
    }

    @Test
    fun upgradeRequestCarriesOnlyTheV11Protocol() {
        val request = sealedWebSocketRequest("wss://relay.test")
        // OkHttp normalizes ws(s) URLs to http(s); the upgrade itself is a WebSocket.
        assertEquals("https://relay.test/v1/ws", request.url.toString())
        assertEquals("abyssal-v11", request.header("Sec-WebSocket-Protocol"))
        assertNull(request.header("Authorization"))
    }
}

package com.abyssal.chat.data.network

import com.abyssal.chat.data.network.v11.AccountBootstrapClient
import com.abyssal.chat.data.network.v11.ControlExchange
import com.abyssal.chat.data.network.v11.ControlExchanges
import com.abyssal.chat.data.network.v11.FakeBootstrapExchanges
import com.abyssal.chat.data.network.v11.FakeOpaque
import com.abyssal.chat.data.network.v11.SealedRecordHttp
import com.abyssal.chat.domain.model.NodeEndpoint
import com.abyssal.chat.domain.model.NodeSession
import com.abyssal.chat.domain.model.TransportKeys
import java.io.IOException
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import okhttp3.Call
import okhttp3.Callback
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okio.Buffer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.abyssal_core.ControlAttestationInput
import uniffi.abyssal_core.ControlResponse

class NetworkIdentityServiceTest {
    private val password get() = "correct horse battery staple".toByteArray()

    private fun ByteArray.zeroed() = all { it == 0.toByte() }

    private fun endpoint(baseUrl: String) = NodeEndpoint(baseUrl, baseUrl, baseUrl.replace("http", "ws"), "test")

    private suspend fun NetworkIdentityService.enter(
        baseUrl: String,
        password: ByteArray = this@NetworkIdentityServiceTest.password,
        capability: ByteArray = ByteArray(32) { 4 },
        accountContext: ByteArray = ByteArray(32) { 5 }
    ) = enterAccount(
        capability = capability,
        accountContext = accountContext,
        expectedNodeId = "node-1",
        nodePublicKey = ByteArray(32) { 9 },
        bootstrapPublicKey = ByteArray(32) { 8 },
        password = password,
        endpoint = endpoint(baseUrl)
    )

    /** Records logout requests and answers them LoggedOut. */
    private class RecordingControl : ControlExchanges {
        val loggedOut = mutableListOf<List<Byte>>()
        override fun issueWsTicket(keys: TransportKeys, attestation: ControlAttestationInput) = error("not used")
        override fun logout(keys: TransportKeys): ControlExchange {
            loggedOut += keys.sessionId.toList()
            return object : ControlExchange {
                override fun requestBytes() = ByteArray(CONTROL_BYTES) { 1 }
                override fun openResponse(reply: ByteArray) = ControlResponse.LoggedOut
                override fun close() = Unit
            }
        }
    }

    private fun fakeService(
        server: MockWebServer,
        exchanges: FakeBootstrapExchanges,
        control: RecordingControl = RecordingControl(),
        cipher: InMemoryPayloadCipher = InMemoryPayloadCipher()
    ) = NetworkIdentityService(
        payloadCipher = cipher,
        callFactory = OkHttpClient(),
        bootstrap = AccountBootstrapClient(
            post = { _, _ -> ByteArray(32) { 1 } },
            opaque = FakeOpaque(),
            exchanges = exchanges
        ),
        controlExchanges = control
    ).also { server.enqueue(MockResponse().setBody(Buffer().write(ByteArray(CONTROL_BYTES)))) }

    @Test
    fun accountEntrySendsOnlyOneSealedRecordAndConsumesEverySecret() = runBlocking {
        val server = MockWebServer()
        server.enqueue(MockResponse().setBody(Buffer().write(ByteArray(4_096) { 0x33 })))
        server.start()
        try {
            val service = NetworkIdentityService(OkHttpClient(), InMemoryPayloadCipher())
            val password = password
            val capability = ByteArray(32) { 4 }
            val accountContext = ByteArray(32) { 5 }

            val result = service.enter(server.url("/").toString().removeSuffix("/"), password, capability, accountContext)

            // The relay's reply did not open under the sealed exchange: rejected.
            assertFalse(result.accepted)
            val request = server.takeRequest()
            val body = request.body.readByteArray()
            assertEquals("/v1/bootstrap", request.path)
            assertEquals("POST", request.method)
            assertEquals("application/octet-stream", request.getHeader("Content-Type"))
            assertNull(request.getHeader("Authorization"))
            assertTrue(body.size > 1_000)
            val text = String(body, Charsets.ISO_8859_1)
            assertFalse(text.contains("correct horse battery staple"))
            assertFalse(text.contains(String(ByteArray(32) { 4 }, Charsets.ISO_8859_1)))
            assertEquals(1, server.requestCount)
            assertTrue(password.zeroed() && capability.zeroed() && accountContext.zeroed())
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun rejectsAnOversizedReplyWithoutReadingItIntoHeap() = runBlocking {
        val server = MockWebServer()
        server.enqueue(MockResponse().setChunkedBody("x".repeat(SealedRecordHttp.MAX_BOOTSTRAP_REPLY_BYTES.toInt() + 1), 8192))
        server.start()
        try {
            val password = password
            val result = NetworkIdentityService(OkHttpClient(), InMemoryPayloadCipher())
                .enter(server.url("/").toString().removeSuffix("/"), password)
            assertFalse(result.accepted)
            assertTrue(password.zeroed())
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun acceptsAConsistentSessionAndHandsOverItsTransportKeys() = runBlocking {
        val server = MockWebServer().apply { start() }
        try {
            val cipher = InMemoryPayloadCipher()
            val result = fakeService(server, FakeBootstrapExchanges.registering(), cipher = cipher)
                .enter(server.url("/").toString().removeSuffix("/"))

            assertTrue(result.accepted)
            assertTrue(result.created)
            assertEquals("Alice_1", result.username)
            assertEquals("node-1", result.nodeId)
            assertEquals(3, result.maxRoomsPerUser)
            assertEquals(900, result.sessionInactivitySec)
            assertNotNull(UUID.fromString(result.token))
            assertArrayEquals(cipher.publicKey(), result.publicKey)
            assertEquals(cipher.prekeyId(), result.prekeyId)
            assertArrayEquals(ByteArray(32) { 0x5a }, result.deviceStorageShare)
            val keys = requireNotNull(result.transport)
            assertArrayEquals(ByteArray(32) { 9 }, keys.nodePublicKey)
            assertArrayEquals(ByteArray(32) { 0x51 }, keys.sessionId)
            assertArrayEquals(ByteArray(32) { 9 }, keys.transportRoot)
            assertEquals(0, server.requestCount)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun logsOutAndWipesASessionItRefuses() = runBlocking {
        val cases = listOf(
            "a registration marked as an existing account" to FakeBootstrapExchanges.registering(created = false),
            "a malformed username" to FakeBootstrapExchanges.registering(username = "Alice Smith"),
            "a short storage share" to FakeBootstrapExchanges.registering(share = ByteArray(16))
        )
        for ((label, exchanges) in cases) {
            val server = MockWebServer().apply { start() }
            try {
                val control = RecordingControl()
                val cipher = InMemoryPayloadCipher()
                val result = fakeService(server, exchanges, control, cipher)
                    .enter(server.url("/").toString().removeSuffix("/"))

                assertFalse(label, result.accepted)
                assertNull(label, result.transport)
                assertEquals(label, List<Byte>(32) { 0x51 }, control.loggedOut.single())
                assertEquals(label, "/v1/control", server.takeRequest(2, TimeUnit.SECONDS)?.path)
                assertTrue(label, runCatching { cipher.publicKey() }.isFailure)
            } finally {
                server.shutdown()
            }
        }
    }

    @Test
    fun revokeSessionLogsOutOverControlAndWipesTheKeys() = runBlocking {
        val server = MockWebServer().apply { start() }
        try {
            val control = RecordingControl()
            val service = fakeService(server, FakeBootstrapExchanges(), control)
            val baseUrl = server.url("/").toString().removeSuffix("/")
            val keys = TransportKeys(ByteArray(32) { 1 }, ByteArray(32) { 2 }, ByteArray(32) { 3 })

            assertTrue(service.revokeSession(NodeSession(endpoint(baseUrl), "local", "node-1", 5, keys)))

            val request = server.takeRequest()
            assertEquals("/v1/control", request.path)
            assertNull(request.getHeader("Authorization"))
            assertEquals(List<Byte>(32) { 2 }, control.loggedOut.single())
            assertTrue(keys.nodePublicKey.zeroed() && keys.sessionId.zeroed() && keys.transportRoot.zeroed())
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun cancellationCancelsTheBootstrapCallAndPropagates() = runBlocking {
        val factory = IdentityCancellationCallFactory()
        val service = NetworkIdentityService(
            client = OkHttpClient(),
            payloadCipher = InMemoryPayloadCipher(),
            callFactory = factory
        )
        val job = launch(Dispatchers.Default) { service.enter("http://127.0.0.1") }

        assertTrue(factory.call.enqueued.await(2, TimeUnit.SECONDS))
        job.cancelAndJoin()

        assertTrue(factory.call.cancelled)
        assertTrue(job.isCancelled)
    }

    private class IdentityCancellationCallFactory : Call.Factory {
        val call = IdentityCancellationCall()

        override fun newCall(request: Request): Call = call
    }

    private class IdentityCancellationCall : Call {
        private val request = Request.Builder().url("http://127.0.0.1/v1/bootstrap").build()
        private var callback: Callback? = null
        val enqueued = CountDownLatch(1)
        @Volatile var cancelled = false

        override fun request(): Request = request

        override fun execute(): Response = error("not used")

        override fun enqueue(responseCallback: Callback) {
            callback = responseCallback
            enqueued.countDown()
        }

        override fun cancel() {
            cancelled = true
            callback?.onFailure(this, IOException("cancelled"))
        }

        override fun isExecuted(): Boolean = callback != null

        override fun isCanceled(): Boolean = cancelled

        override fun timeout() = okio.Timeout.NONE

        override fun clone(): Call = IdentityCancellationCall()
    }

    private companion object {
        const val CONTROL_BYTES = 4_170
    }
}

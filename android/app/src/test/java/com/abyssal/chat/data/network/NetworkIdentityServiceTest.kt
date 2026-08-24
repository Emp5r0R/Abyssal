package com.abyssal.chat.data.network

import com.abyssal.chat.domain.model.NodeEndpoint
import java.io.IOException
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import okhttp3.Call
import okhttp3.Callback
import okhttp3.Request
import okhttp3.Response
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkIdentityServiceTest {
    @Test
    fun strictOpaqueStartAcceptsOnlyTypedModeConsistentResponse() {
        val registration = validOpaqueStart("registration")
        val validatedRegistration = validateOpaqueStartResponse(registration)
        assertNotNull(validatedRegistration)
        assertEquals("registration", validatedRegistration?.mode)
        assertEquals("node-1", validatedRegistration?.nodeId)

        val login = validOpaqueStart("login")
            .put("identity_public_b64", base64(ByteArray(608) { 7 }))
            .put("identity_prekey_id", "prekey-1")
            .put("identity_envelope_b64", base64(byteArrayOf(1, 2, 3)))
        assertNotNull(validateOpaqueStartResponse(login))

        val invalid = listOf(
            JSONObject(registration.toString()).put("accepted", "true"),
            JSONObject(registration.toString()).put("handshake_id", "76f1b4b6-6dd8-1352-80b9-76fa0150484c"),
            JSONObject(registration.toString()).put("node_id", "node 1"),
            JSONObject(registration.toString()).put("response_b64", "AQID="),
            JSONObject(registration.toString()).put("challenge_b64", "AQID"),
            JSONObject(registration.toString()).put("identity_public_b64", 7),
            JSONObject(login.toString()).put("identity_prekey_id", "bad prekey"),
            JSONObject(login.toString()).put("unexpected", true)
        )
        invalid.forEach { assertNull(validateOpaqueStartResponse(it)) }
    }

    @Test
    fun strictAccountFinishBindsModeNodePrekeyAndExactFieldTypes() {
        val finish = validAccountFinish()
        val validated = validateAcceptedAccountResponse(
            finish,
            expectedNodeId = "node-1",
            expectedCreated = true,
            expectedPrekeyId = "prekey-1"
        )
        assertNotNull(validated)
        assertEquals(3, validated?.maxRoomsPerUser)
        assertEquals(900, validated?.sessionInactivitySec)

        val invalid = listOf(
            JSONObject(finish.toString()).put("accepted", 1),
            JSONObject(finish.toString()).put("created", "true"),
            JSONObject(finish.toString()).put("token", "not-a-v4-session-token"),
            JSONObject(finish.toString()).put("username", "Alice Smith"),
            JSONObject(finish.toString()).put("max_rooms_per_user", "3"),
            JSONObject(finish.toString()).put("max_rooms_per_user", 101),
            JSONObject(finish.toString()).put("session_inactivity_sec", 900.0),
            JSONObject(finish.toString()).put("session_inactivity_sec", 59),
            JSONObject(finish.toString()).put("identity_public_b64", "AQID"),
            JSONObject(finish.toString()).put("unexpected", true)
        )
        invalid.forEach { response ->
            assertNull(
                validateAcceptedAccountResponse(response, "node-1", true, "prekey-1")
            )
        }
        assertNull(validateAcceptedAccountResponse(finish, "node-2", true, "prekey-1"))
        assertNull(validateAcceptedAccountResponse(finish, "node-1", false, "prekey-1"))
        assertNull(validateAcceptedAccountResponse(finish, "node-1", true, "prekey-2"))
    }

    @Test
    fun opaqueStartNeverSendsPasswordToRelay() = runBlocking {
        val server = MockWebServer()
        server.enqueue(MockResponse().setResponseCode(401).setBody("{}"))
        server.start()
        try {
            val baseUrl = server.url("/").toString().removeSuffix("/")
            val service = NetworkIdentityService(OkHttpClient(), InMemoryPayloadCipher())

            val password = "correct horse battery staple".toByteArray()
            val result = service.enterAccount(
                code = "ABYS-INVITE-1234",
                password = password,
                endpoint = NodeEndpoint(baseUrl, baseUrl, baseUrl.replace("http", "ws"), "test")
            )

            val request = server.takeRequest()
            val body = request.body.readUtf8()
            assertFalse(result.accepted)
            assertTrue(request.path == "/v2/account/start")
            assertTrue(body.contains("registration_request_b64"))
            assertTrue(body.contains("credential_request_b64"))
            assertFalse(body.contains("correct horse battery staple"))
            assertFalse(body.contains("password"))
            assertTrue(password.all { it == 0.toByte() })
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun rejectsOversizedAccountResponseWithoutReadingItIntoHeap() = runBlocking {
        val server = MockWebServer()
        server.enqueue(
            MockResponse().setChunkedBody("x".repeat(1_048_577), 8192)
        )
        server.start()
        try {
            val baseUrl = server.url("/").toString().removeSuffix("/")
            val service = NetworkIdentityService(OkHttpClient(), InMemoryPayloadCipher())

            val password = "correct horse battery staple".toByteArray()
            val result = service.enterAccount(
                code = "ABYS-INVITE-1234",
                password = password,
                endpoint = NodeEndpoint(baseUrl, baseUrl, baseUrl.replace("http", "ws"), "test")
            )

            assertFalse(result.accepted)
            assertTrue(password.all { it == 0.toByte() })
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun cancellationCancelsIdentityCallAndPropagatesCancellation() = runBlocking {
        val factory = IdentityCancellationCallFactory()
        val service = NetworkIdentityService(
            client = OkHttpClient(),
            payloadCipher = InMemoryPayloadCipher(),
            callFactory = factory
        )
        val endpoint = NodeEndpoint(
            inputUrl = "http://127.0.0.1",
            apiBaseUrl = "http://127.0.0.1",
            wsBaseUrl = "ws://127.0.0.1",
            displayHost = "test"
        )
        val job = launch(Dispatchers.Default) {
            service.enterAccount("ABYS-INVITE-1234", "correct horse battery staple".toByteArray(), endpoint)
        }

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
        private val request = Request.Builder().url("http://127.0.0.1/account").build()
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
        fun validOpaqueStart(mode: String): JSONObject = JSONObject()
            .put("accepted", true)
            .put("mode", mode)
            .put("handshake_id", "76f1b4b6-6dd8-4352-80b9-76fa0150484c")
            .put("response_b64", "AQID")
            .put(
                "challenge_b64",
                if (mode == "registration") base64(ByteArray(32) { 1 }) else JSONObject.NULL
            )
            .put("node_id", "node-1")
            .put("identity_public_b64", JSONObject.NULL)
            .put("identity_prekey_id", JSONObject.NULL)
            .put("identity_envelope_b64", JSONObject.NULL)
            .put("error", JSONObject.NULL)

        fun validAccountFinish(): JSONObject = JSONObject()
            .put("accepted", true)
            .put("created", true)
            .put("token", "6ba7b810-9dad-41d1-80b4-00c04fd430c8")
            .put("node_id", "node-1")
            .put("username", "Alice_1")
            .put("max_rooms_per_user", 3)
            .put("session_inactivity_sec", 900)
            .put("identity_public_b64", base64(ByteArray(608) { 7 }))
            .put("identity_prekey_id", "prekey-1")
            .put("identity_envelope_b64", "AQID")
            .put("error", JSONObject.NULL)

        fun base64(bytes: ByteArray): String =
            Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }
}

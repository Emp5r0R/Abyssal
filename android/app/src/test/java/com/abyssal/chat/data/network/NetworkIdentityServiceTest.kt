package com.abyssal.chat.data.network

import com.abyssal.chat.domain.model.NodeEndpoint
import java.io.IOException
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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkIdentityServiceTest {
    @Test
    fun opaqueStartNeverSendsPasswordToRelay() = runBlocking {
        val server = MockWebServer()
        server.enqueue(MockResponse().setResponseCode(401).setBody("{}"))
        server.start()
        try {
            val baseUrl = server.url("/").toString().removeSuffix("/")
            val service = NetworkIdentityService(OkHttpClient(), InMemoryPayloadCipher())

            val result = service.enterAccount(
                code = "ABYS-INVITE-1234",
                password = "correct horse battery staple",
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

            val result = service.enterAccount(
                code = "ABYS-INVITE-1234",
                password = "correct horse battery staple",
                endpoint = NodeEndpoint(baseUrl, baseUrl, baseUrl.replace("http", "ws"), "test")
            )

            assertFalse(result.accepted)
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
            service.enterAccount("ABYS-INVITE-1234", "correct horse battery staple", endpoint)
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
}

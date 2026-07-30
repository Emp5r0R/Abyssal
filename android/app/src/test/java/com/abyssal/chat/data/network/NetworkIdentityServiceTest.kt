package com.abyssal.chat.data.network

import com.abyssal.chat.domain.model.NodeEndpoint
import kotlinx.coroutines.runBlocking
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
}

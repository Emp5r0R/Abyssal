package com.abyssal.chat.data.network

import java.io.IOException
import kotlinx.coroutines.runBlocking
import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import okio.Timeout
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.abyssal_core.parseInviteCapsule

class InviteBootstrapServiceTest {
    @Test
    fun sharedVectorParsesIdenticallyThroughUniffi() {
        val parsed = parseInviteCapsule(DEEP_LINK, 2_000_000_000UL, false)
        assertEquals(NODE_ID, parsed.nodeId)
        assertEquals("https://node.example.com", parsed.nodeUrl)
        assertArrayEquals(ByteArray(32) { 0x22 }, parsed.capability)
        assertEquals(ACCOUNT_CONTEXT_HEX, parsed.accountContext.toHex())
    }

    @Test
    fun verifiesExactSignedDescriptorBeforeReturningCapability() = runBlocking {
        val factory = StaticCallFactory(DESCRIPTOR_HEX.hexBytes())
        val service = InviteBootstrapService(
            client = OkHttpClient(),
            nodeConfigService = InMemoryNodeConfigService(),
            allowDevelopmentLoopback = false,
            callFactory = factory
        )

        val verified = service.verify(DEEP_LINK).getOrThrow()
        assertEquals(NODE_ID, verified.nodeId)
        assertEquals("https://node.example.com", verified.endpoint.apiBaseUrl)
        assertArrayEquals(ByteArray(32) { 0x22 }, verified.capability)
        assertEquals("https://node.example.com/v1/node", factory.request?.url.toString())
        assertEquals("application/cbor", factory.request?.header("Accept"))
        verified.destroy()
        assertTrue(verified.capability.all { it == 0.toByte() })
        assertTrue(verified.nodePublicKey.all { it == 0.toByte() })
    }

    @Test
    fun rejectsTamperedOversizedAndRedirectedDescriptors() = runBlocking {
        val tampered = DESCRIPTOR_HEX.hexBytes().also { it[it.lastIndex] = (it.last() xor 1) }
        assertTrue(service(StaticCallFactory(tampered)).verify(DEEP_LINK).isFailure)
        assertTrue(service(StaticCallFactory(ByteArray(1_025))).verify(DEEP_LINK).isFailure)
        assertTrue(
            service(StaticCallFactory(DESCRIPTOR_HEX.hexBytes(), redirected = true))
                .verify(DEEP_LINK)
                .isFailure
        )
    }

    private fun service(factory: Call.Factory) = InviteBootstrapService(
        client = OkHttpClient(),
        nodeConfigService = InMemoryNodeConfigService(),
        allowDevelopmentLoopback = false,
        callFactory = factory
    )

    private class StaticCallFactory(
        private val body: ByteArray,
        private val redirected: Boolean = false
    ) : Call.Factory {
        var request: Request? = null

        override fun newCall(request: Request): Call {
            this.request = request
            return StaticCall(request, body, redirected)
        }
    }

    private class StaticCall(
        private val original: Request,
        private val body: ByteArray,
        private val redirected: Boolean
    ) : Call {
        @Volatile
        private var canceled = false

        override fun request(): Request = original
        override fun execute(): Response = response()
        override fun enqueue(responseCallback: Callback) {
            if (canceled) responseCallback.onFailure(this, IOException("Canceled"))
            else responseCallback.onResponse(this, response())
        }
        override fun cancel() { canceled = true }
        override fun isExecuted(): Boolean = false
        override fun isCanceled(): Boolean = canceled
        override fun timeout(): Timeout = Timeout.NONE
        override fun clone(): Call = StaticCall(original, body, redirected)

        private fun response(): Response {
            val responseRequest = if (redirected) {
                original.newBuilder().url("https://other.example/v1/node").build()
            } else {
                original
            }
            return Response.Builder()
                .request(responseRequest)
                .protocol(Protocol.HTTP_1_1)
                .code(200)
                .message("OK")
                .body(body.copyOf().toResponseBody("application/cbor".toMediaType()))
                .build()
        }
    }

    private infix fun Byte.xor(other: Int): Byte = (toInt() xor other).toByte()
    private fun String.hexBytes(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private companion object {
        const val NODE_ID = "abyssal-node-v1:zlLjZjAl8CVJZ5l9jVgQUhve1mxyTiVNmey5lQsROLU"
        const val ACCOUNT_CONTEXT_HEX = "f5145cdbee41235643f64efca7a605d19ebce805cdb66295ff479414856f2734"
        const val DEEP_LINK = "abyssal:invite:glh3igFwb3JnLmFieXNzYWwuY2hhdAFYINBKsjJ0K7SrOhNovUYV5ObQIkq3GgFrr4UgozLJd4c3gYMBcG5vZGUuZXhhbXBsZS5jb20ZAbtYICIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiCQoAGn0rdQBYQDgZJxVYJlrtgAJBj4VbdykqYpymbDWTNY0Uz-18fOOxGzi6fwKTPzEnVkJ6QldbfyY0pl1JJchNJv3TknkT-Qs"
        const val DESCRIPTOR_HEX = "8258508801706f72672e6162797373616c2e636861745820d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737818301706e6f64652e6578616d706c652e636f6d1901bb01090a00584011d674f2075930853f2ae2ea008d7787de469c3d1e954ea8aea6ae5a19e31a2c7d790ce0c473036e3bb016c3bc50c96e85b214659d994da7a8a43dfcff383401"
    }
}

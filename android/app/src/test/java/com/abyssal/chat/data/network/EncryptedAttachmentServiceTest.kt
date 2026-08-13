package com.abyssal.chat.data.network

import android.content.ContextWrapper
import com.abyssal.chat.domain.model.EncryptedAttachmentDownload
import com.abyssal.chat.domain.model.NodeEndpoint
import com.abyssal.chat.domain.model.NodeSession
import kotlinx.coroutines.delay
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import java.util.concurrent.CancellationException
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.ResponseBody
import okhttp3.Response
import okio.Buffer
import okio.BufferedSource
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer

class EncryptedAttachmentServiceTest {
    @Test
    fun statelessAttachmentBoundIncludesOnlyWireOverhead() {
        assertEquals(
            200L * 1024L * 1024L + ATTACHMENT_WIRE_OVERHEAD_BYTES,
            maxSerializedAttachmentBytes("FILE")
        )
        assertTrue(maxSerializedAttachmentBytes("VIDEO") < maxSerializedAttachmentBytes("FILE"))
        assertTrue(maxSerializedAttachmentBytes("IMAGE") < maxSerializedAttachmentBytes("VIDEO"))
        assertEquals(45L, expectedEncryptedAttachmentBytes(4L))
        assertNull(expectedEncryptedAttachmentBytes(0L))
        assertNull(expectedEncryptedAttachmentBytes(Long.MAX_VALUE))
    }

    @Test
    fun acceptsEncryptedAttachmentAtConfiguredBound() {
        val body = ByteArray(128) { it.toByte() }
            .toResponseBody("application/octet-stream".toMediaType())

        val result = readBoundedAttachmentBody(body)

        assertArrayEquals(ByteArray(128) { it.toByte() }, result)
    }

    @Test
    fun rejectsBodyWithDeclaredLengthBeyondConfiguredBound() {
        val body = object : ResponseBody() {
            override fun contentType() = "application/octet-stream".toMediaType()
            override fun contentLength() = MAX_ENCRYPTED_ATTACHMENT_BYTES + 1L
            override fun source(): BufferedSource = Buffer().writeByte(1)
        }

        assertNull(readBoundedAttachmentBody(body))
    }

    @Test
    fun attachmentBodyRequiresPositiveExactContentLength() {
        fun body(declaredLength: Long, bytes: ByteArray): ResponseBody = object : ResponseBody() {
            override fun contentType() = "application/octet-stream".toMediaType()
            override fun contentLength() = declaredLength
            override fun source(): BufferedSource = Buffer().write(bytes)
        }

        assertNull(readBoundedAttachmentBody(body(-1L, byteArrayOf(1))))
        assertNull(readBoundedAttachmentBody(body(0L, byteArrayOf())))
        assertNull(readBoundedAttachmentBody(body(4L, byteArrayOf(1, 2, 3))))
        assertNull(readBoundedAttachmentBody(body(3L, byteArrayOf(1, 2, 3, 4))))
        assertArrayEquals(
            byteArrayOf(1, 2, 3),
            readBoundedAttachmentBody(body(3L, byteArrayOf(1, 2, 3)))
        )
    }

    @Test
    fun rejectsOversizedUploadResponseWithoutReadingItAll() {
        val body = object : ResponseBody() {
            override fun contentType() = "application/json".toMediaType()
            override fun contentLength() = MAX_ATTACHMENT_UPLOAD_RESPONSE_BYTES + 1L
            override fun source(): BufferedSource = Buffer().writeUtf8("{\"accepted\":true}")
        }

        assertNull(readBoundedAttachmentResponse(body))
    }

    @Test
    fun normalizesOnlyCanonicalUuidAttachmentIds() {
        assertEquals(
            "123e4567-e89b-12d3-a456-426614174000",
            normalizeAttachmentId(" 123E4567-E89B-12D3-A456-426614174000 ")
        )
        assertNull(normalizeAttachmentId("../../v1/account/logout"))
        assertNull(normalizeAttachmentId("123e4567-e89b-12d3-c456-426614174000"))
    }

    @Test
    fun downloadReadsClaimAndCompletionRequestsReuseAuthAndClaimHeaders() = runBlocking {
        val wireBytes = ByteArray(45) { it.toByte() }
        val server = MockWebServer()
        server.enqueue(
            MockResponse()
                .setHeader(ATTACHMENT_CLAIM_HEADER, CLAIM)
                .setBody(Buffer().write(wireBytes))
        )
        server.start()
        try {
            val service = service()
            val downloaded = service.downloadEncryptedAttachment(sessionFor(server), ATTACHMENT_ID, "FILE", 4L)

            assertEquals(CLAIM, downloaded?.claim)
            assertArrayEquals(wireBytes, downloaded?.bytes)
            assertEquals("Bearer token", server.takeRequest().getHeader("Authorization"))

            server.enqueue(MockResponse().setResponseCode(204))
            assertTrue(service.completeAttachmentDownload(sessionFor(server), ATTACHMENT_ID, CLAIM))
            val complete = server.takeRequest()
            assertEquals("POST", complete.method)
            assertEquals("/v1/attachment/$ATTACHMENT_ID/complete", complete.path)
            assertEquals("Bearer token", complete.getHeader("Authorization"))
            assertEquals(CLAIM, complete.getHeader(ATTACHMENT_CLAIM_HEADER))

            server.enqueue(MockResponse().setResponseCode(204))
            assertTrue(service.releaseAttachmentDownloadClaim(sessionFor(server), ATTACHMENT_ID, CLAIM))
            val release = server.takeRequest()
            assertEquals("DELETE", release.method)
            assertEquals("/v1/attachment/$ATTACHMENT_ID/claim", release.path)
            assertEquals(CLAIM, release.getHeader(ATTACHMENT_CLAIM_HEADER))
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun ownerDeleteRemovesUploadedAttachmentWithBearerAuth() = runBlocking {
        val server = MockWebServer()
        server.enqueue(MockResponse().setResponseCode(204))
        server.start()
        try {
            val service = service()

            assertTrue(service.deleteUploadedAttachment(sessionFor(server), ATTACHMENT_ID))

            val request = server.takeRequest()
            assertEquals("DELETE", request.method)
            assertEquals("/v1/attachment/$ATTACHMENT_ID", request.path)
            assertEquals("Bearer token", request.getHeader("Authorization"))
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun ownerDeleteTreatsAlreadyExpiredAttachmentAsSuccess() = runBlocking {
        val server = MockWebServer()
        server.enqueue(MockResponse().setResponseCode(404))
        server.start()
        try {
            assertTrue(service().deleteUploadedAttachment(sessionFor(server), ATTACHMENT_ID))
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun uploadAndDeleteUseExplicitSessionInsteadOfActiveConfig() = runBlocking {
        val activeServer = MockWebServer()
        val capturedServer = MockWebServer()
        activeServer.enqueue(MockResponse().setResponseCode(418))
        capturedServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody("{\"accepted\":true,\"attachment_id\":\"$ATTACHMENT_ID\"}")
        )
        capturedServer.enqueue(MockResponse().setResponseCode(204))
        activeServer.start()
        capturedServer.start()
        try {
            val service = service()
            val capturedSession = sessionFor(capturedServer).copy(token = "captured-token")

            val upload = service.uploadEncryptedAttachment(
                session = capturedSession,
                chatId = "dm_bob",
                mediaType = "FILE",
                encryptedBytes = byteArrayOf(1),
                oneTimeView = false,
                deleteAfterDownload = false,
                ttlSec = 0,
                onProgress = { _, _ -> }
            )
            assertTrue(upload.accepted)
            assertEquals(
                "Bearer captured-token",
                capturedServer.takeRequest().getHeader("Authorization")
            )

            assertTrue(service.deleteUploadedAttachment(capturedSession, ATTACHMENT_ID))
            assertEquals(
                "Bearer captured-token",
                capturedServer.takeRequest().getHeader("Authorization")
            )
            assertEquals(0, activeServer.requestCount)
        } finally {
            activeServer.shutdown()
            capturedServer.shutdown()
        }
    }

    @Test
    fun downloadAndClaimLifecycleUseCapturedSessionInsteadOfActiveConfig() = runBlocking {
        val activeServer = MockWebServer()
        val capturedServer = MockWebServer()
        val wireBytes = ByteArray(45) { it.toByte() }
        activeServer.enqueue(MockResponse().setResponseCode(418))
        capturedServer.enqueue(
            MockResponse()
                .setHeader(ATTACHMENT_CLAIM_HEADER, CLAIM)
                .setBody(Buffer().write(wireBytes))
        )
        capturedServer.enqueue(MockResponse().setResponseCode(204))
        capturedServer.enqueue(MockResponse().setResponseCode(204))
        activeServer.start()
        capturedServer.start()
        try {
            val service = service()
            val capturedSession = sessionFor(capturedServer).copy(token = "captured-token")

            val downloaded = service.downloadEncryptedAttachment(
                capturedSession,
                ATTACHMENT_ID,
                "FILE",
                4L
            )
            assertArrayEquals(wireBytes, downloaded?.bytes)
            assertTrue(service.completeAttachmentDownload(capturedSession, ATTACHMENT_ID, CLAIM))
            assertTrue(service.releaseAttachmentDownloadClaim(capturedSession, ATTACHMENT_ID, CLAIM))

            val downloadRequest = capturedServer.takeRequest()
            assertEquals("GET", downloadRequest.method)
            assertEquals("Bearer captured-token", downloadRequest.getHeader("Authorization"))
            val completeRequest = capturedServer.takeRequest()
            assertEquals("POST", completeRequest.method)
            assertEquals("Bearer captured-token", completeRequest.getHeader("Authorization"))
            val releaseRequest = capturedServer.takeRequest()
            assertEquals("DELETE", releaseRequest.method)
            assertEquals("Bearer captured-token", releaseRequest.getHeader("Authorization"))
            assertEquals(0, activeServer.requestCount)
        } finally {
            activeServer.shutdown()
            capturedServer.shutdown()
        }
    }

    @Test
    fun noClaimDownloadDoesNotRequireCompletion() = runBlocking {
        val wireBytes = ByteArray(45) { (it + 1).toByte() }
        val server = MockWebServer()
        server.enqueue(MockResponse().setBody(Buffer().write(wireBytes)))
        server.start()
        try {
            val service = service()
            val downloaded = service.downloadEncryptedAttachment(sessionFor(server), ATTACHMENT_ID, "IMAGE", 4L)

            assertEquals(null, downloaded?.claim)
            assertArrayEquals(wireBytes, downloaded?.bytes)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun failedClaimedDownloadReleasesClaimBeforeReturning() = runBlocking {
        val server = MockWebServer()
        server.enqueue(
            MockResponse()
                .setHeader(ATTACHMENT_CLAIM_HEADER, CLAIM)
                .setBody("")
        )
        server.enqueue(MockResponse().setResponseCode(204))
        server.start()
        try {
            val service = service()

            assertNull(service.downloadEncryptedAttachment(sessionFor(server), ATTACHMENT_ID, "FILE", 4L))
            server.takeRequest()
            val release = server.takeRequest()
            assertEquals("DELETE", release.method)
            assertEquals("/v1/attachment/$ATTACHMENT_ID/claim", release.path)
            assertEquals(CLAIM, release.getHeader(ATTACHMENT_CLAIM_HEADER))
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun cancellationCancelsUnderlyingCallAndClosesLateResponse() = runBlocking {
        val call = CancellableTestCall()
        val job = launch {
            awaitHttpResponse(call) { response ->
                response.body?.bytes()
                Unit
            }
        }
        delay(100)

        job.cancel()
        job.join()

        assertTrue(call.isCanceled())
        val lateBody = TrackingResponseBody()
        call.deliver(
            Response.Builder()
                .request(call.request())
                .protocol(Protocol.HTTP_1_1)
                .code(200)
                .message("OK")
                .body(lateBody)
                .build()
        )
        assertTrue(lateBody.closed)
    }

    @Test
    fun uploadCancellationCancelsUnderlyingCall() = runBlocking {
        val call = CancellableTestCall()
        val service = service(object : Call.Factory {
            override fun newCall(request: Request): Call = call
        })
        val session = NodeSession(
            endpoint = NodeEndpoint(
                inputUrl = "http://localhost",
                apiBaseUrl = "http://localhost",
                wsBaseUrl = "ws://localhost",
                displayHost = "test"
            ),
            token = "token",
            nodeId = "node",
            maxRoomsPerUser = 5
        )
        val job = launch {
            service.uploadEncryptedAttachment(
                session = session,
                chatId = "dm_bob",
                mediaType = "FILE",
                encryptedBytes = byteArrayOf(1),
                oneTimeView = false,
                deleteAfterDownload = false,
                ttlSec = 0,
                onProgress = { _, _ -> }
            )
        }
        delay(100)

        job.cancelAndJoin()

        assertTrue(call.isCanceled())
    }

    @Test
    fun cancellationAfterClaimHeaderObservedReleasesClaimWithoutReturningBytes() = runBlocking {
        val factory = ClaimCancellationCallFactory()
        val service = service(factory)
        val session = testSession().copy(token = "captured-token")
        val job = launch(Dispatchers.Default) {
            service.downloadEncryptedAttachment(session, ATTACHMENT_ID, "FILE", 4L)
        }

        assertTrue(factory.claimCall.bodyReadStarted.await(2, TimeUnit.SECONDS))
        job.cancelAndJoin()

        assertTrue(factory.claimCall.cancelled)
        assertTrue(factory.releaseRequestSeen.await(2, TimeUnit.SECONDS))
        assertEquals("DELETE", factory.releaseRequest.get()?.method)
        assertEquals("Bearer captured-token", factory.releaseRequest.get()?.header("Authorization"))
        assertEquals(CLAIM, factory.releaseRequest.get()?.header(ATTACHMENT_CLAIM_HEADER))
        assertEquals("one download plus one release", 2, factory.requestCount)
    }

    @Test
    fun lateClaimedResponseAfterCancellationReleasesCapturedSessionClaim() = runBlocking {
        val factory = LateClaimResponseCallFactory()
        val service = service(factory)
        val session = testSession().copy(token = "captured-token")
        val job = launch {
            service.downloadEncryptedAttachment(session, ATTACHMENT_ID, "FILE", 4L)
        }
        delay(100)
        job.cancelAndJoin()
        val lateBody = TrackingResponseBody()

        factory.downloadCall.deliver(
            Response.Builder()
                .request(factory.downloadCall.request())
                .protocol(Protocol.HTTP_1_1)
                .code(200)
                .message("OK")
                .header(ATTACHMENT_CLAIM_HEADER, CLAIM)
                .body(lateBody)
                .build()
        )

        assertTrue(factory.releaseRequestSeen.await(2, TimeUnit.SECONDS))
        assertTrue(lateBody.closed)
        val release = factory.releaseRequest.get()
        assertEquals("DELETE", release?.method)
        assertEquals("Bearer captured-token", release?.header("Authorization"))
        assertEquals(CLAIM, release?.header(ATTACHMENT_CLAIM_HEADER))
        assertEquals("one download plus one release", 2, factory.requestCount)
    }

    @Test
    fun downloadRejectsWrongMediaSizeAndAcceptsUnknownContentLengthOnlyAtExactExpectedSize() = runBlocking<Unit> {
        val server = MockWebServer()
        server.enqueue(MockResponse().setBody(Buffer().write(ByteArray(45))))
        server.enqueue(MockResponse().setChunkedBody(Buffer().write(ByteArray(45)), 16))
        server.start()
        try {
            val service = service()
            assertNull(service.downloadEncryptedAttachment(sessionFor(server), ATTACHMENT_ID, "IMAGE", 5L))
            val request = server.takeRequest()
            assertEquals("/v1/attachment/$ATTACHMENT_ID", request.path)

            val downloaded = service.downloadEncryptedAttachment(sessionFor(server), ATTACHMENT_ID, "IMAGE", 4L)
            assertEquals(45, downloaded?.bytes?.size)
            downloaded?.bytes?.fill(0)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun completionHappensBeforePlaintextIsReturned() = runBlocking {
        val plaintext = "secret".encodeToByteArray()
        val events = mutableListOf<String>()
        val downloaded = EncryptedAttachmentDownload(ByteArray(3) { 9 }, CLAIM)

        val result = decryptAndCompleteAttachment(
            downloaded = downloaded,
            decrypt = {
                events += "decrypt"
                plaintext
            },
            complete = {
                events += "complete"
                true
            },
            release = {
                events += "release"
                true
            }
        )

        assertSame(plaintext, result)
        assertEquals(listOf("decrypt", "complete"), events)
        assertArrayEquals(ByteArray(3), downloaded.bytes)
        plaintext.fill(0)
    }

    @Test
    fun completionFailureReleasesClaimAndWipesPlaintext() = runBlocking {
        val plaintext = ByteArray(6) { 4 }
        var releaseCalled = false
        val result = decryptAndCompleteAttachment(
            downloaded = EncryptedAttachmentDownload(ByteArray(3) { 9 }, CLAIM),
            decrypt = { plaintext },
            complete = { false },
            release = {
                releaseCalled = true
                true
            }
        )

        assertNull(result)
        assertTrue(releaseCalled)
        assertArrayEquals(ByteArray(6), plaintext)
    }

    @Test
    fun decryptFailureReleasesClaimAndDoesNotExposePlaintext() = runBlocking {
        var releaseCalled = false
        val result = decryptAndCompleteAttachment(
            downloaded = EncryptedAttachmentDownload(ByteArray(3) { 9 }, CLAIM),
            decrypt = { throw IllegalArgumentException("invalid ciphertext") },
            complete = { throw IllegalStateException("must not complete") },
            release = {
                releaseCalled = true
                true
            }
        )

        assertNull(result)
        assertTrue(releaseCalled)
    }

    @Test
    fun cancellationPropagatesAfterBestEffortClaimRelease() {
        var releaseCalled = false
        try {
            runBlocking {
                decryptAndCompleteAttachment(
                    downloaded = EncryptedAttachmentDownload(ByteArray(3) { 9 }, CLAIM),
                    decrypt = { throw CancellationException("cancelled") },
                    complete = { throw IllegalStateException("must not complete") },
                    release = {
                        releaseCalled = true
                        true
                    }
                )
            }
        } catch (_: CancellationException) {
            // Expected: cleanup must not convert cancellation into a normal failure.
        }
        assertTrue(releaseCalled)
    }

    @Test
    fun noClaimReturnsAuthenticatedPlaintextWithoutClaimCalls() = runBlocking {
        val plaintext = "owner secret".encodeToByteArray()
        var completeCalled = false
        var releaseCalled = false
        val result = decryptAndCompleteAttachment(
            downloaded = EncryptedAttachmentDownload(ByteArray(2) { 8 }),
            decrypt = { plaintext },
            complete = {
                completeCalled = true
                true
            },
            release = {
                releaseCalled = true
                true
            }
        )

        assertArrayEquals(plaintext, result)
        assertFalse(completeCalled)
        assertFalse(releaseCalled)
        result?.fill(0)
        plaintext.fill(0)
    }

    private fun service(client: OkHttpClient = OkHttpClient()): EncryptedAttachmentService =
        EncryptedAttachmentService(
            appContext = ContextWrapper(null),
            client = client
        )

    private fun sessionFor(server: MockWebServer): NodeSession {
        val baseUrl = server.url("/").toString().removeSuffix("/")
        val endpoint = NodeEndpoint(
            inputUrl = baseUrl,
            apiBaseUrl = baseUrl,
            wsBaseUrl = baseUrl.replaceFirst("http", "ws"),
            displayHost = "test"
        )
        return NodeSession(endpoint, "token", "node", 5)
    }

    private fun testSession(): NodeSession = NodeSession(
        endpoint = NodeEndpoint(
            inputUrl = "http://127.0.0.1",
            apiBaseUrl = "http://127.0.0.1",
            wsBaseUrl = "ws://127.0.0.1",
            displayHost = "test"
        ),
        token = "token",
        nodeId = "node",
        maxRoomsPerUser = 5
    )

    private fun service(callFactory: Call.Factory): EncryptedAttachmentService {
        return EncryptedAttachmentService(
            appContext = ContextWrapper(null),
            client = OkHttpClient(),
            callFactory = callFactory
        )
    }

    private class CancellableTestCall : Call {
        private val request = Request.Builder().url("http://localhost/attachment").build()
        private var callback: Callback? = null
        private var cancelled = false

        override fun request(): Request = request

        override fun execute(): Response = error("not used")

        override fun enqueue(responseCallback: Callback) {
            callback = responseCallback
        }

        override fun cancel() {
            cancelled = true
            callback?.onFailure(this, IOException("cancelled"))
        }

        override fun isExecuted(): Boolean = callback != null

        override fun isCanceled(): Boolean = cancelled

        override fun timeout() = okio.Timeout.NONE

        override fun clone(): Call = CancellableTestCall()

        fun deliver(response: Response) {
            callback?.onResponse(this, response)
        }
    }

    private class TrackingResponseBody : ResponseBody() {
        var closed = false

        override fun contentType() = "application/octet-stream".toMediaType()

        override fun contentLength() = 4L

        override fun source() = okio.Buffer().writeUtf8("late")

        override fun close() {
            closed = true
            super.close()
        }
    }

    private class ClaimCancellationCallFactory : Call.Factory {
        val claimCall = ClaimCancellationCall()
        val releaseRequestSeen = CountDownLatch(1)
        val releaseRequest = AtomicReference<Request?>(null)
        private val calls = AtomicInteger(0)
        val requestCount: Int
            get() = calls.get()

        override fun newCall(request: Request): Call {
            return if (calls.getAndIncrement() == 0) {
                claimCall
            } else {
                ImmediateResponseCall(request) {
                    releaseRequest.set(request)
                    releaseRequestSeen.countDown()
                }
            }
        }
    }

    private class LateClaimResponseCallFactory : Call.Factory {
        val downloadCall = CancellableTestCall()
        val releaseRequestSeen = CountDownLatch(1)
        val releaseRequest = AtomicReference<Request?>(null)
        private val calls = AtomicInteger(0)
        val requestCount: Int
            get() = calls.get()

        override fun newCall(request: Request): Call = if (calls.getAndIncrement() == 0) {
            downloadCall
        } else {
            ImmediateResponseCall(request) {
                releaseRequest.set(request)
                releaseRequestSeen.countDown()
            }
        }
    }

    private class ClaimCancellationCall : Call {
        private val request = Request.Builder().url("http://127.0.0.1/attachment").build()
        val bodyReadStarted = CountDownLatch(1)
        @Volatile var cancelled = false

        override fun request(): Request = request

        override fun execute(): Response = error("not used")

        override fun enqueue(responseCallback: Callback) {
            Thread {
                val body = object : ResponseBody() {
                    override fun contentType() = "application/octet-stream".toMediaType()
                    override fun contentLength() = 45L
                    override fun source(): BufferedSource {
                        bodyReadStarted.countDown()
                        while (!cancelled) Thread.yield()
                        return Buffer().write(ByteArray(45))
                    }
                }
                responseCallback.onResponse(
                    this@ClaimCancellationCall,
                    Response.Builder()
                        .request(request)
                        .protocol(Protocol.HTTP_1_1)
                        .code(200)
                        .message("OK")
                        .header(ATTACHMENT_CLAIM_HEADER, CLAIM)
                        .body(body)
                        .build()
                )
            }.start()
        }

        override fun cancel() {
            cancelled = true
        }

        override fun isExecuted(): Boolean = bodyReadStarted.count == 0L

        override fun isCanceled(): Boolean = cancelled

        override fun timeout() = okio.Timeout.NONE

        override fun clone(): Call = ClaimCancellationCall()
    }

    private class ImmediateResponseCall(
        private val request: Request,
        private val onRequest: () -> Unit
    ) : Call {
        override fun request(): Request = request

        override fun execute(): Response = error("not used")

        override fun enqueue(responseCallback: Callback) {
            onRequest()
            responseCallback.onResponse(
                this,
                Response.Builder()
                    .request(request)
                    .protocol(Protocol.HTTP_1_1)
                    .code(204)
                    .message("No Content")
                    .body(ByteArray(0).toResponseBody(null))
                    .build()
            )
        }

        override fun cancel() = Unit

        override fun isExecuted(): Boolean = true

        override fun isCanceled(): Boolean = false

        override fun timeout() = okio.Timeout.NONE

        override fun clone(): Call = ImmediateResponseCall(request, onRequest)
    }

    private companion object {
        const val ATTACHMENT_ID = "123e4567-e89b-12d3-a456-426614174000"
        const val CLAIM = "123e4567-e89b-12d3-a456-426614174001"
    }
}

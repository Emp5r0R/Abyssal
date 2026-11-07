package com.abyssal.chat.data.network

import android.content.ContextWrapper
import com.abyssal.chat.data.network.v11.AttachmentExchange
import com.abyssal.chat.data.network.v11.AttachmentExchanges
import com.abyssal.chat.data.network.v11.AttachmentFraming
import com.abyssal.chat.data.network.v11.AttachmentTransportClient
import com.abyssal.chat.data.network.v11.uuidBytes
import com.abyssal.chat.domain.model.DecryptedAttachmentDownload
import com.abyssal.chat.domain.model.NodeEndpoint
import com.abyssal.chat.domain.model.NodeSession
import com.abyssal.chat.domain.model.TransportKeys
import com.abyssal.chat.testTransportKeys
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.Collections
import java.util.concurrent.CancellationException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody
import okhttp3.ResponseBody.Companion.toResponseBody
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okio.Buffer
import okio.BufferedSource
import okio.buffer
import okio.source
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.abyssal_core.AttachmentTransportFrame
import uniffi.abyssal_core.AttachmentTransportResult
import uniffi.abyssal_core.AttachmentUploadEncryptor
import uniffi.abyssal_core.AttachmentUploadInput
import uniffi.abyssal_core.decryptAttachmentChunk
import uniffi.abyssal_core.generateAttachmentKey

class EncryptedAttachmentServiceTest {
    @Test
    fun chunkedAttachmentBoundsUseFixedAuthenticatedRecords() {
        assertEquals(
            800L * ATTACHMENT_CHUNK_RECORD_BYTES,
            maxSerializedAttachmentBytes("FILE")
        )
        assertTrue(maxSerializedAttachmentBytes("VIDEO") < maxSerializedAttachmentBytes("FILE"))
        assertTrue(maxSerializedAttachmentBytes("IMAGE") < maxSerializedAttachmentBytes("VIDEO"))
        assertEquals(ATTACHMENT_CHUNK_RECORD_BYTES, expectedEncryptedAttachmentBytes(4L))
        assertNull(expectedEncryptedAttachmentBytes(0L))
        assertNull(expectedEncryptedAttachmentBytes(Long.MAX_VALUE))
    }

    @Test
    fun byteArrayAttachmentSourceOpensTwiceAndDestroyZeroizesItsBackingBytes() {
        val bytes = byteArrayOf(1, 2, 3)
        val source = ByteArrayAttachmentSource(bytes)

        // One pass hashes the ciphertext, the other sends it; a third is refused.
        assertArrayEquals(byteArrayOf(1, 2, 3), source.openStream().use { it.readBytes() })
        assertArrayEquals(byteArrayOf(1, 2, 3), source.openStream().use { it.readBytes() })
        assertTrue(runCatching { source.openStream() }.isFailure)
        source.destroy()
        source.destroy()

        assertArrayEquals(ByteArray(3), bytes)
        assertTrue(runCatching { source.openStream() }.isFailure)
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
    fun chunkDecryptorAcceptsAnySlicingAndRefusesTamperingOrTruncation() {
        val plaintext = ByteArray(300_000) { (it % 251).toByte() }
        val (key, ciphertext) = sealed(plaintext)
        for (slice in listOf(1_000, 65_536, 262_201, ciphertext.size)) {
            val decryptor = AttachmentChunkDecryptor(TEST_CHAT_ID, ATTACHMENT_ID, TEST_SENDER, "FILE", key, plaintext.size.toLong())
            ciphertext.toList().chunked(slice).forEach { assertTrue(decryptor.feed(it.toByteArray())) }
            assertArrayEquals(plaintext, decryptor.finish())
        }

        val tampered = ciphertext.copyOf().also { it[300_000] = (it[300_000].toInt() xor 1).toByte() }
        val rejecting = AttachmentChunkDecryptor(TEST_CHAT_ID, ATTACHMENT_ID, TEST_SENDER, "FILE", key, plaintext.size.toLong())
        assertFalse(rejecting.feed(tampered))
        assertNull(rejecting.finish())

        val truncated = AttachmentChunkDecryptor(TEST_CHAT_ID, ATTACHMENT_ID, TEST_SENDER, "FILE", key, plaintext.size.toLong())
        assertTrue(truncated.feed(ciphertext.copyOf(ciphertext.size - 10)))
        assertNull(truncated.finish())
    }

    @Test
    fun uploadDeclaresTheDigestOfExactlyTheFramedCiphertextAndReturnsTheKey() = runBlocking {
        val relay = FakeAttachmentRelay(results = { kind ->
            if (kind == "upload") AttachmentTransportResult.UploadAccepted(uuidBytes(ATTACHMENT_ID)!!) else AttachmentTransportResult.Failure
        })
        val server = MockWebServer().apply {
            enqueue(MockResponse().setBody(Buffer().write(ByteArray(AttachmentFraming.ACTION_RECORD_BYTES))))
            start()
        }
        try {
            val plaintext = ByteArray(300_000) { (it % 253).toByte() }
            val source = ByteArrayAttachmentSource(plaintext.copyOf())
            val progress = Collections.synchronizedList(mutableListOf<Pair<Long, Long>>())

            val result = service(relay).uploadEncryptedAttachment(
                session = sessionFor(server),
                chatId = TEST_CHAT_ID,
                messageId = ATTACHMENT_ID,
                senderUsername = TEST_SENDER,
                mediaType = "file",
                source = source,
                oneTimeView = true,
                deleteAfterDownload = false,
                ttlSec = 600,
                onProgress = { sent, total -> progress += sent to total }
            )

            assertTrue(result.accepted)
            assertEquals(ATTACHMENT_ID, result.attachmentId)
            val key = requireNotNull(result.encryptionKey)
            val request = server.takeRequest()
            assertEquals("/v3/attachment", request.path)
            assertTrue(request.getHeader("Authorization") == null)
            val body = request.body.readByteArray()
            assertEquals(request.getHeader("Content-Length")?.toInt(), body.size)

            val input = relay.uploads.single()
            assertEquals(TEST_CHAT_ID, input.chatId)
            assertEquals("FILE", input.mediaType)
            assertTrue(input.oneTime && input.deleteAfterDownload)
            assertEquals(600u, input.requestedTtlSec)
            val ciphertext = relay.unframe(body)
            assertEquals(input.ciphertextLen.toLong(), ciphertext.size.toLong())
            assertArrayEquals(MessageDigest.getInstance("SHA-256").digest(ciphertext), input.ciphertextSha256)
            // 2 chunk records = 524,402 bytes = 3 data frames, padded to a bucket of 4, then the end frame.
            assertEquals(AttachmentFraming.ACTION_RECORD_BYTES + 5 * AttachmentFraming.STREAM_FRAME_BYTES, body.size)
            assertArrayEquals(plaintext, decrypt(key, ciphertext, plaintext.size))
            assertEquals(300_000L to 300_000L, progress.last())
            assertTrue(relay.exchanges.all { it.closed })
            assertTrue(runCatching { source.openStream() }.isFailure)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun refusedUploadWipesTheKeyAndReportsFailure() = runBlocking {
        val relay = FakeAttachmentRelay(results = { AttachmentTransportResult.Failure })
        val server = MockWebServer().apply {
            enqueue(MockResponse().setBody(Buffer().write(ByteArray(AttachmentFraming.ACTION_RECORD_BYTES))))
            start()
        }
        try {
            val result = service(relay).uploadEncryptedAttachment(
                sessionFor(server), TEST_CHAT_ID, ATTACHMENT_ID, TEST_SENDER, "FILE",
                ByteArrayAttachmentSource(byteArrayOf(1, 2, 3)), false, false, 0
            ) { _, _ -> }
            assertFalse(result.accepted)
            assertNull(result.encryptionKey)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun downloadDecryptsTheFramedStreamAndKeepsTheClaimForCompletion() = runBlocking {
        val plaintext = ByteArray(300_000) { (it % 247).toByte() }
        val (key, ciphertext) = sealed(plaintext)
        val relay = FakeAttachmentRelay(results = { kind ->
            when (kind) {
                "download" -> accepted(ciphertext.size.toLong(), CLAIM)
                else -> AttachmentTransportResult.Success
            }
        })
        val server = MockWebServer().apply {
            enqueue(MockResponse().setBody(Buffer().write(relay.downloadBody(ciphertext))))
            enqueue(MockResponse().setBody(Buffer().write(ByteArray(AttachmentFraming.ACTION_RECORD_BYTES))))
            start()
        }
        try {
            val service = service(relay)
            val session = sessionFor(server)
            val downloaded = download(service, session, key, plaintext.size.toLong())!!

            assertArrayEquals(plaintext, downloaded.bytes)
            assertEquals(CLAIM, downloaded.claim)
            assertEquals("/v3/attachment", server.takeRequest().path)
            assertArrayEquals(uuidBytes(ATTACHMENT_ID), relay.ids.first())

            assertTrue(service.completeAttachmentDownload(session, ATTACHMENT_ID, CLAIM))
            assertEquals(listOf("download", "complete"), relay.exchanges.map { it.kind })
            assertArrayEquals(uuidBytes(CLAIM), relay.claims.single())
            assertTrue(relay.exchanges.all { it.closed })
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun failedOrTamperedDownloadReleasesItsClaimWithoutExposingPlaintext() = runBlocking {
        val plaintext = ByteArray(10_000) { 5 }
        val (key, ciphertext) = sealed(plaintext)
        val cases = listOf(
            "tampered ciphertext" to (ciphertext.copyOf().also { it[100] = (it[100].toInt() xor 1).toByte() } to ciphertext.size.toLong()),
            "a length that differs from the message" to (ciphertext to ciphertext.size.toLong() + 1)
        )
        for ((label, case) in cases) {
            val (served, announced) = case
            val relay = FakeAttachmentRelay(results = { kind ->
                if (kind == "download") accepted(announced, CLAIM) else AttachmentTransportResult.Success
            })
            val server = MockWebServer().apply {
                enqueue(MockResponse().setBody(Buffer().write(relay.downloadBody(served))))
                enqueue(MockResponse().setBody(Buffer().write(ByteArray(AttachmentFraming.ACTION_RECORD_BYTES))))
                start()
            }
            try {
                assertNull(label, download(service(relay), sessionFor(server), key, plaintext.size.toLong()))
                assertEquals(label, listOf("download", "release"), relay.exchanges.map { it.kind })
                assertArrayEquals(label, uuidBytes(CLAIM), relay.claims.single())
                assertEquals(label, 2, server.requestCount)
            } finally {
                server.shutdown()
            }
        }
    }

    @Test
    fun ownerDeleteAndClaimActionsReportOnlyAuthenticatedSuccess() = runBlocking {
        val server = MockWebServer().apply {
            repeat(3) { enqueue(MockResponse().setBody(Buffer().write(ByteArray(AttachmentFraming.ACTION_RECORD_BYTES)))) }
            start()
        }
        try {
            var answer: AttachmentTransportResult = AttachmentTransportResult.Success
            val relay = FakeAttachmentRelay(results = { answer })
            val service = service(relay)
            val session = sessionFor(server)
            assertTrue(service.deleteUploadedAttachment(session, ATTACHMENT_ID))
            answer = AttachmentTransportResult.Failure
            assertFalse(service.releaseAttachmentDownloadClaim(session, ATTACHMENT_ID, CLAIM))
            assertFalse(service.deleteUploadedAttachment(session, "../../v1/account/logout"))
            assertFalse(service.completeAttachmentDownload(session, ATTACHMENT_ID, "not-a-claim"))
            assertEquals(listOf("delete", "release"), relay.exchanges.map { it.kind })
            assertEquals(2, server.requestCount)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun invalidMessageBindingIsRejectedBeforeNetwork() = runBlocking {
        val relay = FakeAttachmentRelay(results = { AttachmentTransportResult.Failure })
        val factory = object : Call.Factory {
            override fun newCall(request: Request): Call = error("no network expected")
        }
        val result = service(relay, factory).uploadEncryptedAttachment(
            testSession(), TEST_CHAT_ID, "not-a-uuid", TEST_SENDER, "FILE",
            ByteArrayAttachmentSource(byteArrayOf(1)), false, false, 0
        ) { _, _ -> }
        assertFalse(result.accepted)
        assertTrue(relay.exchanges.isEmpty())
        assertNull(download(service(relay, factory), testSession(), ByteArray(32), 0L))
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
        val relay = FakeAttachmentRelay(results = { AttachmentTransportResult.Failure })
        val service = service(relay, object : Call.Factory {
            override fun newCall(request: Request): Call = call
        })
        val job = launch {
            service.uploadEncryptedAttachment(
                session = testSession(),
                chatId = "dm_bob",
                messageId = ATTACHMENT_ID,
                senderUsername = "Alice",
                mediaType = "FILE",
                source = ByteArrayAttachmentSource(byteArrayOf(1)),
                oneTimeView = false,
                deleteAfterDownload = false,
                ttlSec = 0,
                onProgress = { _, _ -> }
            )
        }
        delay(200)

        job.cancelAndJoin()

        assertTrue(call.isCanceled())
    }

    @Test
    fun cancellationAfterTheClaimIsOpenedReleasesItWithoutReturningBytes() = runBlocking {
        val relay = FakeAttachmentRelay(results = { kind ->
            if (kind == "download") accepted(ATTACHMENT_CHUNK_RECORD_BYTES, CLAIM) else AttachmentTransportResult.Success
        })
        val factory = ClaimCancellationCallFactory()
        val service = service(relay, factory)
        val job = launch(Dispatchers.Default) {
            download(service, testSession(), ByteArray(32) { 1 }, 4L)
        }

        assertTrue(factory.claimCall.headDelivered.await(2, TimeUnit.SECONDS))
        delay(100)
        job.cancelAndJoin()

        assertTrue(factory.claimCall.cancelled)
        assertTrue(factory.releaseRequestSeen.await(2, TimeUnit.SECONDS))
        assertEquals("/v3/attachment", factory.releaseRequest.get()?.url?.encodedPath)
        assertTrue(relay.exchanges.any { it.kind == "release" })
        assertArrayEquals(uuidBytes(CLAIM), relay.claims.single())
        assertEquals("one download plus one release", 2, factory.requestCount)
    }

    @Test
    fun lateClaimedResponseAfterCancellationReleasesTheClaim() = runBlocking {
        val relay = FakeAttachmentRelay(results = { kind ->
            if (kind == "download") accepted(ATTACHMENT_CHUNK_RECORD_BYTES, CLAIM) else AttachmentTransportResult.Success
        })
        val factory = LateClaimResponseCallFactory()
        val service = service(relay, factory)
        val job = launch {
            download(service, testSession(), ByteArray(32) { 1 }, 4L)
        }
        delay(100)
        job.cancelAndJoin()

        factory.downloadCall.deliver(
            Response.Builder()
                .request(factory.downloadCall.request())
                .protocol(Protocol.HTTP_1_1)
                .code(200)
                .message("OK")
                .body(ByteArray(AttachmentFraming.ACTION_RECORD_BYTES).toResponseBody("application/octet-stream".toMediaType()))
                .build()
        )

        assertTrue(factory.releaseRequestSeen.await(2, TimeUnit.SECONDS))
        assertArrayEquals(uuidBytes(CLAIM), relay.claims.single())
        assertEquals("one download plus one release", 2, factory.requestCount)
    }

    @Test
    fun completionHappensBeforePlaintextIsReturned() = runBlocking {
        val plaintext = "secret".encodeToByteArray()
        val events = mutableListOf<String>()
        val downloaded = DecryptedAttachmentDownload(ByteArray(3) { 9 }, CLAIM)

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
    fun returnedDownloadBufferIsNotWiped() = runBlocking {
        // The app returns the already-decrypted download array itself; it must reach the caller intact.
        val downloaded = DecryptedAttachmentDownload("RIFF....WAVE".encodeToByteArray(), CLAIM)
        val result = decryptAndCompleteAttachment(
            downloaded = downloaded,
            decrypt = { downloaded.bytes },
            complete = { true },
            release = { true }
        )
        assertSame(downloaded.bytes, result)
        assertEquals("RIFF....WAVE", result!!.decodeToString())

        val failed = DecryptedAttachmentDownload(ByteArray(4) { 7 }, CLAIM)
        assertNull(decryptAndCompleteAttachment(failed, decrypt = { failed.bytes }, complete = { false }, release = { true }))
        assertArrayEquals(ByteArray(4), failed.bytes)
    }

    @Test
    fun completionFailureReleasesClaimAndWipesPlaintext() = runBlocking {
        val plaintext = ByteArray(6) { 4 }
        var releaseCalled = false
        val result = decryptAndCompleteAttachment(
            downloaded = DecryptedAttachmentDownload(ByteArray(3) { 9 }, CLAIM),
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
            downloaded = DecryptedAttachmentDownload(ByteArray(3) { 9 }, CLAIM),
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
                    downloaded = DecryptedAttachmentDownload(ByteArray(3) { 9 }, CLAIM),
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
            downloaded = DecryptedAttachmentDownload(ByteArray(2) { 8 }),
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

    /** Seals [plaintext] the way an upload does and returns the key and chunk records. */
    private fun sealed(plaintext: ByteArray): Pair<ByteArray, ByteArray> {
        val key = generateAttachmentKey()
        val records = ByteArrayOutputStream()
        AttachmentUploadEncryptor(TEST_CHAT_ID, ATTACHMENT_ID, TEST_SENDER, "FILE", key, plaintext.size.toULong()).use { encryptor ->
            plaintext.toList().chunked(ATTACHMENT_CHUNK_PLAINTEXT_BYTES.toInt()).forEachIndexed { index, chunk ->
                records.write(encryptor.encryptChunk(index.toUInt(), chunk.toByteArray()))
            }
        }
        return key to records.toByteArray()
    }

    private fun decrypt(key: ByteArray, ciphertext: ByteArray, plaintextBytes: Int): ByteArray {
        val output = ByteArrayOutputStream()
        ciphertext.toList().chunked(ATTACHMENT_CHUNK_RECORD_BYTES.toInt()).forEachIndexed { index, record ->
            output.write(
                decryptAttachmentChunk(
                    TEST_CHAT_ID, ATTACHMENT_ID, TEST_SENDER, "FILE", key,
                    plaintextBytes.toULong(), index.toUInt(), record.toByteArray()
                )
            )
        }
        return output.toByteArray()
    }

    private fun accepted(length: Long, claim: String?) = AttachmentTransportResult.DownloadAccepted(
        claimId = claim?.let(::uuidBytes),
        ciphertextLen = length.toULong(),
        ciphertextSha256 = ByteArray(32) { 1 },
        dataFrameCount = 1u,
        bucketFrameCount = 1u
    )

    private suspend fun download(
        service: EncryptedAttachmentService,
        session: NodeSession,
        key: ByteArray,
        expectedPlaintextBytes: Long
    ): DecryptedAttachmentDownload? = service.downloadDecryptedAttachment(
        session = session,
        attachmentId = ATTACHMENT_ID,
        chatId = TEST_CHAT_ID,
        messageId = ATTACHMENT_ID,
        senderUsername = TEST_SENDER,
        mediaType = "FILE",
        encryptionKey = key,
        expectedPlaintextBytes = expectedPlaintextBytes
    )

    private fun service(relay: FakeAttachmentRelay, callFactory: Call.Factory = OkHttpClient()) =
        EncryptedAttachmentService(ContextWrapper(null), callFactory, AttachmentTransportClient(callFactory, relay))

    private fun sessionFor(server: MockWebServer): NodeSession {
        val baseUrl = server.url("/").toString().removeSuffix("/")
        return NodeSession(
            NodeEndpoint(baseUrl, baseUrl, baseUrl.replaceFirst("http", "ws"), "test"),
            "token", "node", 5, testTransportKeys()
        )
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
        maxRoomsPerUser = 5,
        transport = testTransportKeys()
    )

    /**
     * A relay stand-in at the record layer: a fake frame is [kind, u32 payload
     * length, payload, zero fill] at the real frame size.
     */
    private class FakeAttachmentRelay(
        private val results: (kind: String) -> AttachmentTransportResult
    ) : AttachmentExchanges {
        val exchanges: MutableList<Exchange> = Collections.synchronizedList(mutableListOf())
        val uploads = mutableListOf<AttachmentUploadInput>()
        val ids = mutableListOf<ByteArray>()
        val claims: MutableList<ByteArray> = Collections.synchronizedList(mutableListOf())

        inner class Exchange(val kind: String, private val ciphertextLen: Long = 0L) : AttachmentExchange {
            @Volatile var closed = false
            private var endSeen = false
            override fun requestBytes() = ByteArray(AttachmentFraming.ACTION_RECORD_BYTES) { kind.length.toByte() }
            override fun uploadDataFrameCount() =
                ((ciphertextLen + AttachmentFraming.STREAM_PAYLOAD_BYTES - 1) / AttachmentFraming.STREAM_PAYLOAD_BYTES).toInt()
            override fun uploadBucketFrameCount() = Integer.highestOneBit(maxOf(1, uploadDataFrameCount() * 2 - 1))
            override fun sealDataFrame(payload: ByteArray) = frame(1, payload)
            override fun sealPaddingFrame() = frame(2)
            override fun sealEndFrame() = frame(3)
            override fun openResponse(reply: ByteArray): AttachmentTransportResult {
                require(reply.size == AttachmentFraming.ACTION_RECORD_BYTES)
                return results(kind)
            }
            override fun openStreamFrame(frame: ByteArray): AttachmentTransportFrame {
                require(frame.size == AttachmentFraming.STREAM_FRAME_BYTES)
                val length = ByteBuffer.wrap(frame, 1, 4).int
                return when (frame[0].toInt()) {
                    1 -> AttachmentTransportFrame.Data(frame.copyOfRange(5, 5 + length))
                    2 -> AttachmentTransportFrame.Padding
                    else -> AttachmentTransportFrame.End.also { endSeen = true }
                }
            }
            override fun streamComplete() = endSeen
            override fun close() {
                closed = true
            }
        }

        private fun track(exchange: Exchange) = exchange.also(exchanges::add)

        override fun beginUpload(keys: TransportKeys, input: AttachmentUploadInput): AttachmentExchange {
            uploads += input.copy(ciphertextSha256 = input.ciphertextSha256.copyOf())
            return track(Exchange("upload", input.ciphertextLen.toLong()))
        }

        override fun beginDownload(keys: TransportKeys, attachmentId: ByteArray): AttachmentExchange {
            ids += attachmentId.copyOf()
            return track(Exchange("download"))
        }

        override fun completeDownload(keys: TransportKeys, attachmentId: ByteArray, claimId: ByteArray): AttachmentExchange {
            claims += claimId.copyOf()
            return track(Exchange("complete"))
        }

        override fun releaseDownload(keys: TransportKeys, attachmentId: ByteArray, claimId: ByteArray): AttachmentExchange {
            claims += claimId.copyOf()
            return track(Exchange("release"))
        }

        override fun deleteAttachment(keys: TransportKeys, attachmentId: ByteArray) = track(Exchange("delete"))

        /** The ciphertext carried by an upload body's data frames. */
        fun unframe(body: ByteArray): ByteArray {
            val output = ByteArrayOutputStream()
            var offset = AttachmentFraming.ACTION_RECORD_BYTES
            while (offset < body.size) {
                val frame = body.copyOfRange(offset, offset + AttachmentFraming.STREAM_FRAME_BYTES)
                if (frame[0].toInt() == 1) output.write(frame, 5, ByteBuffer.wrap(frame, 1, 4).int)
                offset += AttachmentFraming.STREAM_FRAME_BYTES
            }
            return output.toByteArray()
        }

        /** A download response: head record, data frames, one padding frame, end frame. */
        fun downloadBody(ciphertext: ByteArray): ByteArray {
            val output = ByteArrayOutputStream()
            output.write(ByteArray(AttachmentFraming.ACTION_RECORD_BYTES))
            ciphertext.toList().chunked(AttachmentFraming.STREAM_PAYLOAD_BYTES).forEach { output.write(frame(1, it.toByteArray())) }
            output.write(frame(2))
            output.write(frame(3))
            return output.toByteArray()
        }

        companion object {
            fun frame(kind: Int, payload: ByteArray = ByteArray(0)): ByteArray {
                val bytes = ByteArray(AttachmentFraming.STREAM_FRAME_BYTES)
                bytes[0] = kind.toByte()
                ByteBuffer.wrap(bytes, 1, 4).putInt(payload.size)
                payload.copyInto(bytes, 5)
                return bytes
            }
        }
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

    /** Delivers the head record, then stalls the body until the call is canceled. */
    private class ClaimCancellationCall : Call {
        private val request = Request.Builder().url("http://127.0.0.1/v3/attachment").build()
        val headDelivered = CountDownLatch(1)
        @Volatile var cancelled = false

        override fun request(): Request = request

        override fun execute(): Response = error("not used")

        override fun enqueue(responseCallback: Callback) {
            val stream = object : java.io.InputStream() {
                private var position = 0
                override fun read(): Int {
                    if (position < AttachmentFraming.ACTION_RECORD_BYTES) {
                        position += 1
                        if (position == AttachmentFraming.ACTION_RECORD_BYTES) headDelivered.countDown()
                        return 0
                    }
                    while (!cancelled) Thread.yield()
                    throw IOException("canceled")
                }
            }
            Thread {
                val body = object : ResponseBody() {
                    override fun contentType() = "application/octet-stream".toMediaType()
                    override fun contentLength() = -1L
                    override fun source(): BufferedSource = stream.source().buffer()
                }
                responseCallback.onResponse(
                    this@ClaimCancellationCall,
                    Response.Builder()
                        .request(request)
                        .protocol(Protocol.HTTP_1_1)
                        .code(200)
                        .message("OK")
                        .body(body)
                        .build()
                )
            }.start()
        }

        override fun cancel() {
            cancelled = true
        }

        override fun isExecuted(): Boolean = true

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
                    .code(200)
                    .message("OK")
                    .body(ByteArray(AttachmentFraming.ACTION_RECORD_BYTES).toResponseBody(null))
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
        const val ATTACHMENT_ID = "123e4567-e89b-42d3-a456-426614174000"
        const val CLAIM = "123e4567-e89b-42d3-a456-426614174001"
        const val TEST_CHAT_ID = "dm_alice_bob"
        const val TEST_SENDER = "Alice"
    }
}

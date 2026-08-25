package com.abyssal.chat.data.network

import com.abyssal.chat.data.repository.InMemoryMessageRepository
import com.abyssal.chat.domain.model.NodeEndpoint
import com.abyssal.chat.domain.model.NodeSession
import com.abyssal.chat.domain.model.ChatSession
import com.abyssal.chat.domain.model.DirectoryStamp
import com.abyssal.chat.domain.model.DirectoryEvidenceStatus
import com.abyssal.chat.domain.model.EncryptedTransportPayload
import com.abyssal.chat.domain.model.IdentityStateSnapshot
import com.abyssal.chat.domain.model.IncomingTransportPayload
import com.abyssal.chat.domain.model.Message
import com.abyssal.chat.domain.model.PrekeyLease
import com.abyssal.chat.domain.model.RecipientEnvelope
import com.abyssal.chat.domain.repository.OutboundSendResult
import java.util.concurrent.CountDownLatch
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.yield
import kotlinx.coroutines.runBlocking
import okhttp3.Call
import okhttp3.Callback
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okio.ByteString
import okio.Buffer
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RealChatTransportSecurityTest {
    private companion object {
        const val ACK_CAPACITY = 64
        const val ACK_SIZE = 64
        val TEST_BUILD_ATTESTATION = BuildAttestationProvider {
            BuildAttestation("android", "2.2.0", "A".repeat(86), "1".repeat(40))
        }
    }

    @Test
    fun oversizedInboundTextClosesWithPolicyViolationAndDisconnects() = runBlocking {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val socket = RecordingWebSocket()
        installSocket(transport, socket)

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
    fun purgeCloseRequiresExactCodeAndReason() {
        assertTrue(isPurgeClose(PURGE_CLOSE_CODE, PURGE_CLOSE_REASON))
        assertFalse(isPurgeClose(PURGE_CLOSE_CODE, "Purge"))
        assertFalse(isPurgeClose(PURGE_CLOSE_CODE, "purge "))
        assertFalse(isPurgeClose(1000, PURGE_CLOSE_REASON))
    }

    @Test
    fun prekeyLeaseParserRequiresExactV9TupleCanonicalIdentityAndPositiveLongExpiry() {
        val publicKey = ByteArray(608) { 7 }
        val valid = JSONObject()
            .put("type", "prekey_lease")
            .put("chat_id", "dm_alice")
            .put("message_id", "message-1")
            .put("recipient_username", "Alice")
            .put("recipient_public_key_b64", encode(publicKey))
            .put("prekey_id", "prekey-1")
            // The relay's lease clock is authoritative. This deliberately
            // looks expired to any current client clock but is valid on-wire.
            .put("expires_at_ms", 1L)

        val parsed = valid.toPrekeyLease()
        assertNotNull(parsed)
        assertEquals("dm_alice", parsed?.chatId)
        assertEquals("message-1", parsed?.messageId)
        assertEquals("Alice", parsed?.recipientUsername)
        assertEquals("prekey-1", parsed?.prekeyId)
        assertArrayEquals(publicKey, parsed?.recipientPublicKey)
        parsed?.recipientPublicKey?.fill(0)

        assertNull(valid.put("extra", true).toPrekeyLease())
        assertNull(valid.put("expires_at_ms", 0L).toPrekeyLease())
        assertNull(valid.put("expires_at_ms", 1).toPrekeyLease())
        assertNull(valid.put("recipient_public_key_b64", encode(ByteArray(128))).toPrekeyLease())
        assertNull(valid.put("prekey_id", "").toPrekeyLease())
        publicKey.fill(0)
    }

    @Test
    fun pendingPrekeyLeaseCompletesOnlyForMatchingTupleAndDrainsOnClose() = runBlocking {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val socket = RecordingWebSocket()
        val listener = installSocket(transport, socket)
        val pending = async(start = CoroutineStart.UNDISPATCHED) {
            transport.requestPrekeyLease("dm_alice", "message-lease", "Alice")
        }
        awaitSent(socket, 1)
        val request = sentControl(socket.sentTexts.single())
        assertEquals(
            setOf("type", "chat_id", "message_id", "recipient_username"),
            request.keys().asSequence().toSet()
        )
        assertEquals("prekey_lease", request.getString("type"))

        val response = JSONObject()
            .put("type", "prekey_lease")
            .put("chat_id", "dm_alice")
            .put("message_id", "message-lease")
            .put("recipient_username", "Alice")
            .put("recipient_public_key_b64", encode(ByteArray(608) { 4 }))
            .put("prekey_id", "prekey-2")
            .put("expires_at_ms", System.currentTimeMillis() + 5_000L)
        listener.onMessage(socket, paddedControl(response.put("message_id", "wrong")))
        assertFalse(pending.isCompleted)
        listener.onMessage(socket, paddedControl(response.put("message_id", "message-lease")))
        val lease = pending.await()
        assertEquals("prekey-2", lease?.prekeyId)
        lease?.recipientPublicKey?.fill(0)

        val draining = async(start = CoroutineStart.UNDISPATCHED) {
            transport.requestPrekeyLease("dm_alice", "message-drain", "Alice")
        }
        awaitSent(socket, 2)
        listener.onClosed(socket, 1000, "bye")
        assertNull(draining.await())
    }

    @Test
    fun completedPrekeyLeaseResultIsWipedWhenCancellationWinsCompletionRace() {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val key = ByteArray(608) { 9 }
        val result = CompletableDeferred<PrekeyLease?>()
        result.complete(
            PrekeyLease(
                chatId = "dm_alice",
                messageId = "message-race",
                recipientUsername = "Alice",
                recipientPublicKey = key,
                prekeyId = "prekey-1",
                expiresAtMs = 1L,
                connectionGeneration = 1L
            )
        )

        val wipe = RealChatTransport::class.java.getDeclaredMethod(
            "wipeCompletedPrekeyResult",
            CompletableDeferred::class.java
        )
        wipe.isAccessible = true
        wipe.invoke(transport, result)

        assertArrayEquals(ByteArray(608), key)
    }

    @Test
    fun unusedPrekeyLeaseReleaseUsesExactBoundedSchema() = runBlocking {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val socket = RecordingWebSocket()
        installSocket(transport, socket)
        assertTrue(transport.releasePrekeyLease("dm_alice", "message-1", "Alice", "prekey-1"))
        val frame = sentControl(socket.sentTexts.single())
        assertEquals(
            setOf("type", "chat_id", "message_id", "recipient_username", "prekey_id"),
            frame.keys().asSequence().toSet()
        )
        assertEquals("prekey_lease_release", frame.getString("type"))
    }

    @Test
    fun messageResultParserRequiresExactBoundedSchemaAndBooleanDecision() {
        val valid = JSONObject()
            .put("type", "message_result")
            .put("message_id", "message-1")
            .put("accepted", true)
        assertEquals("message-1" to true, valid.toOutboundMessageResult())
        assertNull(valid.put("accepted", 1).toOutboundMessageResult())
        assertNull(valid.put("accepted", true).put("extra", true).toOutboundMessageResult())
        assertNull(
            JSONObject()
                .put("type", "message_result")
                .put("message_id", "message-1/other")
                .put("accepted", false)
                .toOutboundMessageResult()
        )
        assertNull(valid.put("type", "result").toOutboundMessageResult())
    }

    @Test
    fun acknowledgementResultParserRequiresExactBoundedSchemaAndBooleanDecision() {
        val valid = JSONObject()
            .put("type", "ack_result")
            .put("message_id", "message-1")
            .put("accepted", true)
        assertEquals("message-1" to true, valid.toAcknowledgementResult())
        assertEquals("message-1" to false, valid.put("accepted", false).toAcknowledgementResult())
        assertNull(valid.put("accepted", 1).toAcknowledgementResult())
        assertNull(valid.put("accepted", true).put("extra", true).toAcknowledgementResult())
        assertNull(
            JSONObject().put("type", "ack_result").put("message_id", "message-1")
                .toAcknowledgementResult()
        )
        assertNull(valid.put("accepted", true).put("type", "message_result").toAcknowledgementResult())
        assertNull(
            valid.put("type", "ack_result")
                .put("message_id", "message/invalid")
                .toAcknowledgementResult()
        )
    }

    @Test
    fun acceptedAndRejectedAcknowledgementsCompleteOnlyFromMatchingAckResult() = runBlocking {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val socket = RecordingWebSocket()
        val listener = installSocket(transport, socket)

        val accepted = async(start = CoroutineStart.UNDISPATCHED) {
            transport.acknowledgeMessage(
                chatId = "forum_alpha",
                messageId = "message-accepted",
                senderUsername = "Alice",
                state = validAckState(),
                usedPrekeyId = "",
                ackSignature = ByteArray(ACK_SIZE) { 7 }
            )
        }
        awaitSent(socket, 1)
        val acceptedFrame = sentControl(socket.sentTexts.single())
        assertEquals("message_ack", acceptedFrame.getString("type"))
        assertFalse(acceptedFrame.has("directory_node_id"))
        assertFalse(acceptedFrame.has("directory_revision"))
        assertFalse(acceptedFrame.has("directory_digest"))
        assertFalse(accepted.isCompleted)
        listener.onMessage(
            socket,
            ackResult("message-accepted", accepted = true)
        )
        assertEquals(OutboundSendResult.ACCEPTED, accepted.await())

        val rejected = async(start = CoroutineStart.UNDISPATCHED) {
            transport.acknowledgeMessage(
                chatId = "forum_alpha",
                messageId = "message-rejected",
                senderUsername = "Alice",
                state = validAckState(),
                usedPrekeyId = "",
                ackSignature = ByteArray(ACK_SIZE) { 8 }
            )
        }
        awaitSent(socket, 2)
        listener.onMessage(socket, ackResult("message-rejected", accepted = false))
        assertEquals(OutboundSendResult.REJECTED, rejected.await())
    }

    @Test
    fun malformedUnknownAndDuplicateAcknowledgementsCloseTheCurrentSocket() = runBlocking {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val socket = RecordingWebSocket()
        val listener = installSocket(transport, socket)

        listener.onMessage(socket, paddedControl(JSONObject().put("type", "ack_result")))
        assertEquals(1008, socket.closeCode)

        val unknownSocket = RecordingWebSocket()
        val unknownListener = installSocket(transport, unknownSocket, generation = 2L)
        unknownListener.onMessage(unknownSocket, ackResult("not-pending", accepted = true))
        assertEquals(1008, unknownSocket.closeCode)

        val duplicateSocket = RecordingWebSocket()
        val duplicateListener = installSocket(transport, duplicateSocket, generation = 3L)
        val pending = async(start = CoroutineStart.UNDISPATCHED) {
            transport.acknowledgeMessage(
                chatId = "forum_alpha",
                messageId = "message-duplicate",
                senderUsername = "Alice",
                state = validAckState(),
                usedPrekeyId = "",
                ackSignature = ByteArray(ACK_SIZE) { 9 }
            )
        }
        awaitSent(duplicateSocket, 1)
        duplicateListener.onMessage(duplicateSocket, ackResult("message-duplicate", accepted = true))
        assertEquals(OutboundSendResult.ACCEPTED, pending.await())
        duplicateListener.onMessage(duplicateSocket, ackResult("message-duplicate", accepted = true))
        assertEquals(1008, duplicateSocket.closeCode)
    }

    @Test
    fun acknowledgementWaitersRecoverExactFramesAcrossNetworkLoss() = runBlocking {
        suspend fun pendingCall(transport: RealChatTransport, id: String) =
            transport.acknowledgeMessage(
                chatId = "forum_alpha",
                messageId = id,
                senderUsername = "Alice",
                state = validAckState(),
                usedPrekeyId = "",
                ackSignature = ByteArray(ACK_SIZE) { 1 }
            )

        val canceledTransport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val canceledSocket = RecordingWebSocket()
        installSocket(canceledTransport, canceledSocket)
        val canceled = async(start = CoroutineStart.UNDISPATCHED) {
            pendingCall(canceledTransport, "message-canceled")
        }
        awaitSent(canceledSocket, 1)
        canceled.cancel()
        assertTrue(runCatching { canceled.await() }.isFailure)
        assertEquals(1008, canceledSocket.closeCode)

        val disconnectedTransport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val disconnectedSocket = RecordingWebSocket()
        installSocket(disconnectedTransport, disconnectedSocket)
        val disconnected = async(start = CoroutineStart.UNDISPATCHED) {
            pendingCall(disconnectedTransport, "message-disconnect")
        }
        awaitSent(disconnectedSocket, 1)
        disconnectedTransport.disconnect()
        assertEquals(OutboundSendResult.AMBIGUOUS, disconnected.await())

        val closedTransport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val closedSocket = RecordingWebSocket()
        val closedListener = installSocket(closedTransport, closedSocket)
        val closed = async(start = CoroutineStart.UNDISPATCHED) {
            pendingCall(closedTransport, "message-closed")
        }
        awaitSent(closedSocket, 1)
        val closedExactFrame = closedSocket.sentTexts.single()
        closedListener.onClosed(closedSocket, 1000, "bye")
        assertFalse(closed.isCompleted)
        val recoveredClosedSocket = RecordingWebSocket()
        val recoveredClosedListener = installSocket(closedTransport, recoveredClosedSocket, generation = 2L)
        recoveredClosedListener.onOpen(recoveredClosedSocket, openResponse(recoveredClosedSocket))
        awaitSent(recoveredClosedSocket, 1)
        assertEquals(closedExactFrame, recoveredClosedSocket.sentTexts.single())
        recoveredClosedListener.onMessage(
            recoveredClosedSocket,
            ackResult("message-closed", accepted = true)
        )
        assertEquals(OutboundSendResult.ACCEPTED, closed.await())

        val failedTransport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val failedSocket = RecordingWebSocket()
        val failedListener = installSocket(failedTransport, failedSocket)
        val failed = async(start = CoroutineStart.UNDISPATCHED) {
            pendingCall(failedTransport, "message-failed")
        }
        awaitSent(failedSocket, 1)
        val failedExactFrame = failedSocket.sentTexts.single()
        failedListener.onFailure(failedSocket, IllegalStateException("socket"), null)
        assertFalse(failed.isCompleted)
        val recoveredFailedSocket = RecordingWebSocket()
        val recoveredFailedListener = installSocket(failedTransport, recoveredFailedSocket, generation = 2L)
        recoveredFailedListener.onOpen(recoveredFailedSocket, openResponse(recoveredFailedSocket))
        awaitSent(recoveredFailedSocket, 1)
        assertEquals(failedExactFrame, recoveredFailedSocket.sentTexts.single())
        recoveredFailedListener.onMessage(
            recoveredFailedSocket,
            ackResult("message-failed", accepted = false)
        )
        assertEquals(OutboundSendResult.REJECTED, failed.await())
    }

    @Test
    fun purgeCloseSettlesPendingAcknowledgementAndSignalsWipe() = runBlocking {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val socket = RecordingWebSocket()
        val listener = installSocket(transport, socket)
        val pending = async(start = CoroutineStart.UNDISPATCHED) {
            transport.acknowledgeMessage(
                chatId = "forum_alpha",
                messageId = "message-purge",
                senderUsername = "Alice",
                state = validAckState(),
                usedPrekeyId = "",
                ackSignature = ByteArray(ACK_SIZE) { 4 }
            )
        }
        awaitSent(socket, 1)

        listener.onClosed(socket, PURGE_CLOSE_CODE, PURGE_CLOSE_REASON)

        assertEquals(OutboundSendResult.AMBIGUOUS, pending.await())
        assertEquals(transport.currentConnectionGeneration(), transport.getIncomingWipeCommands().first())
    }

    @Test
    fun acknowledgementWaitersHaveSeparateBoundedCapacity() = runBlocking {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val socket = RecordingWebSocket()
        val listener = installSocket(transport, socket)
        val waiters = (0 until ACK_CAPACITY).map { index ->
            async(start = CoroutineStart.UNDISPATCHED) {
                transport.acknowledgeMessage(
                    chatId = "forum_alpha",
                    messageId = "message-capacity-$index",
                    senderUsername = "Alice",
                    state = validAckState(),
                    usedPrekeyId = "",
                    ackSignature = ByteArray(ACK_SIZE) { 2 }
                )
            }
        }
        awaitSent(socket, ACK_CAPACITY)
        assertEquals(
            OutboundSendResult.NOT_SENT,
            transport.acknowledgeMessage(
                chatId = "forum_alpha",
                messageId = "message-capacity-overflow",
                senderUsername = "Alice",
                state = validAckState(),
                usedPrekeyId = "",
                ackSignature = ByteArray(ACK_SIZE) { 3 }
            )
        )

        socket.sentTexts.mapNotNull { runCatching { sentControl(it) }.getOrNull() }
            .filter { it.optString("type") == "message_ack" }
            .forEach { frame ->
                listener.onMessage(
                    socket,
                    ackResult(frame.getString("message_id"), accepted = true)
                )
            }
        waiters.forEach { assertEquals(OutboundSendResult.ACCEPTED, it.await()) }
    }

    @Test
    fun mlsFramesCarryConnectionGeneration() = runBlocking {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val socket = RecordingWebSocket()
        val listener = installSocket(transport, socket, generation = 7L)

        listener.onMessage(
            socket,
            mlsRoomDeletedFrame("forum_generation")
        )

        val change = transport.getIncomingMlsFrames().first()
        assertEquals(7L, transport.currentConnectionGeneration())
        assertEquals(7L, change.generation)
        assertEquals("forum_generation", (change.frame as com.abyssal.chat.domain.model.MlsIncomingFrame.RoomDeleted).roomId)
    }

    @Test
    fun disconnectDrainsQueuedCatalogChangesBeforeTheNextSession() = runBlocking {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val socket = RecordingWebSocket()
        val listener = installSocket(transport, socket, generation = 8L)

        listener.onMessage(
            socket,
            mlsRoomDeletedFrame("forum_stale")
        )
        transport.disconnect()

        assertEquals(9L, transport.currentConnectionGeneration())
        assertNull(
            withTimeoutOrNull(100L) {
                transport.getIncomingMlsFrames().first()
            }
        )
    }

    @Test
    fun abnormalSocketInvalidationClearsAuthorizationAndReconnectDoesNotReplayJoins() = runBlocking {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val oldSocket = RecordingWebSocket()
        val oldListener = installSocket(transport, oldSocket, generation = 41L)

        transport.joinChat("forum_manual")
        oldListener.onMessage(
            oldSocket,
            paddedControl(
                JSONObject().put("type", "presence")
                    .put("users", JSONArray().put(presence("Alice")))
            )
        )
        oldListener.onMessage(
            oldSocket,
            paddedControl(
                JSONObject().put("type", "directs")
                    .put("directs", JSONArray().put(direct("dm_alice", "Alice")))
            )
        )

        oldListener.onFailure(oldSocket, IllegalStateException("abnormal socket"), null)

        assertEquals(42L, transport.currentConnectionGeneration())
        assertNull(privateField(transport, "webSocket"))
        assertSocketAuthorizationCleared(transport)
        assertNull(withTimeoutOrNull(100L) { transport.getRoomChanges().first() })

        val newSocket = RecordingWebSocket()
        val newListener = installSocket(transport, newSocket, generation = 43L)
        newListener.onOpen(newSocket, openResponse(newSocket))

        assertTrue(
            "a fresh socket must not replay joins from the invalidated account",
            newSocket.sentTexts.none { sentControl(it).optString("type") == "join" }
        )
    }

    @Test
    fun staleSocketCallbacksCannotMutateOrCloseTheCurrentGeneration() = runBlocking {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val oldSocket = RecordingWebSocket()
        val oldListener = installSocket(transport, oldSocket, generation = 50L)
        val currentSocket = RecordingWebSocket()
        val currentListener = installSocket(transport, currentSocket, generation = 51L)
        currentListener.onOpen(currentSocket, openResponse(currentSocket))
        currentListener.onMessage(
            currentSocket,
            paddedControl(
                JSONObject().put("type", "presence")
                    .put("users", JSONArray().put(presence("Alice")))
            )
        )

        oldListener.onMessage(oldSocket, mlsRoomDeletedFrame("forum_stale_callback"))
        assertNull(withTimeoutOrNull(100L) { transport.getIncomingMlsFrames().first() })

        oldListener.onFailure(oldSocket, IllegalStateException("late failure"), null)
        assertEquals(51L, transport.currentConnectionGeneration())
        assertNull(currentSocket.closeCode)
        assertEquals("CONNECTED", transport.getServerStatus().first().state)
        assertEquals(listOf("Alice"), transport.getPresence().first().map { it.username })

        currentListener.onMessage(currentSocket, mlsRoomDeletedFrame("forum_current_callback"))
        val change = transport.getIncomingMlsFrames().first()
        assertEquals(51L, change.generation)
        assertEquals("forum_current_callback", (change.frame as com.abyssal.chat.domain.model.MlsIncomingFrame.RoomDeleted).roomId)
    }

    @Test
    fun staleOutboundCleanupCannotRemoveSameIdPendingFromNewGeneration() = runBlocking {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val oldSocket = RecordingWebSocket()
        installSocket(transport, oldSocket, generation = 70L)
        val currentSocket = RecordingWebSocket()
        val currentListener = installSocket(transport, currentSocket, generation = 71L)
        val catalog = with(transport) {
            JSONArray().put(presence("Alice")).toPresenceCatalog()
        } ?: error("test presence must parse")
        assertTrue(with(transport) { acceptPresenceCatalog(catalog) })

        val pending = async(start = CoroutineStart.UNDISPATCHED) {
            transport.sendEncryptedPayload(
                chatId = "forum_alpha",
                payload = outboundPayload("message-same-generation")
            )
        }
        awaitSent(currentSocket, 1)
        val sentPayload = JSONObject(currentSocket.sentTexts.single())
        assertEquals(4096, currentSocket.sentTexts.single().toByteArray(StandardCharsets.UTF_8).size)
        assertEquals(4096, sentPayload.getInt("padding_bucket"))
        assertTrue(sentPayload.getString("padding").matches(Regex("^[A-Za-z0-9_-]*$")))
        assertEquals("node-1", sentPayload.getString("directory_node_id"))
        assertEquals(1L, sentPayload.getLong("directory_revision"))
        assertEquals(directoryDigest("Alice"), sentPayload.getString("directory_digest"))

        invokeAbortPendingOutbound(
            transport = transport,
            socket = oldSocket,
            generation = 70L,
            messageId = "message-same-generation"
        )
        assertFalse(pending.isCompleted)

        currentListener.onMessage(
            currentSocket,
            messageResult("message-same-generation", accepted = true)
        )
        assertEquals(OutboundSendResult.ACCEPTED, pending.await())
    }

    @Test
    fun parsedPayloadFromInvalidatedSocketCannotBeEnqueued() = runBlocking {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val socket = RecordingWebSocket()
        val listener = installSocket(transport, socket, generation = 72L)
        val presenceCatalog = with(transport) {
            JSONArray().put(presence("Alice")).toPresenceCatalog()
        } ?: error("test presence must parse")
        assertTrue(with(transport) { acceptPresenceCatalog(presenceCatalog) })
        val parsedPayload = with(transport) {
            JSONObject(inboundMessageFrame("forum_parsed_before_invalidation"))
                .toIncomingPayload()
        }
            ?: error("test payload must parse")

        transport.disconnect()

        val enqueueMethod = RealChatTransport::class.java.getDeclaredMethod(
            "enqueueIncomingPayload",
            WebSocket::class.java,
            Long::class.javaPrimitiveType,
            IncomingTransportPayload::class.java
        )
        enqueueMethod.isAccessible = true
        enqueueMethod.invoke(transport, socket, 72L, parsedPayload)
        // Also cover the callback entry point after invalidation; its initial
        // check must reject the old listener without reaching the channel.
        listener.onMessage(socket, inboundMessageFrame("forum_parsed_before_invalidation"))

        assertNull(withTimeoutOrNull(100L) { transport.getIncomingPayloads().first() })
    }

    @Test
    fun incomingPayloadQueueOverflowClosesCurrentSocketFailClosed() = runBlocking {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val socket = RecordingWebSocket()
        installSocket(transport, socket, generation = 73L)
        val presenceCatalog = with(transport) {
            JSONArray().put(presence("Alice")).toPresenceCatalog()
        } ?: error("test presence must parse")
        assertTrue(with(transport) { acceptPresenceCatalog(presenceCatalog) })

        val enqueueMethod = RealChatTransport::class.java.getDeclaredMethod(
            "enqueueIncomingPayload",
            WebSocket::class.java,
            Long::class.javaPrimitiveType,
            IncomingTransportPayload::class.java
        ).apply { isAccessible = true }
        repeat(32) { index ->
            val payload = with(transport) {
                JSONObject(inboundMessageFrame("forum_inbound_$index"))
                    .put("message_id", "message-inbound-$index")
                    .toIncomingPayload(73L)
            } ?: error("test payload must parse")
            enqueueMethod.invoke(transport, socket, 73L, payload)
        }
        val overflowPayload = with(transport) {
            JSONObject(inboundMessageFrame("forum_inbound_overflow"))
                .put("message_id", "message-inbound-overflow")
                .toIncomingPayload(73L)
        } ?: error("overflow payload must parse")
        enqueueMethod.invoke(transport, socket, 73L, overflowPayload)

        assertEquals(1008, socket.closeCode)
        assertEquals("incoming consumer stalled", socket.closeReason)
        assertEquals("DISCONNECTED", transport.getServerStatus().first().state)
        assertArrayEquals(ByteArray(overflowPayload.nonce.size), overflowPayload.nonce)
        assertArrayEquals(ByteArray(overflowPayload.ciphertext.size), overflowPayload.ciphertext)
        assertArrayEquals(ByteArray(overflowPayload.signature.size), overflowPayload.signature)
        assertArrayEquals(ByteArray(overflowPayload.wrappedKey.size), overflowPayload.wrappedKey)
        assertArrayEquals(
            ByteArray(overflowPayload.senderPublicKey.size),
            overflowPayload.senderPublicKey
        )
        assertArrayEquals(
            ByteArray(overflowPayload.identityPublicKey.size),
            overflowPayload.identityPublicKey
        )
    }

    @Test
    fun generationAwareJoinRejectsStaleGenerationAndTargetsOnlyCurrentSocket() = runBlocking {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val oldSocket = RecordingWebSocket()
        installSocket(transport, oldSocket, generation = 73L)
        val currentSocket = RecordingWebSocket()
        installSocket(transport, currentSocket, generation = 74L)

        transport.joinChat("forum_stale", expectedConnectionGeneration = 73L)
        transport.joinChat("forum_current", expectedConnectionGeneration = 74L)

        assertTrue(oldSocket.sentTexts.isEmpty())
        assertEquals(1, currentSocket.sentTexts.size)
        assertEquals("forum_current", JSONObject(currentSocket.sentTexts.single()).getString("chat_id"))
    }

    @Test
    fun staleGenerationCommandsCannotReachReplacementSocket() = runBlocking {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val oldSocket = RecordingWebSocket()
        installSocket(transport, oldSocket, generation = 80L)
        val currentSocket = RecordingWebSocket()
        installSocket(transport, currentSocket, generation = 81L)
        val catalog = with(transport) {
            JSONArray().put(presence("Alice")).toPresenceCatalog()
        } ?: error("test presence must parse")
        assertTrue(with(transport) { acceptPresenceCatalog(catalog) })

        transport.createForum(roomSession("forum_stale_command"), 80L)
        transport.deleteForum("forum_stale_command", 80L)
        transport.openDirect("Alice", 80L)
        assertFalse(transport.signalUserActivity(80L))
        transport.broadcastGlobalWipe(80L)
        assertFalse(transport.syncIdentityState(validAckState(), 80L))

        val payload = outboundPayload("message-stale-command")
        assertEquals(
            OutboundSendResult.NOT_SENT,
            transport.sendEncryptedPayload("forum_alpha", payload, 80L)
        )
        assertTrue(currentSocket.sentTexts.isEmpty())
        assertArrayEquals(ByteArray(payload.ciphertext.size), payload.ciphertext)

        transport.openDirect("Alice", 81L)
        assertEquals("open_direct", JSONObject(currentSocket.sentTexts.single()).getString("type"))
    }

    @Test
    fun globalWipeSurvivesImmediateSocketFailureWithPostInvalidationGeneration() = runBlocking {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val socket = RecordingWebSocket()
        val listener = installSocket(transport, socket, generation = 82L)
        val pending = async(start = CoroutineStart.UNDISPATCHED) {
            transport.acknowledgeMessage(
                chatId = "forum_alpha",
                messageId = "message-wipe-command",
                senderUsername = "Alice",
                state = validAckState(),
                usedPrekeyId = "",
                ackSignature = ByteArray(ACK_SIZE) { 7 }
            )
        }
        awaitSent(socket, 1)

        listener.onMessage(socket, paddedControl(JSONObject().put("type", "GLOBAL_WIPE")))
        listener.onFailure(socket, IllegalStateException("failure after wipe"), null)

        assertEquals(OutboundSendResult.AMBIGUOUS, pending.await())
        assertEquals(PURGE_CLOSE_CODE, socket.closeCode)
        assertEquals(PURGE_CLOSE_REASON, socket.closeReason)
        assertEquals(83L, transport.currentConnectionGeneration())
        assertEquals(83L, transport.getIncomingWipeCommands().first())
        assertNull(withTimeoutOrNull(100L) { transport.getIncomingWipeCommands().first() })
    }

    @Test
    fun carriedGlobalWipeIsRetaggedWhenSameSessionReconnectsBeforeCollection() = runBlocking {
        val nodeConfig = InMemoryNodeConfigService().apply {
            setActiveSession(testSession())
        }
        val ticketFactory = TicketCancellationCallFactory()
        val transport = RealChatTransport(
            nodeConfig,
            OkHttpClient(),
            ticketFactory,
            TEST_BUILD_ATTESTATION
        )
        val socket = RecordingWebSocket()
        val listener = installSocket(transport, socket, generation = 83L)

        listener.onMessage(socket, paddedControl(JSONObject().put("type", "GLOBAL_WIPE")))
        listener.onFailure(socket, IllegalStateException("failure after wipe"), null)
        assertEquals(84L, transport.currentConnectionGeneration())

        transport.connect()

        assertTrue(ticketFactory.call.enqueued.await(2, TimeUnit.SECONDS))
        assertEquals(85L, transport.currentConnectionGeneration())
        assertEquals(85L, transport.getIncomingWipeCommands().first())
        assertNull(withTimeoutOrNull(100L) { transport.getIncomingWipeCommands().first() })
    }

    @Test
    fun guardedRepositoryMutationAndConnectionInvalidationAreLinearized() = runBlocking {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val socket = RecordingWebSocket()
        val listener = installSocket(transport, socket, generation = 86L)
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val mutationCompleted = AtomicBoolean(false)
        val invalidationCompleted = AtomicBoolean(false)
        val mutationFailure = AtomicReference<Throwable?>(null)
        val invalidationFailure = AtomicReference<Throwable?>(null)
        val repository = InMemoryMessageRepository()
        val repositoryEpoch = repository.currentEpoch()

        val mutationThread = Thread {
            try {
                val accepted = transport.runIfConnectionCurrent(86L) {
                    entered.countDown()
                    if (!release.await(2, TimeUnit.SECONDS)) return@runIfConnectionCurrent false
                    check(
                        repository.saveMessageIfCurrent(
                            repositoryEpoch,
                            "dm_linearized",
                            Message(
                                id = "linearized",
                                sender = "Alice",
                                receiver = "Bob",
                                content = "payload",
                                timestampMs = 1L,
                                selfDestructDurationSec = 0
                            )
                        )
                    ) { "repository publication was rejected" }
                    mutationCompleted.set(true)
                    true
                }
                check(accepted) { "current-generation mutation was rejected" }
            } catch (failure: Throwable) {
                mutationFailure.set(failure)
            }
        }.apply { start() }
        assertTrue(entered.await(2, TimeUnit.SECONDS))
        val invalidationThread = Thread {
            try {
                listener.onFailure(socket, IllegalStateException("disconnect"), null)
                invalidationCompleted.set(true)
            } catch (failure: Throwable) {
                invalidationFailure.set(failure)
            }
        }.apply { start() }

        Thread.sleep(50L)
        assertFalse(invalidationCompleted.get())
        assertEquals(86L, transport.currentConnectionGeneration())
        release.countDown()
        mutationThread.join(2_000L)
        invalidationThread.join(2_000L)

        assertFalse("mutation thread did not finish", mutationThread.isAlive)
        assertFalse("invalidation thread did not finish", invalidationThread.isAlive)
        assertNull("mutation thread failed", mutationFailure.get())
        assertNull("invalidation thread failed", invalidationFailure.get())
        assertTrue(mutationCompleted.get())
        assertTrue(invalidationCompleted.get())
        assertEquals(87L, transport.currentConnectionGeneration())
        assertFalse(transport.runIfConnectionCurrent(86L) { true })
        assertEquals("linearized", repository.getMessages("dm_linearized").first().single().id)
        repository.close()
    }

    @Test
    fun explicitDisconnectDropsOldPurgeAndWipesQueuedCiphertext() = runBlocking {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val socket = RecordingWebSocket()
        installSocket(transport, socket, generation = 84L)
        val presenceCatalog = with(transport) {
            JSONArray().put(presence("Alice")).toPresenceCatalog()
        } ?: error("test presence must parse")
        assertTrue(with(transport) { acceptPresenceCatalog(presenceCatalog) })
        assertTrue(with(transport) { acceptDynamicRoom(roomSession("forum_queued_payload")) })
        val payload = with(transport) {
            JSONObject(inboundMessageFrame("forum_queued_payload")).toIncomingPayload(84L)
        } ?: error("test payload must parse")
        val enqueueMethod = RealChatTransport::class.java.getDeclaredMethod(
            "enqueueIncomingPayload",
            WebSocket::class.java,
            Long::class.javaPrimitiveType,
            IncomingTransportPayload::class.java
        ).apply { isAccessible = true }
        enqueueMethod.invoke(transport, socket, 84L, payload)
        transport.signalPurge()

        transport.disconnect()

        assertNull(withTimeoutOrNull(100L) { transport.getIncomingWipeCommands().first() })
        assertNull(withTimeoutOrNull(100L) { transport.getIncomingPayloads().first() })
        assertArrayEquals(ByteArray(payload.nonce.size), payload.nonce)
        assertArrayEquals(ByteArray(payload.ciphertext.size), payload.ciphertext)
        assertArrayEquals(ByteArray(payload.signature.size), payload.signature)
        assertArrayEquals(ByteArray(payload.wrappedKey.size), payload.wrappedKey)
        assertArrayEquals(ByteArray(payload.senderPublicKey.size), payload.senderPublicKey)
        assertArrayEquals(ByteArray(payload.identityPublicKey.size), payload.identityPublicKey)
    }

    @Test
    fun unauthorizedReceiverPayloadIsDroppedWithoutDeliveringCiphertext() = runBlocking {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val socket = RecordingWebSocket()
        val listener = installSocket(transport, socket, generation = 60L)
        val catalog = with(transport) {
            JSONArray().put(presence("Alice")).toPresenceCatalog()
        } ?: error("test presence must parse")
        assertTrue(with(transport) { acceptPresenceCatalog(catalog) })

        listener.onMessage(socket, paddedInboundMessageFrame())

        assertNull(withTimeoutOrNull(100L) { transport.getIncomingPayloads().first() })
        assertNull(socket.closeCode)
        assertEquals(60L, transport.currentConnectionGeneration())
    }

    @Test
    fun missingIncomingMessagePaddingClosesCurrentSocketFailClosed() = runBlocking {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val socket = RecordingWebSocket()
        val listener = installSocket(transport, socket, generation = 61L)

        listener.onMessage(socket, inboundMessageFrame())

        assertNull(withTimeoutOrNull(100L) { transport.getIncomingPayloads().first() })
        assertEquals(1008, socket.closeCode)
        assertEquals("invalid message padding", socket.closeReason)
        assertEquals("DISCONNECTED", transport.getServerStatus().first().state)
        assertTrue(transport.currentConnectionGeneration() > 61L)
    }

    @Test
    fun mlsQueueOverflowClosesCurrentSocketFailClosed() = runBlocking {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val socket = RecordingWebSocket()
        val listener = installSocket(transport, socket, generation = 10L)

        repeat(129) { listener.onMessage(socket, mlsRoomDeletedFrame("forum_$it")) }

        assertEquals(1008, socket.closeCode)
        assertEquals("MLS consumer stalled", socket.closeReason)
        assertEquals("DISCONNECTED", transport.getServerStatus().first().state)
    }

    @Test
    fun purgeCommandIsDurableAndCoalesced() = runBlocking {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())

        transport.signalPurge()
        transport.signalPurge()
        assertEquals(transport.currentConnectionGeneration(), transport.getIncomingWipeCommands().first())
    }

    @Test
    fun utf8LimitCountsMultibyteAndSurrogateInputWithoutAllocation() {
        assertFalse(exceedsUtf8ByteLimit("\u20ac".repeat(349_525), 1 * 1024 * 1024))
        assertTrue(exceedsUtf8ByteLimit("\u20ac".repeat(349_526), 1 * 1024 * 1024))
        assertFalse(exceedsUtf8ByteLimit("\ud83d\ude00", 4))
        assertTrue(exceedsUtf8ByteLimit("\ud83d\ude00", 3))
        assertFalse(exceedsUtf8ByteLimit("\ud83d", 1))
    }

    @Test
    fun websocketTicketResponseRejectsMalformedExtraAndOversizedBodies() {
        val ticket = "A".repeat(43)
        val valid = JSONObject()
            .put("ticket", ticket)
            .put("expires_in_sec", 15)
            .toString()
            .toByteArray()
        assertEquals(WsTicket(ticket, 15), parseWsTicketResponseBody(valid))
        val nonCanonicalTicket = ticket.dropLast(1) + "B"
        assertNull(
            parseWsTicketResponseBody(
                JSONObject().put("ticket", nonCanonicalTicket).put("expires_in_sec", 15)
                    .toString().toByteArray()
            )
        )

        assertNull(
            parseWsTicketResponseBody(
                JSONObject()
                    .put("ticket", ticket)
                    .put("expires_in_sec", 15)
                    .put("unexpected", true)
                    .toString()
                    .toByteArray()
            )
        )
        assertNull(
            parseWsTicketResponseBody(
                JSONObject().put("ticket", ticket).put("expires_in_sec", 15.5).toString().toByteArray()
            )
        )
        assertNull(parseWsTicketResponseBody(ByteArray(WS_TICKET_MAX_RESPONSE_BYTES + 1) { '{'.code.toByte() }))
    }

    @Test
    fun websocketUpgradeContainsOnlyShortTicketAndNeverBearer() {
        val ticket = "A".repeat(43)
        val endpoint = NodeEndpoint(
            inputUrl = "https://node.example",
            apiBaseUrl = "https://node.example",
            wsBaseUrl = "wss://node.example",
            displayHost = "node.example"
        )

        val request = websocketUpgradeRequest(endpoint, ticket)
        val protocols = request.header("Sec-WebSocket-Protocol")
        assertEquals("abyssal-v2, ticket.$ticket", protocols)
        assertFalse(protocols.orEmpty().contains("bearer."))
        assertNull(request.header("Authorization"))
    }

    @Test
    fun disconnectCancelsInFlightTicketAndBlocksLateUpgrade() = runBlocking {
        val factory = TicketCancellationCallFactory()
        val node = InMemoryNodeConfigService()
        val endpoint = NodeEndpoint(
            inputUrl = "http://127.0.0.1",
            apiBaseUrl = "http://127.0.0.1",
            wsBaseUrl = "ws://127.0.0.1",
            displayHost = "127.0.0.1"
        )
        node.setActiveSession(NodeSession(endpoint, "token-1", "node-1", 5))
        val transport = RealChatTransport(node, OkHttpClient(), factory, TEST_BUILD_ATTESTATION)

        transport.connect()
        assertTrue(factory.call.enqueued.await(2, java.util.concurrent.TimeUnit.SECONDS))
        transport.disconnect()

        assertTrue(factory.call.cancelled)
        assertEquals("DISCONNECTED", transport.getServerStatus().first().state)
    }

    @Test
    fun unconfiguredBuildFailsBeforeTicketNetworkAccess() = runBlocking {
        val node = InMemoryNodeConfigService().apply { setActiveSession(testSession()) }
        val calls = AtomicBoolean(false)
        val transport = RealChatTransport(
            node,
            OkHttpClient(),
            Call.Factory {
                calls.set(true)
                error("ticket request must not be created")
            },
            BuildAttestationProvider { null }
        )

        transport.connect()

        assertFalse(calls.get())
        assertEquals("SECURITY_REJECTED", transport.getServerStatus().first().state)
    }

    @Test
    fun relayBuildRejectionIsDistinctAndTicketBodyIsExact() = runBlocking {
        val server = MockWebServer()
        server.enqueue(MockResponse().setResponseCode(426))
        server.start()
        try {
            val base = server.url("/")
            val endpoint = NodeEndpoint(
                inputUrl = base.toString(),
                apiBaseUrl = base.toString().removeSuffix("/"),
                wsBaseUrl = base.toString().replaceFirst("http://", "ws://").removeSuffix("/"),
                displayHost = base.host
            )
            val node = InMemoryNodeConfigService().apply {
                setActiveSession(NodeSession(endpoint, "token-1", "node-1", 5))
            }
            val client = OkHttpClient.Builder().build()
            val transport = RealChatTransport(node, client, client, TEST_BUILD_ATTESTATION)

            transport.connect()

            val status = withTimeout(2_000L) {
                transport.getServerStatus().first { it.state == "SECURITY_REJECTED" }
            }
            assertEquals("node-1", status.nodeId)
            val request = server.takeRequest(2, TimeUnit.SECONDS)
            assertNotNull(request)
            val payload = JSONObject(request!!.body.readUtf8())
            assertEquals(
                setOf("platform", "version", "build_signature_b64"),
                payload.keys().asSequence().toSet()
            )
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun presenceCatalogRejectsOversizeSchemaTypesNoncanonicalAndCollisionsAtomically() {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val valid = presence("Alice")
        assertEquals(1, with(transport) { JSONArray().put(valid).toPresenceCatalog()?.entries?.size })
        assertNull(with(transport) {
            JSONArray().put(presence("Alice").remove("directory_node_id")).toPresenceCatalog()
        })
        assertNull(with(transport) {
            JSONArray().put(presence("Alice").put("directory_revision", 0L)).toPresenceCatalog()
        })
        assertNull(with(transport) {
            JSONArray().put(presence("Alice").put("directory_node_id", "node/foreign")).toPresenceCatalog()
        })

        val malformed = JSONArray().put(presence("Alice")).put(presence("alice"))
        assertNull(with(transport) { malformed.toPresenceCatalog() })
        assertNull(with(transport) {
            JSONArray().put(presence("Alice").put("unexpected", true)).toPresenceCatalog()
        })
        assertNull(with(transport) {
            JSONArray().put(presence("Alice").remove("connected")).toPresenceCatalog()
        })
        assertNull(with(transport) {
            JSONArray().put(presence("Alice").put("connected", "true")).toPresenceCatalog()
        })
        assertNull(with(transport) {
            JSONArray().put(
                presence("Alice").put("identity_public_b64", "A".repeat(170) + "B")
            ).toPresenceCatalog()
        })
        val oversized = JSONArray()
        repeat(129) { oversized.put(presence("User$it")) }
        assertNull(with(transport) { oversized.toPresenceCatalog() })
    }

    @Test
    fun directoryCheckpointRejectsDigestConflictsAndDropsEvictedOldEvidence() {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val first = with(transport) {
            JSONArray().put(presence("Alice")).toPresenceCatalog()
        } ?: error("test presence must parse")
        assertTrue(with(transport) { acceptPresenceCatalog(first) })
        assertEquals(
            DirectoryEvidenceStatus.KNOWN,
            transport.directoryEvidenceStatus(DirectoryStamp("node-1", 1u, directoryDigest("Alice")))
        )

        val malformedDigest = with(transport) {
            JSONArray().put(presence("Alice").put("directory_digest", encode(ByteArray(32) { 9 })))
                .toPresenceCatalog()
        } ?: error("schema-valid malformed digest must parse")
        assertFalse(with(transport) { acceptPresenceCatalog(malformedDigest) })

        val sameRevisionConflict = with(transport) {
            JSONArray().put(presence("Bob")).toPresenceCatalog()
        } ?: error("conflicting catalog must parse")
        assertFalse(with(transport) { acceptPresenceCatalog(sameRevisionConflict) })

        for (revision in 2uL..34uL) {
            val catalog = with(transport) {
                JSONArray().put(presence("Alice", revision = revision)).toPresenceCatalog()
            } ?: error("revision $revision must parse")
            assertTrue(with(transport) { acceptPresenceCatalog(catalog) })
        }
        assertEquals(
            DirectoryEvidenceStatus.UNKNOWN_OLD,
            transport.directoryEvidenceStatus(DirectoryStamp("node-1", 1u, directoryDigest("Alice")))
        )
        assertEquals(
            DirectoryEvidenceStatus.KNOWN,
            transport.directoryEvidenceStatus(DirectoryStamp("node-1", 34u, directoryDigest("Alice", revision = 34u)))
        )
        assertEquals(
            DirectoryEvidenceStatus.CONFLICT,
            transport.directoryEvidenceStatus(DirectoryStamp("node-foreign", 34u, directoryDigest("Alice", "node-foreign", 34u)))
        )
    }

    @Test
    fun presenceCallbackRejectsAuthenticatedNodeMismatch() {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val socket = RecordingWebSocket()
        val listener = installSocket(transport, socket, generation = 35L)
        val foreignCatalog = JSONArray().put(presence("Alice", nodeId = "node-foreign"))

        listener.onMessage(
            socket,
            paddedControl(JSONObject().put("type", "presence").put("users", foreignCatalog))
        )

        assertEquals(1008, socket.closeCode)
        assertEquals("directory changed", socket.closeReason)
        assertNull(transport.currentDirectoryStamp())
    }

    @Test
    fun roomCatalogRejectsOversizeSchemaTypesRangesCollisionsAndPartialFrames() {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        assertEquals(
            1,
            with(transport) { JSONArray().put(room()).toChatSessions(1024)?.size }
        )
        assertNull(with(transport) { JSONArray().put(room().remove("owner_username")).toChatSessions(1024) })
        assertNull(with(transport) {
            JSONArray().put(room().put("allow_images", "true")).toChatSessions(1024)
        })
        assertNull(with(transport) {
            JSONArray().put(room().put("self_destruct_timer_sec", 86_401)).toChatSessions(1024)
        })
        assertNull(with(transport) {
            JSONArray().put(room().put("name", "x".repeat(37))).toChatSessions(1024)
        })
        assertNull(with(transport) {
            JSONArray().put(room("forum_alpha")).put(room("forum_ALPHA")).toChatSessions(1024)
        })
        val oversized = JSONArray()
        repeat(1025) { oversized.put(room("forum_room_$it")) }
        assertNull(with(transport) { oversized.toChatSessions(1024) })
        // A valid entry followed by a malformed one produces no partial result.
        assertNull(with(transport) {
            JSONArray().put(room()).put(room().put("overall_expiry_sec", 86_401)).toChatSessions(1024)
        })
    }

    @Test
    fun directCatalogRejectsOversizeSchemaTypesAndCaseCollisions() {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        assertEquals(1, with(transport) { JSONArray().put(direct()).toDirectSessions()?.size })
        assertNull(with(transport) { JSONArray().put(direct().remove("peer_username")).toDirectSessions() })
        assertNull(with(transport) {
            JSONArray().put(direct().put("peer_username", 7)).toDirectSessions()
        })
        assertNull(with(transport) {
            JSONArray().put(direct("dm_alice", "Alice")).put(direct("dm_ALICE", "Bob"))
                .toDirectSessions()
        })
        assertNull(with(transport) {
            JSONArray().put(direct("dm_alice", "Alice")).put(direct("dm_bob", "alice"))
                .toDirectSessions()
        })
        val oversized = JSONArray()
        repeat(129) { oversized.put(direct("dm_user_$it", "User$it")) }
        assertNull(with(transport) { oversized.toDirectSessions() })
    }

    @Test
    fun inboundMessageRequiresPinnedStableIdentityAndAllowsPrekeyRotation() {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val stable = ByteArray(608) { index -> if (index < 64) 1 else 2 }
        val rotated = stable.clone().also { it[100] = 9 }
        val forged = stable.clone().also { it[0] = 7 }
        fun frame(publicKey: ByteArray, username: String = "Alice") = JSONObject()
            .put("type", "message")
            .put("version", 9)
            .put("chat_id", "dm_alice")
            .put("message_id", "message-1")
            .put("nonce_b64", encode(ByteArray(12) { 3 }))
            .put("ciphertext_b64", encode(byteArrayOf(4)))
            .put("signature_b64", encode(ByteArray(64) { 5 }))
            .put("wrapped_key_b64", encode(byteArrayOf(6)))
            .put("sender_username", username)
            .put("sender_public_key_b64", encode(publicKey))
            .put("identity_public_b64", encode(publicKey))
            .put("prekey_id", "")
            .put("is_prekey", false)
            .put("directory_node_id", "node-1")
            .put("directory_revision", 1L)
            .put("directory_digest", directoryDigest("Alice"))

        val aliceCatalog = with(transport) {
            JSONArray().put(presence("Alice")).toPresenceCatalog()
        }
        assertNotNull(aliceCatalog)
        assertTrue(with(transport) { acceptPresenceCatalog(aliceCatalog!!) })
        val accepted = with(transport) { frame(rotated).toIncomingPayload() }
        assertTrue(accepted != null)
        accepted!!.senderPublicKey.fill(0)
        accepted.identityPublicKey.fill(0)
        accepted.nonce.fill(0)
        accepted.ciphertext.fill(0)
        accepted.signature.fill(0)
        accepted.wrappedKey.fill(0)
        assertNull(with(transport) { frame(forged).toIncomingPayload() })
        assertNull(with(transport) { frame(stable, "Missing").toIncomingPayload() })

        // A historical pin is insufficient after the directory removes a user.
        // The current presence catalog must still bind the username to its key.
        val bobCatalog = with(transport) {
            JSONArray().put(presence("Bob", revision = 2u)).toPresenceCatalog()
        }
        assertNotNull(bobCatalog)
        assertTrue(with(transport) { acceptPresenceCatalog(bobCatalog!!) })
        assertNull(with(transport) { frame(rotated).toIncomingPayload() })
        stable.fill(0)
        rotated.fill(0)
        forged.fill(0)
    }

    @Test
    fun dynamicCatalogEventsRespectCapsAndCaseCollisionRules() {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        assertTrue(with(transport) { acceptDynamicRoom(roomSession("forum_alpha")) })
        assertFalse(with(transport) { acceptDynamicRoom(roomSession("forum_ALPHA")) })
        repeat(1023) { index ->
            assertTrue(with(transport) { acceptDynamicRoom(roomSession("forum_room_$index")) })
        }
        assertFalse(with(transport) { acceptDynamicRoom(roomSession("forum_overflow")) })

        val directTransport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        assertTrue(with(directTransport) { acceptDynamicDirect(directSession("dm_alice", "Alice")) })
        assertFalse(with(directTransport) {
            acceptDynamicDirect(directSession("dm_ALICE", "Alice"))
        })
        assertFalse(with(directTransport) {
            acceptDynamicDirect(directSession("dm_bob", "alice"))
        })
        repeat(127) { index ->
            assertTrue(with(directTransport) {
                acceptDynamicDirect(directSession("dm_user_$index", "User$index"))
            })
        }
        assertFalse(with(directTransport) {
            acceptDynamicDirect(directSession("dm_overflow", "Overflow"))
        })
    }

    @Test
    fun inboundMessageMustTargetKnownChatAndBoundDirectPeer() {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        assertTrue(with(transport) { acceptDynamicRoom(roomSession("forum_alpha")) })
        assertTrue(with(transport) { acceptDynamicDirect(directSession("dm_alice", "Alice")) })

        fun payload(chatId: String, sender: String) = IncomingTransportPayload(
            chatId = chatId,
            messageId = "message-1",
            version = 9,
            identityPublicKey = ByteArray(1),
            nonce = ByteArray(1),
            ciphertext = ByteArray(1),
            signature = ByteArray(1),
            wrappedKey = ByteArray(1),
            senderUsername = sender,
            senderPublicKey = ByteArray(1)
        )

        assertFalse(with(transport) { isAuthorizedIncomingPayload(payload("forum_alpha", "Alice")) })
        assertFalse(with(transport) { isAuthorizedIncomingPayload(payload("forum_unknown", "Alice")) })
        assertTrue(with(transport) { isAuthorizedIncomingPayload(payload("dm_alice", "alice")) })
        assertFalse(with(transport) { isAuthorizedIncomingPayload(payload("dm_alice", "Mallory")) })
        assertFalse(with(transport) { isAuthorizedIncomingPayload(payload("dm_unknown", "Alice")) })
        assertFalse(with(transport) { isAuthorizedIncomingPayload(payload("dm_alice_extra", "Alice")) })
    }

    private fun validAckState() = IdentityStateSnapshot(
        revision = 1u,
        envelope = ByteArray(8) { 1 },
        identityPublicKey = ByteArray(608) { 2 },
        prekeyId = "prekey-1",
        stateSignature = ByteArray(64) { 3 }
    )

    private fun messageResult(messageId: String, accepted: Boolean): String = paddedControl(
        JSONObject()
            .put("type", "message_result")
            .put("message_id", messageId)
            .put("accepted", accepted)
    )

    private fun ackResult(messageId: String, accepted: Boolean): String = paddedControl(
        JSONObject()
            .put("type", "ack_result")
            .put("message_id", messageId)
            .put("accepted", accepted)
    )

    private fun mlsRoomDeletedFrame(id: String): String = paddedControl(
        JSONObject()
            .put("type", "mls_room_deleted")
            .put("protocol_version", 10)
            .put("room_id", id),
        ControlTransportPadding.MLS_DOMAIN_MAX_BYTES
    )

    private fun paddedControl(
        frame: JSONObject,
        domainLimit: Int = if (frame.optString("type").startsWith("mls_")) {
            ControlTransportPadding.MLS_DOMAIN_MAX_BYTES
        } else {
            ControlTransportPadding.LEGACY_DOMAIN_MAX_BYTES
        }
    ): String = frame.padOutgoingControl(domainLimit) ?: error("invalid control fixture")

    private fun sentControl(raw: String): JSONObject {
        val frame = JSONObject(raw)
        val domainLimit = if (frame.optString("type").startsWith("mls_")) {
            ControlTransportPadding.MLS_DOMAIN_MAX_BYTES
        } else {
            ControlTransportPadding.LEGACY_DOMAIN_MAX_BYTES
        }
        check(frame.validateAndStripIncomingControlPadding(raw, domainLimit))
        return frame
    }

    private fun outboundMlsApplicationFrame(messageId: String, revision: String): JSONObject = JSONObject()
        .put("type", "mls_application").put("protocol_version", 10).put("room_id", "forum_alpha")
        .put("message_id", messageId).put("group_id_b64", encode(ByteArray(32))).put("epoch", "0")
        .put("revision", revision).put("membership_digest_b64", encode(ByteArray(32) { 1 }))
        .put("ciphertext_b64", encode(byteArrayOf(1))).put("authenticated_data_b64", encode(byteArrayOf(2)))
        .put("state_envelope_b64", encode(byteArrayOf(3)))

    private fun inboundMessageFrame(chatId: String = "dm_alice"): String = JSONObject()
        .put("type", "message")
        .put("version", 9)
        .put("chat_id", chatId)
        .put("message_id", "message-unauthorized")
        .put("nonce_b64", encode(ByteArray(12) { 3 }))
        .put("ciphertext_b64", encode(byteArrayOf(4)))
        .put("signature_b64", encode(ByteArray(64) { 5 }))
        .put("wrapped_key_b64", encode(byteArrayOf(6)))
        .put("sender_username", "Alice")
        .put("sender_public_key_b64", encode(ByteArray(608) { 1 }))
        .put("identity_public_b64", encode(ByteArray(608) { 1 }))
        .put("prekey_id", "")
        .put("is_prekey", false)
        .put("directory_node_id", "node-1")
        .put("directory_revision", 1L)
        .put("directory_digest", directoryDigest("Alice"))
        .toString()

    private fun paddedInboundMessageFrame(chatId: String = "dm_alice"): String {
        val base = JSONObject(inboundMessageFrame(chatId))
        for (bucket in listOf(4096, 16_384, 65_536, 262_144, 1_048_576)) {
            val frame = JSONObject(base.toString())
                .put("padding_bucket", bucket)
                .put("padding", "")
            val emptyBytes = frame.toString().toByteArray(StandardCharsets.UTF_8).size
            if (emptyBytes > bucket) continue
            frame.put("padding", "A".repeat(bucket - emptyBytes))
            return frame.toString().also {
                check(it.toByteArray(StandardCharsets.UTF_8).size == bucket)
            }
        }
        error("test message exceeds transport buckets")
    }

    private fun outboundPayload(messageId: String): EncryptedTransportPayload =
        EncryptedTransportPayload(
            version = 9,
            messageId = messageId,
            nonce = ByteArray(12) { 1 },
            ciphertext = byteArrayOf(2),
            envelopes = listOf(
                RecipientEnvelope(
                    recipientUsername = "Alice",
                    wrappedKey = byteArrayOf(7),
                    prekeyId = "",
                    isPrekey = false,
                    signature = ByteArray(64) { 8 }
                )
            ),
            stateRevision = 1u,
            identityEnvelope = ByteArray(8) { 3 },
            identityPublicKey = ByteArray(608) { 4 },
            prekeyId = "prekey-1",
            stateSignature = ByteArray(64) { 5 },
            directoryNodeId = "node-1",
            directoryRevision = 1u,
            directoryDigest = directoryDigest("Alice")
        )

    private fun invokeAbortPendingOutbound(
        transport: RealChatTransport,
        socket: RecordingWebSocket,
        generation: Long,
        messageId: String
    ) {
        val method = RealChatTransport::class.java.getDeclaredMethod(
            "abortPendingOutbound",
            WebSocket::class.java,
            Long::class.javaPrimitiveType,
            String::class.java,
            CompletableDeferred::class.java,
            String::class.java
        )
        method.isAccessible = true
        method.invoke(transport, socket, generation, messageId, null, "old send failed")
    }

    private fun openResponse(socket: RecordingWebSocket): Response = Response.Builder()
        .request(socket.request())
        .protocol(Protocol.HTTP_1_1)
        .code(101)
        .message("Switching Protocols")
        .build()

    private fun assertSocketAuthorizationCleared(transport: RealChatTransport) {
        listOf(
            "joinedChatIds",
            "identityPins",
            "roomCatalogIds",
            "directCatalogIds",
            "directCatalogPeers",
            "directCatalogPeerById"
        ).forEach { name ->
            val value = privateField(transport, name)
            assertTrue(
                name,
                when (value) {
                    is Collection<*> -> value.isEmpty()
                    is Map<*, *> -> value.isEmpty()
                    else -> false
                }
            )
        }
    }

    private fun privateField(target: Any, name: String): Any? {
        val field = target.javaClass.getDeclaredField(name)
        field.isAccessible = true
        return field.get(target)
    }

    @Test
    fun mlsTransactionAcceptsOnlyExactGenerationRoomRevisionAndResultType() = runBlocking {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val socket = RecordingWebSocket()
        val listener = installSocket(transport, socket, generation = 7L)
        val frame = outboundMlsApplicationFrame("message_1", "9")
        val pending = async(start = CoroutineStart.UNDISPATCHED) {
            transport.sendMlsTransaction("forum_alpha", "message_1", 9uL, frame, 7L)
        }
        awaitSent(socket, 1)
        val wrong = JSONObject().put("type", "mls_snapshot_result").put("protocol_version", 10)
            .put("room_id", "forum_alpha").put("message_id", "message_1").put("revision", "9").put("accepted", true)
        listener.onMessage(socket, paddedControl(wrong))
        assertEquals(1008, socket.closeCode)
        assertEquals(OutboundSendResult.AMBIGUOUS, pending.await())
    }

    @Test
    fun mlsTransactionCompletesForExactAuthenticatedTuple() = runBlocking {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val socket = RecordingWebSocket()
        val listener = installSocket(transport, socket, generation = 3L)
        val frame = outboundMlsApplicationFrame("message_2", "4")
        val pending = async(start = CoroutineStart.UNDISPATCHED) {
            transport.sendMlsTransaction("forum_alpha", "message_2", 4uL, frame, 3L)
        }
        awaitSent(socket, 1)
        val result = JSONObject().put("type", "mls_room_result").put("protocol_version", 10)
            .put("room_id", "forum_alpha").put("message_id", "message_2").put("revision", "4").put("accepted", true)
        listener.onMessage(socket, paddedControl(result))
        assertEquals(OutboundSendResult.ACCEPTED, pending.await())
        assertNull(socket.closeCode)
    }

    @Test
    fun malformedMlsFrameFailsClosedInsteadOfFallingThroughLegacyRoomParser() {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val socket = RecordingWebSocket()
        val listener = installSocket(transport, socket)
        listener.onMessage(
            socket,
            paddedControl(
                JSONObject().put("type", "mls_application")
                    .put("protocol_version", 10)
                    .put("room_id", "forum_alpha")
            )
        )
        assertEquals(1008, socket.closeCode)
        assertEquals("DISCONNECTED", runBlocking { transport.getServerStatus().first() }.state)
    }

    @Test
    fun legacyRoomCatalogFailsClosedAndCannotAuthorizeProtocolV9RoomPayloads() {
        val transport = RealChatTransport(InMemoryNodeConfigService(), OkHttpClient())
        val socket = RecordingWebSocket()
        val listener = installSocket(transport, socket)
        listener.onMessage(
            socket,
            paddedControl(JSONObject().put("type", "rooms").put("rooms", JSONArray()))
        )
        assertEquals(1008, socket.closeCode)
        assertEquals("legacy room protocol", socket.closeReason)
    }

    private suspend fun awaitSent(socket: RecordingWebSocket, expected: Int) {
        withTimeout(2_000L) {
            while (socket.sentTexts.size < expected) yield()
        }
    }

    private fun installSocket(
        transport: RealChatTransport,
        socket: RecordingWebSocket,
        generation: Long = 1L
    ): WebSocketListener {
        val socketField = RealChatTransport::class.java.getDeclaredField("webSocket")
        socketField.isAccessible = true
        socketField.set(transport, socket)
        val generationField = RealChatTransport::class.java
            .getDeclaredField("connectionGeneration")
        generationField.isAccessible = true
        (generationField.get(transport) as java.util.concurrent.atomic.AtomicLong).set(generation)
        val listenerMethod = RealChatTransport::class.java.getDeclaredMethod(
            "listener",
            String::class.java,
            Long::class.javaPrimitiveType
        )
        listenerMethod.isAccessible = true
        return listenerMethod.invoke(transport, "node-1", generation) as WebSocketListener
    }

    private fun presence(
        username: String,
        nodeId: String = "node-1",
        revision: ULong = 1u,
        identity: ByteArray = ByteArray(608) { 1 },
    ): JSONObject = JSONObject()
        .put("username", username)
        .put("connected", true)
        .put("identity_public_b64", encode(identity))
        .put("identity_prekey_id", "prekey-1")
        .put("directory_digest", directoryDigest(username, nodeId, revision, identity))
        .put("directory_node_id", nodeId)
        .put("directory_revision", revision.toLong())

    private fun directoryDigest(
        username: String,
        nodeId: String = "node-1",
        revision: ULong = 1u,
        identity: ByteArray = ByteArray(608) { 1 },
    ): String {
        val domain = "ABYSSAL_DIRECTORY_CHECKPOINT_V2".toByteArray(StandardCharsets.UTF_8)
        val node = nodeId.toByteArray(StandardCharsets.UTF_8)
        val name = username.toByteArray(StandardCharsets.UTF_8)
        val transcript = ByteBuffer.allocate(domain.size + 4 + node.size + 8 + 4 + 4 + name.size + 64)
            .order(ByteOrder.BIG_ENDIAN)
        transcript.put(domain)
        transcript.putInt(node.size)
        transcript.put(node)
        transcript.putLong(revision.toLong())
        transcript.putInt(1)
        transcript.putInt(name.size)
        transcript.put(name)
        transcript.put(identity, 0, 64)
        return encode(MessageDigest.getInstance("SHA-256").digest(transcript.array()))
    }

    private fun testSession() = NodeSession(
        endpoint = NodeEndpoint(
            inputUrl = "http://127.0.0.1",
            apiBaseUrl = "http://127.0.0.1",
            wsBaseUrl = "ws://127.0.0.1",
            displayHost = "test"
        ),
        token = "token-1",
        nodeId = "node-1",
        maxRoomsPerUser = 5
    )

    private fun room(id: String = "forum_alpha"): JSONObject = JSONObject()
        .put("id", id)
        .put("name", "alpha")
        .put("owner_username", "Owner123")
        .put("self_destruct_timer_sec", 5)
        .put("overall_expiry_sec", 0)
        .put("allow_images", true)
        .put("allow_videos", true)
        .put("allow_files", true)
        .put("enforce_text_absolute_expiry", false)
        .put("image_read_timer_sec", 5)
        .put("image_overall_expiry_sec", 0)
        .put("enforce_image_absolute_expiry", false)
        .put("video_read_timer_sec", 5)
        .put("video_overall_expiry_sec", 0)
        .put("enforce_video_absolute_expiry", false)
        .put("file_read_timer_sec", 5)
        .put("file_overall_expiry_sec", 0)
        .put("enforce_file_absolute_expiry", false)

    private fun direct(id: String = "dm_alice", peer: String = "Alice"): JSONObject = JSONObject()
        .put("id", id)
        .put("peer_username", peer)

    private fun roomSession(id: String): ChatSession = ChatSession(
        id = id,
        name = "room",
        isForum = true,
        lastMessage = null,
        unreadCount = 0,
        selfDestructTimerSec = 5
    )

    private fun directSession(id: String, peer: String): ChatSession = ChatSession(
        id = id,
        name = peer,
        isForum = false,
        lastMessage = null,
        unreadCount = 0,
        selfDestructTimerSec = 5
    )

    private fun encode(bytes: ByteArray): String =
        java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    private class RecordingWebSocket : WebSocket {
        var closeCode: Int? = null
        var closeReason: String? = null
        var cancelled = false
        val sentTexts = CopyOnWriteArrayList<String>()

        override fun request(): Request = Request.Builder().url("https://node.example/v1/ws").build()

        override fun queueSize(): Long = 0L

        override fun send(text: String): Boolean {
            sentTexts += text
            return true
        }

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

    private class TicketCancellationCallFactory : Call.Factory {
        val call = TicketCancellationCall()

        override fun newCall(request: Request): Call {
            assertEquals("POST", request.method)
            assertEquals("Bearer token-1", request.header("Authorization"))
            assertEquals("no-store", request.header("Cache-Control"))
            assertEquals("application/json; charset=utf-8", request.body?.contentType().toString())
            val body = Buffer()
            request.body?.writeTo(body)
            val payload = JSONObject(body.readUtf8())
            assertEquals(
                setOf("platform", "version", "build_signature_b64"),
                payload.keys().asSequence().toSet()
            )
            assertEquals("android", payload.getString("platform"))
            assertEquals("2.2.0", payload.getString("version"))
            assertEquals("A".repeat(86), payload.getString("build_signature_b64"))
            assertTrue(request.url.encodedPath.endsWith("/v1/ws-ticket"))
            return call
        }
    }

    private class TicketCancellationCall : Call {
        private val request = Request.Builder().url("http://127.0.0.1/v1/ws-ticket").build()
        val enqueued = CountDownLatch(1)
        @Volatile var cancelled = false

        override fun request(): Request = request

        override fun execute(): Response = error("not used")

        override fun enqueue(responseCallback: Callback) {
            enqueued.countDown()
        }

        override fun cancel() {
            cancelled = true
        }

        override fun isExecuted(): Boolean = enqueued.count == 0L

        override fun isCanceled(): Boolean = cancelled

        override fun timeout() = okio.Timeout.NONE

        override fun clone(): Call = TicketCancellationCall()
    }
}

package com.abyssal.chat.data.network

import com.abyssal.chat.domain.model.ChatSession
import com.abyssal.chat.domain.model.EncryptedTransportPayload
import com.abyssal.chat.domain.model.IncomingTransportPayload
import com.abyssal.chat.domain.model.IdentityStateSnapshot
import com.abyssal.chat.domain.model.NodeEndpoint
import com.abyssal.chat.domain.model.NodeSession
import com.abyssal.chat.domain.model.RoomChange
import com.abyssal.chat.domain.model.ServerStatus
import com.abyssal.chat.domain.model.UserPresence
import com.abyssal.chat.domain.repository.IChatTransport
import com.abyssal.chat.domain.repository.INodeConfigService
import com.abyssal.chat.domain.repository.OutboundSendResult
import java.util.Collections
import java.util.Base64
import java.util.LinkedHashMap
import java.util.LinkedHashSet
import java.util.Locale
import java.nio.charset.StandardCharsets
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import org.json.JSONArray
import okhttp3.OkHttpClient
import okhttp3.Call
import okhttp3.Callback
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONObject

/** Mirrors the JVM UTF-8 encoder without allocating a second copy of hostile input. */
internal fun exceedsUtf8ByteLimit(value: String, maxBytes: Int): Boolean {
    var encodedBytes = 0L
    var index = 0
    while (index < value.length) {
        val character = value[index]
        val width = when {
            character.code <= 0x7f -> 1
            character.code <= 0x7ff -> 2
            Character.isHighSurrogate(character) &&
                index + 1 < value.length &&
                Character.isLowSurrogate(value[index + 1]) -> {
                index += 1
                4
            }
            Character.isSurrogate(character) -> 1
            else -> 3
        }
        encodedBytes += width
        if (encodedBytes > maxBytes) return true
        index += 1
    }
    return false
}

internal data class WsTicket(val value: String, val expiresInSec: Int)

internal const val WS_TICKET_MAX_RESPONSE_BYTES = 4 * 1024
internal const val PURGE_CLOSE_CODE = 4001
internal const val PURGE_CLOSE_REASON = "purge"
private const val WS_TICKET_B64_LENGTH = 43
private val WS_TICKET_REGEX = Regex("^[A-Za-z0-9_-]{43}$")
private const val OUTBOUND_RESULT_TIMEOUT_MS = 15_000L

internal fun JSONObject.toOutboundMessageResult(): Pair<String, Boolean>? {
    if (keys().asSequence().toSet() != setOf("type", "message_id", "accepted")) return null
    if ((get("type") as? String) != "message_result") return null
    val messageId = get("message_id") as? String ?: return null
    if (messageId.isEmpty() || messageId.length > 128 ||
        !messageId.all { it.isLetterOrDigit() || it == '_' || it == '-' }
    ) return null
    val accepted = get("accepted") as? Boolean ?: return null
    return messageId to accepted
}

internal fun JSONObject.toAcknowledgementResult(): Pair<String, Boolean>? {
    if (keys().asSequence().toSet() != setOf("type", "message_id", "accepted")) return null
    if ((get("type") as? String) != "ack_result") return null
    val messageId = get("message_id") as? String ?: return null
    if (messageId.isEmpty() || messageId.length > 128 ||
        !messageId.all { it.isLetterOrDigit() || it == '_' || it == '-' }
    ) return null
    val accepted = get("accepted") as? Boolean ?: return null
    return messageId to accepted
}

internal fun isPurgeClose(code: Int, reason: String): Boolean =
    code == PURGE_CLOSE_CODE && reason == PURGE_CLOSE_REASON

/** Strict relay ticket schema. Caller owns and must wipe [raw] after this call. */
internal fun parseWsTicketResponseBody(raw: ByteArray): WsTicket? {
    if (raw.isEmpty() || raw.size > WS_TICKET_MAX_RESPONSE_BYTES) return null
    return runCatching {
        val json = JSONObject(String(raw, StandardCharsets.UTF_8))
        val keys = json.keys().asSequence().toSet()
        if (keys != setOf("ticket", "expires_in_sec")) return@runCatching null
        val ticket = json.get("ticket") as? String
            ?: return@runCatching null
        if (ticket.length != WS_TICKET_B64_LENGTH || !WS_TICKET_REGEX.matches(ticket)) {
            return@runCatching null
        }
        val decodedTicket = runCatching { Base64.getUrlDecoder().decode(ticket) }.getOrNull()
            ?: return@runCatching null
        val canonicalTicket = try {
            if (decodedTicket.size != 32) return@runCatching null
            Base64.getUrlEncoder().withoutPadding().encodeToString(decodedTicket)
        } finally {
            decodedTicket.fill(0)
        }
        if (canonicalTicket != ticket) return@runCatching null
        val expires = when (val value = json.get("expires_in_sec")) {
            is Int -> value
            is Long -> value.takeIf { it in 1L..30L }?.toInt()
            else -> null
        } ?: return@runCatching null
        if (expires !in 1..30) return@runCatching null
        WsTicket(ticket, expires)
    }.getOrNull()
}

internal fun websocketUpgradeRequest(endpoint: NodeEndpoint, ticket: String): Request {
    require(WS_TICKET_REGEX.matches(ticket))
    return Request.Builder()
        .url("${endpoint.wsBaseUrl}/v1/ws")
        .header("Sec-WebSocket-Protocol", "abyssal-v1, ticket.$ticket")
        .build()
}

class RealChatTransport(
    private val nodeConfigService: INodeConfigService,
    private val client: OkHttpClient,
    private val callFactory: Call.Factory = client
) : IChatTransport {
    private data class PendingOperation(
        val generation: Long,
        val result: CompletableDeferred<OutboundSendResult>
    )

    private data class DrainedPendingOperations(
        val outbound: List<CompletableDeferred<OutboundSendResult>>,
        val acknowledgements: List<CompletableDeferred<OutboundSendResult>>
    )

    private data class SocketSnapshot(
        val socket: WebSocket,
        val generation: Long
    )

    // A wipe must survive until the ViewModel collector is scheduled. A bounded
    // channel keeps this durable without allowing repeated relay frames to grow
    // memory; the atomic gate also coalesces GLOBAL_WIPE + purge close pairs.
    private val _wipeCommands = Channel<Long>(
        capacity = 1,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )
    private val _incomingPayloads = Channel<IncomingTransportPayload>(
        capacity = 32,
        onUndeliveredElement = ::wipeIncomingPayload
    )
    private val _roomChanges = Channel<RoomChange>(capacity = ROOM_CHANGE_BUFFER_CAPACITY)
    private val _presence = MutableStateFlow<List<UserPresence>>(emptyList())
    private val _serverStatus = MutableStateFlow(ServerStatus("DISCONNECTED", "No node", 0))
    private val connecting = AtomicBoolean(false)
    private val connectionGeneration = AtomicLong(0L)
    private val purgeSignaled = AtomicBoolean(false)
    private val connectionLock = Any()
    private val identityPins = Collections.synchronizedMap(
        LinkedHashMap<String, String>(MAX_PINNED_IDENTITIES, 0.75f, true)
    )
    private val catalogLock = Any()
    private val roomCatalogIds = LinkedHashMap<String, String>()
    private val directCatalogIds = LinkedHashMap<String, String>()
    private val directCatalogPeers = LinkedHashMap<String, String>()
    /** Canonical direct-chat id to the peer identity authorized to send on it. */
    private val directCatalogPeerById = LinkedHashMap<String, String>()

    @Volatile
    private var webSocket: WebSocket? = null
    @Volatile
    private var ticketCall: Call? = null
    private val joinedChatIds = Collections.synchronizedSet(LinkedHashSet<String>())
    private val pendingOutbound = LinkedHashMap<String, PendingOperation>()
    private val pendingAcknowledgements =
        LinkedHashMap<String, PendingOperation>()

    override fun connect() {
        val session = nodeConfigService.getActiveSession()
        if (session == null) {
            _serverStatus.value = ServerStatus("DISCONNECTED", "No node", 0)
            return
        }

        val generation: Long
        synchronized(connectionLock) {
            if (webSocket != null || connecting.get()) return
            connecting.set(true)
            generation = connectionGeneration.incrementAndGet()
            if (purgeSignaled.get()) {
                while (_wipeCommands.tryReceive().isSuccess) Unit
                signalPurgeLocked(generation, force = true)
            }
            _serverStatus.value = ServerStatus("CONNECTING", session.nodeId, 0)
        }
        val request = Request.Builder()
            .url("${session.endpoint.apiBaseUrl}/v1/ws-ticket")
            .header("Authorization", "Bearer ${session.token}")
            .header("Cache-Control", "no-store")
            .header("Pragma", "no-cache")
            .post(ByteArray(0).toRequestBody(null))
            .build()
        val call = runCatching { callFactory.newCall(request) }.getOrElse {
            failTicketConnection(generation, session)
            return
        }
        synchronized(connectionLock) {
            if (!isCurrentConnection(generation, session)) {
                call.cancel()
                return
            }
            ticketCall = call
        }
        try {
            call.enqueue(object : Callback {
                override fun onFailure(call: Call, e: IOException) {
                    synchronized(connectionLock) {
                        if (!isCurrentTicket(call, generation, session)) return
                        ticketCall = null
                        connecting.set(false)
                        _serverStatus.value = ServerStatus("DISCONNECTED", session.nodeId, 0)
                    }
                }

                override fun onResponse(call: Call, response: Response) {
                    if (!isCurrentTicket(call, generation, session)) {
                        response.close()
                        return
                    }
                    val ticket = response.use { parseWsTicket(it) }
                    if (ticket == null || !isCurrentTicket(call, generation, session)) {
                        failTicketConnection(generation, session)
                        return
                    }
                    synchronized(connectionLock) {
                        if (!isCurrentTicket(call, generation, session)) return
                        ticketCall = null
                        val active = nodeConfigService.getActiveSession()
                        if (active == null || !isSameSession(active, session) || generation != connectionGeneration.get()) {
                            connecting.set(false)
                            _serverStatus.value = ServerStatus("DISCONNECTED", session.nodeId, 0)
                            return
                        }
                        webSocket = runCatching {
                            val wsRequest = websocketUpgradeRequest(active.endpoint, ticket.value)
                            client.newWebSocket(wsRequest, listener(active.nodeId, generation))
                        }.getOrElse {
                            connecting.set(false)
                            _serverStatus.value = ServerStatus("DISCONNECTED", active.nodeId, 0)
                            return
                        }
                    }
                }
            })
        } catch (_: RuntimeException) {
            call.cancel()
            failTicketConnection(generation, session)
        }
    }

    override fun disconnect() {
        val pendingCall: Call?
        val socket: WebSocket?
        val drainedPending: DrainedPendingOperations
        synchronized(connectionLock) {
            drainedPending = advanceConnectionEpochAndDrainRoomChangesLocked()
            connecting.set(false)
            pendingCall = ticketCall
            ticketCall = null
            socket = webSocket
            webSocket = null
            clearAuthorizationStateLocked()
            clearPresence()
            _serverStatus.value = ServerStatus("DISCONNECTED", "No node", 0)
        }
        pendingCall?.cancel()
        socket?.close(1000, "client disconnect")
        // Resolve before clearing local cryptographic state. Callers must treat
        // every in-flight frame as ambiguous and fail closed.
        completeDrainedPendingOperations(drainedPending, OutboundSendResult.AMBIGUOUS)
    }

    override fun getServerStatus(): Flow<ServerStatus> = _serverStatus.asStateFlow()

    override fun getIncomingWipeCommands(): Flow<Long> = _wipeCommands.receiveAsFlow()

    override fun getIncomingPayloads(): Flow<IncomingTransportPayload> = _incomingPayloads.receiveAsFlow()

    override fun currentConnectionGeneration(): Long = connectionGeneration.get()

    override fun runIfConnectionCurrent(
        expectedConnectionGeneration: Long,
        mutation: () -> Boolean
    ): Boolean = synchronized(connectionLock) {
        if (connectionGeneration.get() != expectedConnectionGeneration) false else mutation()
    }

    override fun getRoomChanges(): Flow<RoomChange> = _roomChanges.receiveAsFlow()

    override fun getPresence(): Flow<List<UserPresence>> = _presence.asStateFlow()

    override suspend fun joinChat(chatId: String) {
        joinChatInternal(chatId, expectedConnectionGeneration = null)
    }

    override suspend fun joinChat(chatId: String, expectedConnectionGeneration: Long) {
        joinChatInternal(chatId, expectedConnectionGeneration)
    }

    private fun joinChatInternal(chatId: String, expectedConnectionGeneration: Long?) {
        if (!isSafeIdentifier(chatId)) return
        val frame = JSONObject()
            .put("type", "join")
            .put("chat_id", chatId)
            .toString()
        synchronized(connectionLock) {
            val generation = connectionGeneration.get()
            if (expectedConnectionGeneration != null &&
                generation != expectedConnectionGeneration
            ) {
                return
            }
            rememberJoinedChat(chatId)
            // Keep capture and send in one critical section. Invalidation cannot
            // advance the epoch between the check and writing the frame.
            webSocket?.send(frame)
        }
    }

    private fun rememberJoinedChat(chatId: String) {
        if (!isSafeIdentifier(chatId)) return
        synchronized(joinedChatIds) {
            joinedChatIds.add(chatId)
            while (joinedChatIds.size > MAX_JOINED_CHAT_IDS) {
                val iterator = joinedChatIds.iterator()
                if (!iterator.hasNext()) break
                iterator.next()
                iterator.remove()
            }
        }
    }

    /** Prevent an old catalog callback from repopulating a new socket's joins. */
    private fun rememberJoinedChatForSocket(
        socket: WebSocket,
        generation: Long,
        chatId: String
    ): Boolean = synchronized(connectionLock) {
        if (!isCurrentSocket(socket, generation)) {
            false
        } else {
            rememberJoinedChat(chatId)
            true
        }
    }

    private fun removeJoinedChatForSocket(
        socket: WebSocket,
        generation: Long,
        chatId: String
    ): Boolean = synchronized(connectionLock) {
        if (!isCurrentSocket(socket, generation)) {
            false
        } else {
            synchronized(joinedChatIds) { joinedChatIds.remove(chatId) }
            synchronized(catalogLock) {
                roomCatalogIds.remove(chatId.lowercase(Locale.ROOT))
            }
            true
        }
    }

    private fun isCurrentTicket(call: Call, generation: Long, expected: NodeSession): Boolean =
        isCurrentConnection(generation, expected) &&
            connecting.get() &&
            ticketCall === call

    private fun isCurrentConnection(generation: Long, expected: NodeSession): Boolean =
        generation == connectionGeneration.get() &&
            isSameSession(nodeConfigService.getActiveSession(), expected)

    private fun failTicketConnection(generation: Long, expected: NodeSession) {
        synchronized(connectionLock) {
            if (!isCurrentConnection(generation, expected)) return
            ticketCall = null
            connecting.set(false)
            _serverStatus.value = ServerStatus("DISCONNECTED", expected.nodeId, 0)
        }
    }

    private fun isCurrentSocket(socket: WebSocket, generation: Long): Boolean =
        generation == connectionGeneration.get() && webSocket === socket

    /** Must be called under [connectionLock]. Registration also takes this lock. */
    private fun advanceConnectionEpochAndDrainRoomChangesLocked(): DrainedPendingOperations {
        connectionGeneration.incrementAndGet()
        val currentGeneration = connectionGeneration.get()
        while (_roomChanges.tryReceive().isSuccess) {
            // Catalog changes are scoped to the invalidated connection epoch.
        }
        drainIncomingPayloadsLocked()
        while (_wipeCommands.tryReceive().isSuccess) {
            // Purge commands from the invalidated epoch cannot be applied to a
            // replacement session. A purge close publishes a fresh command
            // after this drain with [currentGeneration].
        }
        purgeSignaled.set(false)
        // Remove only entries that predate the newly published generation while
        // holding the same lock used by send registration. A reconnect may
        // register new entries immediately after this method returns; those
        // entries must never be included in the old invalidation result.
        val outbound = synchronized(pendingOutbound) {
            drainPendingResultsLocked(pendingOutbound, currentGeneration)
        }
        val acknowledgements = synchronized(pendingAcknowledgements) {
            drainPendingResultsLocked(pendingAcknowledgements, currentGeneration)
        }
        return DrainedPendingOperations(outbound, acknowledgements)
    }

    /** Must be called under [connectionLock]. */
    private fun drainIncomingPayloadsLocked() {
        while (true) {
            val payload = _incomingPayloads.tryReceive().getOrNull() ?: return
            wipeIncomingPayload(payload)
        }
    }

    private fun drainPendingResultsLocked(
        pending: LinkedHashMap<String, PendingOperation>,
        currentGeneration: Long
    ): List<CompletableDeferred<OutboundSendResult>> {
        val drained = ArrayList<CompletableDeferred<OutboundSendResult>>(pending.size)
        val iterator = pending.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (entry.value.generation != currentGeneration) {
                drained += entry.value.result
                iterator.remove()
            }
        }
        return drained
    }

    private fun emitRoomChange(socket: WebSocket, generation: Long, change: RoomChange) {
        val overflowed = synchronized(connectionLock) {
            if (!isCurrentSocket(socket, generation)) return
            !_roomChanges.trySend(change.copy(connectionGeneration = generation)).isSuccess
        }
        if (overflowed) {
            // Never silently lose a catalog mutation. Reconnect to obtain a fresh,
            // authoritative snapshot if the bounded consumer queue is exhausted.
            closeCurrentSocket(socket, _serverStatus.value.nodeId, "catalog consumer stalled")
        }
    }

    /**
     * The initial callback check is only an optimization: invalidation may
     * happen while a frame is being parsed. Recheck and enqueue under the
     * connection lock so an old callback cannot publish ciphertext after its
     * socket epoch has been invalidated.
     */
    private fun enqueueIncomingPayload(
        socket: WebSocket,
        generation: Long,
        payload: IncomingTransportPayload
    ) {
        var overflowed = false
        val enqueued = synchronized(connectionLock) {
            if (!isCurrentSocket(socket, generation)) {
                false
            } else if (_incomingPayloads.trySend(payload).isSuccess) {
                true
            } else {
                overflowed = true
                false
            }
        }
        if (!enqueued) wipeIncomingPayload(payload)
        if (overflowed) {
            closeCurrentSocket(socket, _serverStatus.value.nodeId, "incoming consumer stalled")
        }
    }

    private fun takePendingResult(
        socket: WebSocket,
        generation: Long,
        messageId: String,
        pending: LinkedHashMap<String, PendingOperation>
    ): CompletableDeferred<OutboundSendResult>? = synchronized(connectionLock) {
        if (!isCurrentSocket(socket, generation)) {
            null
        } else {
            synchronized(pending) {
                val operation = pending[messageId]
                if (operation == null || operation.generation != generation) {
                    null
                } else {
                    pending.remove(messageId)
                    operation.result
                }
            }
        }
    }

    private fun parseWsTicket(response: Response): WsTicket? {
        if (!response.isSuccessful) return null
        val cacheControl = response.header("Cache-Control") ?: return null
        if (!cacheControl.split(',').any { it.trim().equals("no-store", ignoreCase = true) }) {
            return null
        }
        val body = response.body ?: return null
        if (body.contentLength() > WS_TICKET_MAX_RESPONSE_BYTES) return null
        val raw = runCatching {
            body.source().readByteArray((WS_TICKET_MAX_RESPONSE_BYTES + 1).toLong())
        }.getOrNull() ?: return null
        return try {
            parseWsTicketResponseBody(raw)
        } finally {
            raw.fill(0)
        }
    }

    private fun isSameSession(actual: NodeSession?, expected: NodeSession): Boolean =
        actual?.token == expected.token &&
            actual.nodeId == expected.nodeId &&
            actual.endpoint.apiBaseUrl == expected.endpoint.apiBaseUrl &&
            actual.endpoint.wsBaseUrl == expected.endpoint.wsBaseUrl

    private fun captureSocketSnapshot(expectedGeneration: Long?): SocketSnapshot? =
        synchronized(connectionLock) {
            val generation = connectionGeneration.get()
            val socket = webSocket ?: return@synchronized null
            if (expectedGeneration != null && expectedGeneration != generation) {
                return@synchronized null
            }
            SocketSnapshot(socket, generation)
        }

    private fun sendCommandFrame(frame: String, expectedGeneration: Long?): Boolean {
        return synchronized(connectionLock) {
            val snapshot = captureSocketSnapshot(expectedGeneration) ?: return@synchronized false
            // The socket snapshot and write are atomic with invalidation. This
            // prevents a queued command from reaching a socket after its epoch
            // has been purged.
            val sent = runCatching { snapshot.socket.send(frame) }.getOrDefault(false)
            if (!sent && isCurrentSocket(snapshot.socket, snapshot.generation)) {
                _serverStatus.value = _serverStatus.value.copy(state = "DISCONNECTED")
            }
            sent
        }
    }

    override suspend fun createForum(session: ChatSession) {
        createForumInternal(session, expectedGeneration = null)
    }

    override suspend fun createForum(
        session: ChatSession,
        expectedConnectionGeneration: Long
    ) {
        createForumInternal(session, expectedConnectionGeneration)
    }

    private fun createForumInternal(session: ChatSession, expectedGeneration: Long?) {
        val frame = JSONObject()
            .put("type", "create_room")
            .put("room", session.toRoomJson())
            .toString()
        sendCommandFrame(frame, expectedGeneration)
    }

    override suspend fun deleteForum(chatId: String) {
        deleteForumInternal(chatId, expectedGeneration = null)
    }

    override suspend fun deleteForum(chatId: String, expectedConnectionGeneration: Long) {
        deleteForumInternal(chatId, expectedConnectionGeneration)
    }

    private fun deleteForumInternal(chatId: String, expectedGeneration: Long?) {
        val frame = JSONObject()
            .put("type", "delete_room")
            .put("chat_id", chatId)
            .toString()
        sendCommandFrame(frame, expectedGeneration)
    }

    override suspend fun openDirect(peerUsername: String) {
        openDirectInternal(peerUsername, expectedGeneration = null)
    }

    override suspend fun openDirect(peerUsername: String, expectedConnectionGeneration: Long) {
        openDirectInternal(peerUsername, expectedConnectionGeneration)
    }

    private fun openDirectInternal(peerUsername: String, expectedGeneration: Long?) {
        val frame = JSONObject()
            .put("type", "open_direct")
            .put("peer_username", peerUsername)
            .toString()
        sendCommandFrame(frame, expectedGeneration)
    }

    override suspend fun sendEncryptedPayload(
        chatId: String,
        payload: EncryptedTransportPayload
    ): OutboundSendResult = sendEncryptedPayloadInternal(chatId, payload, null)

    override suspend fun sendEncryptedPayload(
        chatId: String,
        payload: EncryptedTransportPayload,
        expectedConnectionGeneration: Long
    ): OutboundSendResult = sendEncryptedPayloadInternal(
        chatId,
        payload,
        expectedConnectionGeneration
    )

    private suspend fun sendEncryptedPayloadInternal(
        chatId: String,
        payload: EncryptedTransportPayload,
        expectedGeneration: Long?
    ): OutboundSendResult {
        var registered = false
        lateinit var socket: WebSocket
        var generation = 0L
        return try {
            if (payload.version != PROTOCOL_VERSION || payload.stateSignature.size != STATE_SIGNATURE_BYTES) {
                return OutboundSendResult.NOT_SENT
            }
            val frame = JSONObject()
                .put("type", "message")
                .put("chat_id", chatId)
                .put("version", payload.version)
                .put("message_id", payload.messageId)
                .put("nonce_b64", encode(payload.nonce))
                .put("ciphertext_b64", encode(payload.ciphertext))
                .put("state_revision", payload.stateRevision.toLong())
                .put("identity_envelope_b64", encode(payload.identityEnvelope))
                .put("identity_public_b64", encode(payload.identityPublicKey))
                .put("prekey_id", payload.prekeyId)
                .put("state_signature_b64", encode(payload.stateSignature))
                .put("envelopes", JSONArray().apply {
                    payload.envelopes.forEach { envelope ->
                        put(
                            JSONObject()
                                .put("recipient_username", envelope.recipientUsername)
                                .put("wrapped_key_b64", encode(envelope.wrappedKey))
                                .put("prekey_id", envelope.prekeyId)
                                .put("is_prekey", envelope.isPrekey)
                                .put("signature_b64", encode(envelope.signature))
                        )
                    }
                })
                .toString()
            // Outbound encrypted frames contain ASCII JSON and base64url only, so
            // character count equals wire bytes here.
            if (frame.length > MAX_WEBSOCKET_FRAME_BYTES) {
                return OutboundSendResult.NOT_SENT
            }
            val result = CompletableDeferred<OutboundSendResult>()
            synchronized(connectionLock) {
                socket = webSocket ?: return OutboundSendResult.NOT_SENT
                generation = connectionGeneration.get()
                if (expectedGeneration != null && generation != expectedGeneration) {
                    return OutboundSendResult.NOT_SENT
                }
                synchronized(pendingOutbound) {
                    if (pendingOutbound.size >= MAX_PENDING_OUTBOUND &&
                        !pendingOutbound.containsKey(payload.messageId)
                    ) return OutboundSendResult.NOT_SENT
                    if (pendingOutbound.containsKey(payload.messageId)) {
                        return OutboundSendResult.NOT_SENT
                    }
                    pendingOutbound[payload.messageId] = PendingOperation(generation, result)
                    registered = true
                }
            }
            val sent = synchronized(connectionLock) {
                if (!isCurrentSocket(socket, generation)) {
                    false
                } else {
                    // Registration, epoch validation, and the socket write are
                    // one critical section; invalidation either drains this
                    // operation first or observes the already-sent frame.
                    runCatching { socket.send(frame) }.getOrDefault(false)
                }
            }
            if (!sent) {
                synchronized(pendingOutbound) {
                    val pending = pendingOutbound[payload.messageId]
                    if (pending?.generation == generation && pending.result === result) {
                        pendingOutbound.remove(payload.messageId)
                    }
                }
                if (isCurrentSocket(socket, generation)) {
                    closeCurrentSocket(socket, _serverStatus.value.nodeId, "message send failed")
                }
                return OutboundSendResult.NOT_SENT
            }
            try {
                withTimeout(OUTBOUND_RESULT_TIMEOUT_MS) { result.await() }
            } catch (_: kotlinx.coroutines.TimeoutCancellationException) {
                abortPendingOutbound(socket, generation, payload.messageId, result, "message result timeout")
                OutboundSendResult.AMBIGUOUS
            } catch (_: CancellationException) {
                abortPendingOutbound(socket, generation, payload.messageId, result, "message send cancelled")
                OutboundSendResult.AMBIGUOUS
            }
        } catch (error: CancellationException) {
            if (!registered) throw error
            abortPendingOutbound(socket, generation, payload.messageId, null, "message send cancelled")
            OutboundSendResult.AMBIGUOUS
        } catch (_: Exception) {
            if (registered) {
                abortPendingOutbound(socket, generation, payload.messageId, null, "message send failed")
                OutboundSendResult.AMBIGUOUS
            } else {
                OutboundSendResult.NOT_SENT
            }
        } finally {
            wipeEncryptedPayload(payload)
        }
    }

    override suspend fun acknowledgeMessage(
        chatId: String,
        messageId: String,
        senderUsername: String,
        state: IdentityStateSnapshot,
        usedPrekeyId: String,
        ackSignature: ByteArray
    ): OutboundSendResult = acknowledgeMessageInternal(
        chatId,
        messageId,
        senderUsername,
        state,
        usedPrekeyId,
        ackSignature,
        null
    )

    override suspend fun acknowledgeMessage(
        chatId: String,
        messageId: String,
        senderUsername: String,
        state: IdentityStateSnapshot,
        usedPrekeyId: String,
        ackSignature: ByteArray,
        expectedConnectionGeneration: Long
    ): OutboundSendResult = acknowledgeMessageInternal(
        chatId,
        messageId,
        senderUsername,
        state,
        usedPrekeyId,
        ackSignature,
        expectedConnectionGeneration
    )

    private suspend fun acknowledgeMessageInternal(
        chatId: String,
        messageId: String,
        senderUsername: String,
        state: IdentityStateSnapshot,
        usedPrekeyId: String,
        ackSignature: ByteArray,
        expectedGeneration: Long?
    ): OutboundSendResult {
        val frame = try {
            if (!isSafeIdentifier(chatId) || !isSafeIdentifier(messageId) ||
                !isSafeUsername(senderUsername) ||
                (usedPrekeyId.isNotEmpty() && !PREKEY_ID_REGEX.matches(usedPrekeyId)) ||
                state.stateSignature.size != STATE_SIGNATURE_BYTES ||
                state.identityPublicKey.size != IDENTITY_PUBLIC_KEY_BYTES ||
                ackSignature.size != ACK_SIGNATURE_BYTES
            ) return OutboundSendResult.NOT_SENT
            JSONObject()
                .put("type", "message_ack")
                .put("chat_id", chatId)
                .put("message_id", messageId)
                .put("sender_username", senderUsername)
                .put("state_revision", state.revision.toLong())
                .put("identity_envelope_b64", encode(state.envelope))
                .put("identity_public_b64", encode(state.identityPublicKey))
                .put("prekey_id", state.prekeyId)
                .put("state_signature_b64", encode(state.stateSignature))
                .put("ack_signature_b64", encode(ackSignature))
                .put("used_prekey_id", usedPrekeyId)
                .toString()
        } catch (_: Exception) {
            return OutboundSendResult.NOT_SENT
        }
        if (frame.length > MAX_WEBSOCKET_FRAME_BYTES) return OutboundSendResult.NOT_SENT
        val result = CompletableDeferred<OutboundSendResult>()
        lateinit var socket: WebSocket
        val generation: Long
        synchronized(connectionLock) {
            socket = webSocket ?: return OutboundSendResult.NOT_SENT
            generation = connectionGeneration.get()
            if (expectedGeneration != null && generation != expectedGeneration) {
                return OutboundSendResult.NOT_SENT
            }
            synchronized(pendingAcknowledgements) {
                if (pendingAcknowledgements.size >= MAX_PENDING_ACKNOWLEDGEMENTS ||
                    pendingAcknowledgements.containsKey(messageId)
                ) return OutboundSendResult.NOT_SENT
                pendingAcknowledgements[messageId] = PendingOperation(generation, result)
            }
        }
        val sent = synchronized(connectionLock) {
            if (!isCurrentSocket(socket, generation)) {
                false
            } else {
                try {
                    // See sendEncryptedPayloadInternal: do not let invalidation
                    // race between registration and the write.
                    socket.send(frame)
                } catch (_: Exception) {
                    false
                }
            }
        }
        if (!sent) {
            synchronized(pendingAcknowledgements) {
                val pending = pendingAcknowledgements[messageId]
                if (pending?.generation == generation && pending.result === result) {
                    pendingAcknowledgements.remove(messageId)
                }
            }
            if (isCurrentSocket(socket, generation)) {
                closeCurrentSocket(socket, _serverStatus.value.nodeId, "ack send failed")
            }
            return OutboundSendResult.NOT_SENT
        }
        return try {
            withTimeout(OUTBOUND_RESULT_TIMEOUT_MS) { result.await() }
        } catch (_: kotlinx.coroutines.TimeoutCancellationException) {
            abortPendingAcknowledgement(socket, generation, messageId, result, "ack result timeout")
            OutboundSendResult.AMBIGUOUS
        } catch (_: CancellationException) {
            abortPendingAcknowledgement(socket, generation, messageId, result, "ack send cancelled")
            OutboundSendResult.AMBIGUOUS
        } catch (_: Exception) {
            abortPendingAcknowledgement(socket, generation, messageId, result, "ack result failed")
            OutboundSendResult.AMBIGUOUS
        }
    }

    override suspend fun syncIdentityState(state: IdentityStateSnapshot): Boolean {
        return syncIdentityStateInternal(state, expectedGeneration = null)
    }

    override suspend fun syncIdentityState(
        state: IdentityStateSnapshot,
        expectedConnectionGeneration: Long
    ): Boolean = syncIdentityStateInternal(state, expectedConnectionGeneration)

    private fun syncIdentityStateInternal(
        state: IdentityStateSnapshot,
        expectedGeneration: Long?
    ): Boolean {
        if (state.stateSignature.size != STATE_SIGNATURE_BYTES) return false
        return sendCommandFrame(
            JSONObject()
                .put("type", "identity_state")
                .put("state_revision", state.revision.toLong())
                .put("identity_envelope_b64", encode(state.envelope))
                .put("identity_public_b64", encode(state.identityPublicKey))
                .put("prekey_id", state.prekeyId)
                .put("state_signature_b64", encode(state.stateSignature))
                .toString(),
            expectedGeneration
        )
    }

    override suspend fun signalUserActivity(): Boolean {
        return signalUserActivityInternal(expectedGeneration = null)
    }

    override suspend fun signalUserActivity(expectedConnectionGeneration: Long): Boolean =
        signalUserActivityInternal(expectedConnectionGeneration)

    private fun signalUserActivityInternal(expectedGeneration: Long?): Boolean =
        sendCommandFrame(JSONObject().put("type", "activity").toString(), expectedGeneration)

    override suspend fun broadcastGlobalWipe() {
        broadcastGlobalWipeInternal(expectedGeneration = null)
    }

    override suspend fun broadcastGlobalWipe(expectedConnectionGeneration: Long) {
        broadcastGlobalWipeInternal(expectedConnectionGeneration)
    }

    private fun broadcastGlobalWipeInternal(expectedGeneration: Long?) {
        val frame = JSONObject()
            .put("type", "global_wipe")
            .toString()
        sendCommandFrame(frame, expectedGeneration)
    }

    private fun listener(nodeId: String, generation: Long): WebSocketListener {
        return object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                val chatsToJoin = synchronized(connectionLock) {
                    if (!isCurrentSocket(webSocket, generation)) {
                        null
                    } else {
                        // Collections.synchronizedSet still requires its
                        // monitor while iterating. Keep the snapshot under
                        // connectionLock as well, matching invalidation's
                        // connectionLock -> joinedChatIds lock order.
                        connecting.set(false)
                        _serverStatus.value = ServerStatus("CONNECTED", nodeId, 0)
                        synchronized(joinedChatIds) { joinedChatIds.toList() }
                    }
                }
                if (chatsToJoin == null) {
                    webSocket.close(1000, "stale connection")
                    return
                }
                chatsToJoin.forEach { chatId ->
                    sendJoinFrameForSocket(webSocket, generation, chatId)
                }
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                if (!isCurrentSocket(webSocket, generation)) return
                if (disconnectForOversizedTextFrame(webSocket, text, nodeId)) return
                runCatching {
                    val json = JSONObject(text)
                    when (json.optString("type")) {
                        "GLOBAL_WIPE", "global_wipe" -> signalPurgeForSocket(webSocket, generation)
                        "message" -> {
                            if (json.optInt("version") != PROTOCOL_VERSION) return
                            json.toIncomingPayload(generation)?.let { payload ->
                                if (!isAuthorizedIncomingPayload(payload)) {
                                    wipeIncomingPayload(payload)
                                    return@let
                                }
                                enqueueIncomingPayload(webSocket, generation, payload)
                            }
                        }
                        "message_result" -> {
                            val parsed = json.toOutboundMessageResult()
                            if (parsed == null) {
                                closeCurrentSocket(webSocket, nodeId, "invalid message result")
                                return
                            }
                            val (messageId, accepted) = parsed
                            val pending = takePendingResult(
                                webSocket,
                                generation,
                                messageId,
                                pendingOutbound
                            )
                            if (pending == null) {
                                closeCurrentSocket(webSocket, nodeId, "unexpected message result")
                                return
                            }
                            pending.complete(
                                if (accepted) OutboundSendResult.ACCEPTED
                                else OutboundSendResult.REJECTED
                            )
                        }
                        "ack_result" -> {
                            val parsed = json.toAcknowledgementResult()
                            if (parsed == null) {
                                closeCurrentSocket(webSocket, nodeId, "invalid ack result")
                                return
                            }
                            val (messageId, accepted) = parsed
                            val pending = takePendingResult(
                                webSocket,
                                generation,
                                messageId,
                                pendingAcknowledgements
                            )
                            if (pending == null) {
                                closeCurrentSocket(webSocket, nodeId, "unexpected ack result")
                                return
                            }
                            pending.complete(
                                if (accepted) OutboundSendResult.ACCEPTED
                                else OutboundSendResult.REJECTED
                            )
                        }
                        "presence" -> {
                            val users = json.optJSONArray("users") ?: return
                            val catalog = users.toPresenceCatalog() ?: return
                            if (!acceptPresenceCatalogForSocket(webSocket, generation, catalog)) {
                                wipePresence(catalog.entries)
                                closeCurrentSocket(webSocket, nodeId, "directory changed")
                                return
                            }
                            Unit
                        }
                        "rooms" -> {
                            val rooms = json.optJSONArray("rooms") ?: return
                            val sessions = rooms.toChatSessions(MAX_ROOM_CATALOG_ENTRIES) ?: return
                            if (!installRoomCatalogForSocket(webSocket, generation, sessions)) return
                            sessions.forEach { session ->
                                if (rememberJoinedChatForSocket(webSocket, generation, session.id)) {
                                    emitRoomChange(webSocket, generation, RoomChange("upsert", session = session))
                                }
                            }
                        }
                        "room_created" -> {
                            json.optJSONObject("room")?.toChatSession()
                                ?.takeIf { acceptDynamicRoomForSocket(webSocket, generation, it) }
                                ?.let { session ->
                                    if (rememberJoinedChatForSocket(webSocket, generation, session.id)) {
                                        emitRoomChange(webSocket, generation, RoomChange("upsert", session = session))
                                    }
                                }
                        }
                        "room_deleted" -> {
                            val chatId = json.optString("chat_id")
                                .takeIf { it.startsWith("forum_") && isSafeIdentifier(it) } ?: return
                            if (removeJoinedChatForSocket(webSocket, generation, chatId)) {
                                emitRoomChange(webSocket, generation, RoomChange("delete", chatId = chatId))
                            }
                            Unit
                        }
                        "directs" -> {
                            val directs = json.optJSONArray("directs") ?: return
                            val sessions = directs.toDirectSessions() ?: return
                            if (!installDirectCatalogForSocket(webSocket, generation, sessions)) return
                            sessions.forEach { session ->
                                if (rememberJoinedChatForSocket(webSocket, generation, session.id)) {
                                    emitRoomChange(webSocket, generation, RoomChange("upsert", session = session))
                                }
                            }
                        }
                        "direct_opened" -> {
                            json.optJSONObject("direct")?.toDirectSession()
                                ?.takeIf { acceptDynamicDirectForSocket(webSocket, generation, it) }
                                ?.let { session ->
                                    if (rememberJoinedChatForSocket(webSocket, generation, session.id)) {
                                        emitRoomChange(webSocket, generation, RoomChange("upsert", session = session))
                                    }
                                }
                        }
                        else -> Unit
                    }
                }
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                invalidateCurrentSocket(
                    socket = webSocket,
                    nodeId = nodeId,
                    closeCode = null,
                    reason = reason,
                    signalPurge = isPurgeClose(code, reason)
                )
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                invalidateCurrentSocket(
                    socket = webSocket,
                    nodeId = nodeId,
                    closeCode = null,
                    reason = "socket failure"
                )
            }
        }
    }

    internal fun signalPurge() {
        synchronized(connectionLock) {
            signalPurgeLocked(connectionGeneration.get(), force = false)
        }
    }

    private fun signalPurgeForSocket(socket: WebSocket, generation: Long) {
        synchronized(connectionLock) {
            if (isCurrentSocket(socket, generation)) {
                signalPurgeLocked(generation, force = false)
            }
        }
    }

    /** Must be called under [connectionLock]. */
    private fun signalPurgeLocked(generation: Long, force: Boolean) {
        if (force) {
            purgeSignaled.set(true)
            _wipeCommands.trySend(generation)
        } else if (purgeSignaled.compareAndSet(false, true)) {
            _wipeCommands.trySend(generation)
        }
    }

    private fun completeDrainedPendingOperations(
        drained: DrainedPendingOperations,
        result: OutboundSendResult
    ) {
        drained.outbound.forEach { it.complete(result) }
        drained.acknowledgements.forEach { it.complete(result) }
    }

    private fun abortPendingOutbound(
        socket: WebSocket,
        generation: Long,
        messageId: String,
        expected: CompletableDeferred<OutboundSendResult>?,
        reason: String
    ) {
        synchronized(pendingOutbound) {
            val actual = pendingOutbound[messageId]
            if (actual?.generation == generation &&
                (expected == null || actual.result === expected)
            ) {
                pendingOutbound.remove(messageId)
            }
        }
        if (isCurrentSocket(socket, generation)) {
            closeCurrentSocket(socket, _serverStatus.value.nodeId, reason, closeCode = 1001)
        }
    }

    private fun abortPendingAcknowledgement(
        socket: WebSocket,
        generation: Long,
        messageId: String,
        expected: CompletableDeferred<OutboundSendResult>,
        reason: String
    ) {
        val removed = synchronized(pendingAcknowledgements) {
            val actual = pendingAcknowledgements[messageId]
            if (actual?.generation != generation || actual.result !== expected) {
                false
            } else {
                pendingAcknowledgements.remove(messageId)
                true
            }
        }
        if (!removed) return
        if (isCurrentSocket(socket, generation)) {
            closeCurrentSocket(socket, _serverStatus.value.nodeId, reason)
        }
    }

    internal fun disconnectForOversizedTextFrame(
        socket: WebSocket,
        text: String,
        nodeId: String
    ): Boolean {
        if (!exceedsUtf8ByteLimit(text, MAX_WEBSOCKET_FRAME_BYTES)) return false
        closeCurrentSocket(socket, nodeId, "message too big", closeCode = 1009)
        return true
    }

    private fun closeCurrentSocket(
        socket: WebSocket,
        nodeId: String,
        reason: String,
        closeCode: Int = 1008
    ) {
        invalidateCurrentSocket(socket, nodeId, closeCode, reason)
    }

    private fun invalidateCurrentSocket(
        socket: WebSocket,
        nodeId: String,
        closeCode: Int?,
        reason: String,
        signalPurge: Boolean = false
    ) {
        val drainedPending: DrainedPendingOperations
        synchronized(connectionLock) {
            if (webSocket !== socket) return
            // A GLOBAL_WIPE frame can be queued immediately before the socket
            // fails. Carry that command into the post-invalidation generation
            // instead of draining and silently losing it.
            val carryPurge = signalPurge || purgeSignaled.get()
            drainedPending = advanceConnectionEpochAndDrainRoomChangesLocked()
            if (carryPurge) {
                signalPurgeLocked(connectionGeneration.get(), force = true)
            }
            connecting.set(false)
            webSocket = null
            // Authorization is scoped to the authenticated socket. Keep this
            // under the connection lock so a reconnect cannot install a new
            // catalog between invalidation and the old catalog being purged.
            clearAuthorizationStateLocked()
            clearPresence()
            _serverStatus.value = ServerStatus("DISCONNECTED", nodeId, 0)
        }
        completeDrainedPendingOperations(drainedPending, OutboundSendResult.AMBIGUOUS)
        if (closeCode != null && !socket.close(closeCode, reason)) socket.cancel()
    }

    /**
     * Clears all socket-scoped routing and identity authorization.
     *
     * Callers hold [connectionLock]. Child locks are always acquired in the
     * order joined-chat set, identity pins, then catalog maps; no catalog
     * operation acquires the connection lock while holding a child lock.
     */
    private fun clearAuthorizationStateLocked() {
        synchronized(joinedChatIds) {
            joinedChatIds.clear()
        }
        synchronized(identityPins) {
            identityPins.clear()
        }
        synchronized(catalogLock) {
            roomCatalogIds.clear()
            directCatalogIds.clear()
            directCatalogPeers.clear()
            directCatalogPeerById.clear()
        }
    }

    /** Replays a join only to the callback socket that received onOpen. */
    private fun sendJoinFrameForSocket(
        socket: WebSocket,
        generation: Long,
        chatId: String
    ) {
        val frame = JSONObject()
            .put("type", "join")
            .put("chat_id", chatId)
            .toString()
        synchronized(connectionLock) {
            if (isCurrentSocket(socket, generation)) socket.send(frame)
        }
    }

    private fun wipeIncomingPayload(payload: IncomingTransportPayload) {
        payload.nonce.fill(0)
        payload.ciphertext.fill(0)
        payload.signature.fill(0)
        payload.wrappedKey.fill(0)
        payload.senderPublicKey.fill(0)
        payload.identityPublicKey.fill(0)
    }

    private fun wipeEncryptedPayload(payload: EncryptedTransportPayload) {
        payload.nonce.fill(0)
        payload.ciphertext.fill(0)
        payload.identityEnvelope.fill(0)
        payload.identityPublicKey.fill(0)
        payload.stateSignature.fill(0)
        payload.envelopes.forEach {
            it.wrappedKey.fill(0)
            it.signature.fill(0)
        }
    }

    private fun clearPresence() {
        val previous = _presence.value
        _presence.value = emptyList()
        wipePresence(previous)
    }

    internal fun acceptPresenceCatalog(catalog: PresenceCatalog): Boolean {
        if (catalog.entries.map { it.directoryDigest }.distinct().size > 1) return false
        if (!pinIdentities(catalog.identityPins)) return false
        val previousPresence = _presence.value
        _presence.value = catalog.entries
        wipePresence(previousPresence)
        return true
    }

    private fun acceptPresenceCatalogForSocket(
        socket: WebSocket,
        generation: Long,
        catalog: PresenceCatalog
    ): Boolean = synchronized(connectionLock) {
        isCurrentSocket(socket, generation) && acceptPresenceCatalog(catalog)
    }

    private fun installRoomCatalog(sessions: List<ChatSession>) {
        synchronized(catalogLock) {
            roomCatalogIds.clear()
            sessions.forEach { session ->
                roomCatalogIds[session.id.lowercase(Locale.ROOT)] = session.id
            }
        }
    }

    private fun installRoomCatalogForSocket(
        socket: WebSocket,
        generation: Long,
        sessions: List<ChatSession>
    ): Boolean = synchronized(connectionLock) {
        if (!isCurrentSocket(socket, generation)) {
            false
        } else {
            installRoomCatalog(sessions)
            true
        }
    }

    private fun installDirectCatalog(sessions: List<ChatSession>) {
        synchronized(catalogLock) {
            directCatalogIds.clear()
            directCatalogPeers.clear()
            directCatalogPeerById.clear()
            sessions.forEach { session ->
                val idKey = session.id.lowercase(Locale.ROOT)
                val peerKey = session.name.lowercase(Locale.ROOT)
                directCatalogIds[idKey] = session.id
                directCatalogPeers[peerKey] = session.name
                directCatalogPeerById[idKey] = session.name
            }
        }
    }

    private fun installDirectCatalogForSocket(
        socket: WebSocket,
        generation: Long,
        sessions: List<ChatSession>
    ): Boolean = synchronized(connectionLock) {
        if (!isCurrentSocket(socket, generation)) {
            false
        } else {
            installDirectCatalog(sessions)
            true
        }
    }

    internal fun acceptDynamicRoom(session: ChatSession): Boolean {
        if (!session.isForum ||
            !session.id.startsWith("forum_") ||
            !isSafeIdentifier(session.id)
        ) return false
        val key = session.id.lowercase(Locale.ROOT)
        synchronized(catalogLock) {
            val existing = roomCatalogIds[key]
            if (existing != null && existing != session.id) return false
            if (existing == null && roomCatalogIds.size >= MAX_ROOM_CATALOG_ENTRIES) return false
            roomCatalogIds[key] = session.id
            return true
        }
    }

    private fun acceptDynamicRoomForSocket(
        socket: WebSocket,
        generation: Long,
        session: ChatSession
    ): Boolean = synchronized(connectionLock) {
        isCurrentSocket(socket, generation) && acceptDynamicRoom(session)
    }

    internal fun acceptDynamicDirect(session: ChatSession): Boolean {
        if (session.isForum ||
            !session.id.matches(DIRECT_ID_REGEX) ||
            !isSafeUsername(session.name)
        ) return false
        val idKey = session.id.lowercase(Locale.ROOT)
        val peerKey = session.name.lowercase(Locale.ROOT)
        synchronized(catalogLock) {
            val existingId = directCatalogIds[idKey]
            val existingPeer = directCatalogPeers[peerKey]
            if ((existingId != null && existingId != session.id) ||
                (existingPeer != null && existingPeer != session.name) ||
                (existingPeer != null && existingId == null) ||
                (existingId != null && existingPeer == null)
            ) return false
            if (existingId == null && directCatalogIds.size >= MAX_DIRECT_CATALOG_ENTRIES) return false
            directCatalogIds[idKey] = session.id
            directCatalogPeers[peerKey] = session.name
            directCatalogPeerById[idKey] = session.name
            return true
        }
    }

    private fun acceptDynamicDirectForSocket(
        socket: WebSocket,
        generation: Long,
        session: ChatSession
    ): Boolean = synchronized(connectionLock) {
        isCurrentSocket(socket, generation) && acceptDynamicDirect(session)
    }

    /**
     * A valid envelope is not sufficient authorization to enter the message
     * collector. The relay's catalog is the local routing boundary: rooms must
     * be known, and a direct envelope must name the peer bound to that direct id.
     */
    internal fun isAuthorizedIncomingPayload(payload: IncomingTransportPayload): Boolean {
        val idKey = payload.chatId.lowercase(Locale.ROOT)
        synchronized(catalogLock) {
            return when {
                idKey.startsWith("forum_") -> roomCatalogIds.containsKey(idKey)
                idKey.startsWith("dm_") -> directCatalogPeerById[idKey]
                    ?.equals(payload.senderUsername, ignoreCase = true) == true
                else -> false
            }
        }
    }

    private fun wipePresence(presence: List<UserPresence>) {
        presence.forEach { it.publicKey.fill(0) }
    }

    internal data class PresenceCatalog(
        val entries: List<UserPresence>,
        val identityPins: Map<String, String>
    )

    private object InvalidCatalogException : Exception()

    private fun hasExactKeys(json: JSONObject, expected: Set<String>): Boolean =
        json.keys().asSequence().toSet() == expected

    private fun JSONObject.stringValue(key: String): String? =
        if (!has(key) || isNull(key)) null else get(key) as? String

    private fun JSONObject.booleanValue(key: String): Boolean? =
        if (!has(key) || isNull(key)) null else get(key) as? Boolean

    private fun decodeCanonicalBase64Url(value: String, expectedBytes: Int): ByteArray? {
        val expectedLength = (expectedBytes * 8 + 5) / 6
        if (value.length != expectedLength || !CANONICAL_BASE64_URL_REGEX.matches(value)) return null
        val decoded = runCatching { decode(value) }.getOrNull() ?: return null
        if (decoded.size != expectedBytes || encode(decoded) != value) {
            decoded.fill(0)
            return null
        }
        return decoded
    }

    internal fun JSONArray.toPresenceCatalog(): PresenceCatalog? {
        if (length() > MAX_PRESENCE_ENTRIES) return null
        val entries = ArrayList<UserPresence>(length())
        val identityPins = LinkedHashMap<String, String>(length())
        val usernames = HashSet<String>(length())
        return try {
            for (index in 0 until length()) {
                var publicKey: ByteArray? = null
                try {
                    val user = optJSONObject(index) ?: throw InvalidCatalogException
                    if (!hasExactKeys(user, PRESENCE_KEYS)) throw InvalidCatalogException
                    val username = user.stringValue("username")
                        ?.takeIf(::isSafeUsername) ?: throw InvalidCatalogException
                    val usernameKey = username.lowercase(Locale.ROOT)
                    if (!usernames.add(usernameKey)) throw InvalidCatalogException
                    val publicKeyB64 = user.stringValue("identity_public_b64")
                        ?: throw InvalidCatalogException
                    publicKey = decodeCanonicalBase64Url(publicKeyB64, IDENTITY_PUBLIC_KEY_BYTES)
                        ?: throw InvalidCatalogException
                    val prekeyId = user.stringValue("identity_prekey_id")
                        ?.takeIf { PREKEY_ID_REGEX.matches(it) } ?: throw InvalidCatalogException
                    val directoryDigest = user.stringValue("directory_digest")
                        ?: throw InvalidCatalogException
                    val digestBytes = decodeCanonicalBase64Url(directoryDigest, DIRECTORY_DIGEST_BYTES)
                        ?: throw InvalidCatalogException
                    digestBytes.fill(0)
                    val connected = user.booleanValue("connected") ?: throw InvalidCatalogException
                    val fingerprintBytes = publicKey.copyOfRange(0, IDENTITY_FINGERPRINT_BYTES)
                    val fingerprint = try {
                        encode(fingerprintBytes)
                    } finally {
                        fingerprintBytes.fill(0)
                    }
                    identityPins[usernameKey] = fingerprint
                    entries += UserPresence(
                        username = username,
                        connected = connected,
                        publicKey = publicKey,
                        prekeyId = prekeyId,
                        directoryDigest = directoryDigest
                    )
                    publicKey = null
                } finally {
                    publicKey?.fill(0)
                }
            }
            PresenceCatalog(entries, identityPins)
        } catch (_: Exception) {
            wipePresence(entries)
            null
        }
    }

    internal fun JSONArray.toChatSessions(maxEntries: Int): List<ChatSession>? {
        if (length() > maxEntries) return null
        val sessions = ArrayList<ChatSession>(length())
        val ids = HashSet<String>(length())
        for (index in 0 until length()) {
            val session = optJSONObject(index)?.toChatSession() ?: return null
            if (!ids.add(session.id.lowercase(Locale.ROOT))) return null
            sessions += session
        }
        return sessions
    }

    internal fun JSONArray.toDirectSessions(): List<ChatSession>? {
        if (length() > MAX_DIRECT_CATALOG_ENTRIES) return null
        val sessions = ArrayList<ChatSession>(length())
        val ids = HashSet<String>(length())
        val peers = HashSet<String>(length())
        for (index in 0 until length()) {
            val session = optJSONObject(index)?.toDirectSession() ?: return null
            if (!ids.add(session.id.lowercase(Locale.ROOT)) ||
                !peers.add(session.name.lowercase(Locale.ROOT))
            ) return null
            sessions += session
        }
        return sessions
    }

    internal fun pinIdentities(pins: Map<String, String>): Boolean {
        synchronized(identityPins) {
            if (pins.any { (username, fingerprint) ->
                    identityPins[username]?.let { it != fingerprint } == true
                }
            ) return false
            val newPins = pins.keys.count { !identityPins.containsKey(it) }
            if (identityPins.size + newPins > MAX_PINNED_IDENTITIES) return false
            pins.forEach { (username, fingerprint) -> identityPins[username] = fingerprint }
            return true
        }
    }

    internal fun isPinnedIdentity(username: String, publicKey: ByteArray): Boolean {
        if (publicKey.size != IDENTITY_PUBLIC_KEY_BYTES) return false
        val fingerprintBytes = publicKey.copyOfRange(0, IDENTITY_FINGERPRINT_BYTES)
        val fingerprint = try {
            encode(fingerprintBytes)
        } finally {
            fingerprintBytes.fill(0)
        }
        synchronized(identityPins) {
            val pinned = identityPins[username.lowercase(Locale.ROOT)] == fingerprint
            val present = _presence.value.any { it.username.equals(username, ignoreCase = true) }
            return pinned && present
        }
    }

    internal fun JSONObject.toIncomingPayload(connectionGeneration: Long = 0L): IncomingTransportPayload? {
        var nonce: ByteArray? = null
        var ciphertext: ByteArray? = null
        var signature: ByteArray? = null
        var wrappedKey: ByteArray? = null
        var senderPublicKey: ByteArray? = null
        var identityPublicKey: ByteArray? = null
        var ownershipTransferred = false
        return try {
            val chatId = optString("chat_id").takeIf { isSafeIdentifier(it) } ?: return null
            val messageId = optString("message_id").takeIf { isSafeIdentifier(it) } ?: return null
            val version = optInt("version")
            if (version != PROTOCOL_VERSION) return null
            val senderUsername = optString("sender_username")
                .takeIf { isSafeUsername(it) } ?: return null
            val prekeyId = optString("prekey_id")
            val isPrekey = optBoolean("is_prekey", false)
            if (isPrekey != prekeyId.isNotEmpty() ||
                (prekeyId.isNotEmpty() && !PREKEY_ID_REGEX.matches(prekeyId))
            ) return null

            val decodedNonce = decode(getString("nonce_b64"))
            val decodedCiphertext = decode(getString("ciphertext_b64"))
            val decodedSignature = decode(getString("signature_b64"))
            val decodedWrappedKey = decode(getString("wrapped_key_b64"))
            val decodedSenderPublicKey = decode(getString("sender_public_key_b64"))
            val decodedIdentityPublicKey = decode(getString("identity_public_b64"))
            nonce = decodedNonce
            ciphertext = decodedCiphertext
            signature = decodedSignature
            wrappedKey = decodedWrappedKey
            senderPublicKey = decodedSenderPublicKey
            identityPublicKey = decodedIdentityPublicKey
            if (
                decodedNonce.size != MESSAGE_NONCE_BYTES ||
                decodedCiphertext.isEmpty() || decodedCiphertext.size > MAX_CIPHERTEXT_BYTES ||
                decodedSignature.size != MESSAGE_SIGNATURE_BYTES ||
                decodedWrappedKey.isEmpty() || decodedWrappedKey.size > MAX_WRAPPED_KEY_BYTES ||
                decodedSenderPublicKey.size != IDENTITY_PUBLIC_KEY_BYTES ||
                decodedIdentityPublicKey.size != IDENTITY_PUBLIC_KEY_BYTES ||
                !isPinnedIdentity(senderUsername, decodedSenderPublicKey)
            ) return null

            val payload = IncomingTransportPayload(
                chatId = chatId,
                messageId = messageId,
                version = version,
                identityPublicKey = decodedIdentityPublicKey,
                nonce = decodedNonce,
                ciphertext = decodedCiphertext,
                signature = decodedSignature,
                wrappedKey = decodedWrappedKey,
                senderUsername = senderUsername,
                senderPublicKey = decodedSenderPublicKey,
                prekeyId = prekeyId,
                isPrekey = isPrekey,
                connectionGeneration = connectionGeneration
            )
            ownershipTransferred = true
            payload
        } catch (_: Exception) {
            null
        } finally {
            if (!ownershipTransferred) {
                nonce?.fill(0)
                ciphertext?.fill(0)
                signature?.fill(0)
                wrappedKey?.fill(0)
                senderPublicKey?.fill(0)
                identityPublicKey?.fill(0)
            }
        }
    }

    private fun ChatSession.toRoomJson(): JSONObject {
        return JSONObject()
            .put("id", id)
            .put("name", name)
            .put("self_destruct_timer_sec", selfDestructTimerSec)
            .put("overall_expiry_sec", overallExpirySec)
            .put("allow_images", allowImages)
            .put("allow_videos", allowVideos)
            .put("allow_files", allowFiles)
            .put("enforce_text_absolute_expiry", enforceTextAbsoluteExpiry)
            .put("image_read_timer_sec", imageReadTimerSec)
            .put("image_overall_expiry_sec", imageOverallExpirySec)
            .put("enforce_image_absolute_expiry", enforceImageAbsoluteExpiry)
            .put("video_read_timer_sec", videoReadTimerSec)
            .put("video_overall_expiry_sec", videoOverallExpirySec)
            .put("enforce_video_absolute_expiry", enforceVideoAbsoluteExpiry)
            .put("file_read_timer_sec", fileReadTimerSec)
            .put("file_overall_expiry_sec", fileOverallExpirySec)
            .put("enforce_file_absolute_expiry", enforceFileAbsoluteExpiry)
    }

    private fun JSONObject.toChatSession(): ChatSession? {
        if (!hasExactKeys(this, ROOM_KEYS)) return null
        val chatId = stringValue("id")
            ?.takeIf { it.startsWith("forum_") && isSafeIdentifier(it) } ?: return null
        val name = stringValue("name")
            ?.takeIf { it.isNotEmpty() && it.length <= MAX_ROOM_NAME_CHARS }
            ?.takeIf { name -> name.none(Char::isISOControl) }
            ?: return null
        val ownerUsername = stringValue("owner_username")
            ?.takeIf(::isSafeUsername) ?: return null
        return ChatSession(
            id = chatId,
            name = name,
            isForum = true,
            lastMessage = null,
            unreadCount = 0,
            selfDestructTimerSec = intSecondsValue("self_destruct_timer_sec") ?: return null,
            overallExpirySec = intSecondsValue("overall_expiry_sec") ?: return null,
            allowImages = booleanValue("allow_images") ?: return null,
            allowVideos = booleanValue("allow_videos") ?: return null,
            allowFiles = booleanValue("allow_files") ?: return null,
            enforceTextAbsoluteExpiry = booleanValue("enforce_text_absolute_expiry") ?: return null,
            imageReadTimerSec = intSecondsValue("image_read_timer_sec") ?: return null,
            imageOverallExpirySec = intSecondsValue("image_overall_expiry_sec") ?: return null,
            enforceImageAbsoluteExpiry = booleanValue("enforce_image_absolute_expiry") ?: return null,
            videoReadTimerSec = intSecondsValue("video_read_timer_sec") ?: return null,
            videoOverallExpirySec = intSecondsValue("video_overall_expiry_sec") ?: return null,
            enforceVideoAbsoluteExpiry = booleanValue("enforce_video_absolute_expiry") ?: return null,
            fileReadTimerSec = intSecondsValue("file_read_timer_sec") ?: return null,
            fileOverallExpirySec = intSecondsValue("file_overall_expiry_sec") ?: return null,
            enforceFileAbsoluteExpiry = booleanValue("enforce_file_absolute_expiry") ?: return null,
            ownerUsername = ownerUsername
        )
    }

    private fun JSONObject.toDirectSession(): ChatSession? {
        if (!hasExactKeys(this, DIRECT_KEYS)) return null
        val chatId = stringValue("id")?.takeIf { it.matches(DIRECT_ID_REGEX) } ?: return null
        val peerUsername = stringValue("peer_username")?.takeIf { isSafeUsername(it) }
            ?: return null
        return ChatSession(
            id = chatId,
            name = peerUsername,
            isForum = false,
            lastMessage = null,
            unreadCount = 0,
            selfDestructTimerSec = 5
        )
    }

    private fun JSONObject.intSecondsValue(key: String): Int? {
        val value = if (!has(key) || isNull(key)) null else get(key)
        val integer = when (value) {
            is Int -> value.toLong()
            is Long -> value
            else -> return null
        }
        return integer.takeIf { it in 0L..MAX_RETENTION_SEC.toLong() }?.toInt()
    }

    private companion object {
        const val PROTOCOL_VERSION = 8
        // Protocol-v8 ciphertext is padded to 256-byte buckets. Base64url and
        // JSON framing add overhead, so this client keeps room below the relay cap.
        const val MAX_WEBSOCKET_FRAME_BYTES = 1 * 1024 * 1024
        const val MAX_CIPHERTEXT_BYTES = 1_048_848
        const val MAX_WRAPPED_KEY_BYTES = 4096
        const val MESSAGE_NONCE_BYTES = 12
        const val MESSAGE_SIGNATURE_BYTES = 64
        const val ACK_SIGNATURE_BYTES = 64
        const val STATE_SIGNATURE_BYTES = 64
        const val IDENTITY_PUBLIC_KEY_BYTES = 128
        const val MAX_USERNAME_CHARS = 80
        const val MAX_ROOM_NAME_CHARS = 36
        const val MAX_RETENTION_SEC = 86_400
        const val MAX_PRESENCE_ENTRIES = 128
        const val MAX_ROOM_CATALOG_ENTRIES = 1024
        const val MAX_DIRECT_CATALOG_ENTRIES = 128
        const val ROOM_CHANGE_BUFFER_CAPACITY =
            MAX_ROOM_CATALOG_ENTRIES + MAX_DIRECT_CATALOG_ENTRIES
        const val MAX_PINNED_IDENTITIES = 1024
        const val MAX_JOINED_CHAT_IDS = 512
        const val MAX_PENDING_OUTBOUND = 64
        const val MAX_PENDING_ACKNOWLEDGEMENTS = 64
        const val DIRECTORY_DIGEST_BYTES = 32
        const val IDENTITY_FINGERPRINT_BYTES = 64
        val PREKEY_ID_REGEX = Regex("^[A-Za-z0-9_-]{1,32}$")
        val DIRECT_ID_REGEX = Regex("^dm_[A-Za-z0-9_-]{1,125}$")
        val CANONICAL_BASE64_URL_REGEX = Regex("^[A-Za-z0-9_-]+$")
        val PRESENCE_KEYS = setOf(
            "username", "connected", "identity_public_b64", "identity_prekey_id", "directory_digest"
        )
        val ROOM_KEYS = setOf(
            "id", "name", "owner_username", "self_destruct_timer_sec", "overall_expiry_sec",
            "allow_images", "allow_videos", "allow_files", "enforce_text_absolute_expiry",
            "image_read_timer_sec", "image_overall_expiry_sec", "enforce_image_absolute_expiry",
            "video_read_timer_sec", "video_overall_expiry_sec", "enforce_video_absolute_expiry",
            "file_read_timer_sec", "file_overall_expiry_sec", "enforce_file_absolute_expiry"
        )
        val DIRECT_KEYS = setOf("id", "peer_username")

        fun isSafeIdentifier(value: String): Boolean =
            value.isNotEmpty() && value.length <= 128 &&
                value.all { character ->
                    character in 'A'..'Z' || character in 'a'..'z' || character in '0'..'9' ||
                        character == '_' || character == '-'
                }

        fun isSafeUsername(value: String): Boolean =
            value.length in 1..MAX_USERNAME_CHARS &&
                value.all { character ->
                    character in 'A'..'Z' || character in 'a'..'z' || character in '0'..'9' ||
                        character == '_' || character == '-'
                }

        fun encode(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

        fun decode(value: String): ByteArray = Base64.getUrlDecoder().decode(value)
    }
}

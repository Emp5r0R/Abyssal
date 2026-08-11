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
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asSharedFlow
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
private const val WS_TICKET_B64_LENGTH = 43
private val WS_TICKET_REGEX = Regex("^[A-Za-z0-9_-]{43}$")

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
    private val _wipeCommands = MutableSharedFlow<Unit>(extraBufferCapacity = 1)
    private val _incomingPayloads = Channel<IncomingTransportPayload>(
        capacity = 32,
        onUndeliveredElement = ::wipeIncomingPayload
    )
    private val _roomChanges = MutableSharedFlow<RoomChange>(extraBufferCapacity = 32)
    private val _presence = MutableStateFlow<List<UserPresence>>(emptyList())
    private val _serverStatus = MutableStateFlow(ServerStatus("DISCONNECTED", "No node", 0))
    private val connecting = AtomicBoolean(false)
    private val connectionGeneration = AtomicLong(0L)
    private val connectionLock = Any()
    private val identityPins = Collections.synchronizedMap(
        LinkedHashMap<String, String>(MAX_PINNED_IDENTITIES, 0.75f, true)
    )
    private val catalogLock = Any()
    private val roomCatalogIds = LinkedHashMap<String, String>()
    private val directCatalogIds = LinkedHashMap<String, String>()
    private val directCatalogPeers = LinkedHashMap<String, String>()

    @Volatile
    private var webSocket: WebSocket? = null
    @Volatile
    private var ticketCall: Call? = null
    private val joinedChatIds = Collections.synchronizedSet(LinkedHashSet<String>())

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
        synchronized(connectionLock) {
            connectionGeneration.incrementAndGet()
            connecting.set(false)
            pendingCall = ticketCall
            ticketCall = null
            socket = webSocket
            webSocket = null
        }
        pendingCall?.cancel()
        socket?.close(1000, "client disconnect")
        joinedChatIds.clear()
        identityPins.clear()
        synchronized(catalogLock) {
            roomCatalogIds.clear()
            directCatalogIds.clear()
            directCatalogPeers.clear()
        }
        while (true) {
            val payload = _incomingPayloads.tryReceive().getOrNull() ?: break
            wipeIncomingPayload(payload)
        }
        clearPresence()
        _serverStatus.value = ServerStatus("DISCONNECTED", "No node", 0)
    }

    override fun getServerStatus(): Flow<ServerStatus> = _serverStatus.asStateFlow()

    override fun getIncomingWipeCommands(): Flow<Unit> = _wipeCommands.asSharedFlow()

    override fun getIncomingPayloads(): Flow<IncomingTransportPayload> = _incomingPayloads.receiveAsFlow()

    override fun getRoomChanges(): Flow<RoomChange> = _roomChanges.asSharedFlow()

    override fun getPresence(): Flow<List<UserPresence>> = _presence.asStateFlow()

    override suspend fun joinChat(chatId: String) {
        if (!isSafeIdentifier(chatId)) return
        rememberJoinedChat(chatId)
        sendJoinFrame(chatId)
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

    override suspend fun createForum(session: ChatSession) {
        val frame = JSONObject()
            .put("type", "create_room")
            .put("room", session.toRoomJson())
            .toString()

        if (webSocket?.send(frame) != true) {
            _serverStatus.value = _serverStatus.value.copy(state = "DISCONNECTED")
        }
    }

    override suspend fun deleteForum(chatId: String) {
        val frame = JSONObject()
            .put("type", "delete_room")
            .put("chat_id", chatId)
            .toString()

        if (webSocket?.send(frame) != true) {
            _serverStatus.value = _serverStatus.value.copy(state = "DISCONNECTED")
        }
    }

    override suspend fun openDirect(peerUsername: String) {
        val frame = JSONObject()
            .put("type", "open_direct")
            .put("peer_username", peerUsername)
            .toString()

        if (webSocket?.send(frame) != true) {
            _serverStatus.value = _serverStatus.value.copy(state = "DISCONNECTED")
        }
    }

    override suspend fun sendEncryptedPayload(
        chatId: String,
        payload: EncryptedTransportPayload
    ): Boolean {
        return try {
            if (payload.version != PROTOCOL_VERSION || payload.stateSignature.size != STATE_SIGNATURE_BYTES) {
                return false
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
                _serverStatus.value = _serverStatus.value.copy(state = "DISCONNECTED")
                false
            } else {
                val accepted = webSocket?.send(frame) == true
                if (!accepted) {
                    _serverStatus.value = _serverStatus.value.copy(state = "DISCONNECTED")
                }
                accepted
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
    ): Boolean {
        if (state.stateSignature.size != STATE_SIGNATURE_BYTES ||
            state.identityPublicKey.size != IDENTITY_PUBLIC_KEY_BYTES ||
            ackSignature.size != ACK_SIGNATURE_BYTES
        ) return false
        val accepted = webSocket?.send(
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
        ) == true
        if (!accepted) _serverStatus.value = _serverStatus.value.copy(state = "DISCONNECTED")
        return accepted
    }

    override suspend fun syncIdentityState(state: IdentityStateSnapshot): Boolean {
        if (state.stateSignature.size != STATE_SIGNATURE_BYTES) return false
        val accepted = webSocket?.send(
            JSONObject()
                .put("type", "identity_state")
                .put("state_revision", state.revision.toLong())
                .put("identity_envelope_b64", encode(state.envelope))
                .put("identity_public_b64", encode(state.identityPublicKey))
                .put("prekey_id", state.prekeyId)
                .put("state_signature_b64", encode(state.stateSignature))
                .toString()
        ) == true
        if (!accepted) _serverStatus.value = _serverStatus.value.copy(state = "DISCONNECTED")
        return accepted
    }

    override suspend fun signalUserActivity(): Boolean {
        val accepted = webSocket?.send(JSONObject().put("type", "activity").toString()) == true
        if (!accepted) {
            _serverStatus.value = _serverStatus.value.copy(state = "DISCONNECTED")
        }
        return accepted
    }

    override suspend fun broadcastGlobalWipe() {
        val frame = JSONObject()
            .put("type", "global_wipe")
            .toString()

        if (webSocket?.send(frame) != true) {
            _serverStatus.value = _serverStatus.value.copy(state = "DISCONNECTED")
        }
    }

    private fun listener(nodeId: String, generation: Long): WebSocketListener {
        return object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                if (!isCurrentSocket(webSocket, generation)) {
                    webSocket.close(1000, "stale connection")
                    return
                }
                connecting.set(false)
                _serverStatus.value = ServerStatus("CONNECTED", nodeId, 0)
                joinedChatIds.toList().forEach { chatId ->
                    sendJoinFrame(chatId)
                }
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                if (!isCurrentSocket(webSocket, generation)) return
                if (disconnectForOversizedTextFrame(webSocket, text, nodeId)) return
                runCatching {
                    val json = JSONObject(text)
                    when (json.optString("type")) {
                        "GLOBAL_WIPE", "global_wipe" -> _wipeCommands.tryEmit(Unit)
                        "message" -> {
                            if (json.optInt("version") != PROTOCOL_VERSION) return
                            json.toIncomingPayload()?.let { payload ->
                                if (!_incomingPayloads.trySend(payload).isSuccess) wipeIncomingPayload(payload)
                            }
                        }
                        "presence" -> {
                            val users = json.optJSONArray("users") ?: return
                            val catalog = users.toPresenceCatalog() ?: return
                            if (!acceptPresenceCatalog(catalog)) {
                                wipePresence(catalog.entries)
                                closeCurrentSocket(webSocket, nodeId, "directory changed")
                                return
                            }
                            Unit
                        }
                        "rooms" -> {
                            val rooms = json.optJSONArray("rooms") ?: return
                            val sessions = rooms.toChatSessions(MAX_ROOM_CATALOG_ENTRIES) ?: return
                            installRoomCatalog(sessions)
                            sessions.forEach { session ->
                                rememberJoinedChat(session.id)
                                _roomChanges.tryEmit(RoomChange("upsert", session = session))
                            }
                        }
                        "room_created" -> {
                            json.optJSONObject("room")?.toChatSession()
                                ?.takeIf(::acceptDynamicRoom)
                                ?.let { session ->
                                    rememberJoinedChat(session.id)
                                    _roomChanges.tryEmit(RoomChange("upsert", session = session))
                                }
                        }
                        "room_deleted" -> {
                            val chatId = json.optString("chat_id")
                                .takeIf { it.startsWith("forum_") && isSafeIdentifier(it) } ?: return
                            joinedChatIds.remove(chatId)
                            synchronized(catalogLock) {
                                roomCatalogIds.remove(chatId.lowercase(Locale.ROOT))
                            }
                            _roomChanges.tryEmit(RoomChange("delete", chatId = chatId))
                        }
                        "directs" -> {
                            val directs = json.optJSONArray("directs") ?: return
                            val sessions = directs.toDirectSessions() ?: return
                            installDirectCatalog(sessions)
                            sessions.forEach { session ->
                                rememberJoinedChat(session.id)
                                _roomChanges.tryEmit(RoomChange("upsert", session = session))
                            }
                        }
                        "direct_opened" -> {
                            json.optJSONObject("direct")?.toDirectSession()
                                ?.takeIf(::acceptDynamicDirect)
                                ?.let { session ->
                                    rememberJoinedChat(session.id)
                                    _roomChanges.tryEmit(RoomChange("upsert", session = session))
                                }
                        }
                        else -> Unit
                    }
                }
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                if (!isCurrentSocket(webSocket, generation)) return
                connecting.set(false)
                this@RealChatTransport.webSocket = null
                clearPresence()
                _serverStatus.value = ServerStatus("DISCONNECTED", nodeId, 0)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                if (!isCurrentSocket(webSocket, generation)) return
                connecting.set(false)
                this@RealChatTransport.webSocket = null
                clearPresence()
                _serverStatus.value = ServerStatus("DISCONNECTED", nodeId, 0)
            }
        }
    }

    internal fun disconnectForOversizedTextFrame(
        socket: WebSocket,
        text: String,
        nodeId: String
    ): Boolean {
        if (!exceedsUtf8ByteLimit(text, MAX_WEBSOCKET_FRAME_BYTES)) return false
        connecting.set(false)
        if (!socket.close(1009, "message too big")) socket.cancel()
        if (webSocket === socket) webSocket = null
        clearPresence()
        _serverStatus.value = ServerStatus("DISCONNECTED", nodeId, 0)
        return true
    }

    private fun closeCurrentSocket(socket: WebSocket, nodeId: String, reason: String) {
        if (this.webSocket === socket) this.webSocket = null
        if (!socket.close(1008, reason)) socket.cancel()
        connecting.set(false)
        clearPresence()
        _serverStatus.value = ServerStatus("DISCONNECTED", nodeId, 0)
    }

    private fun sendJoinFrame(chatId: String) {
        val frame = JSONObject()
            .put("type", "join")
            .put("chat_id", chatId)
            .toString()

        webSocket?.send(frame)
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

    private fun installRoomCatalog(sessions: List<ChatSession>) {
        synchronized(catalogLock) {
            roomCatalogIds.clear()
            sessions.forEach { session ->
                roomCatalogIds[session.id.lowercase(Locale.ROOT)] = session.id
            }
        }
    }

    private fun installDirectCatalog(sessions: List<ChatSession>) {
        synchronized(catalogLock) {
            directCatalogIds.clear()
            directCatalogPeers.clear()
            sessions.forEach { session ->
                directCatalogIds[session.id.lowercase(Locale.ROOT)] = session.id
                directCatalogPeers[session.name.lowercase(Locale.ROOT)] = session.name
            }
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
            return true
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

    internal fun JSONObject.toIncomingPayload(): IncomingTransportPayload? {
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
                isPrekey = isPrekey
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
        const val PROTOCOL_VERSION = 7
        const val MAX_WEBSOCKET_FRAME_BYTES = 1 * 1024 * 1024
        const val MAX_CIPHERTEXT_BYTES = 1 * 1024 * 1024
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
        const val MAX_PINNED_IDENTITIES = 1024
        const val MAX_JOINED_CHAT_IDS = 512
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

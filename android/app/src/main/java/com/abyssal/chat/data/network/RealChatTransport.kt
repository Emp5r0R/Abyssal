package com.abyssal.chat.data.network

import com.abyssal.chat.domain.model.ChatSession
import com.abyssal.chat.domain.model.EncryptedTransportPayload
import com.abyssal.chat.domain.model.IncomingTransportPayload
import com.abyssal.chat.domain.model.IdentityStateSnapshot
import com.abyssal.chat.domain.model.RoomChange
import com.abyssal.chat.domain.model.ServerStatus
import com.abyssal.chat.domain.model.UserPresence
import com.abyssal.chat.domain.repository.IChatTransport
import com.abyssal.chat.domain.repository.INodeConfigService
import java.util.Collections
import java.util.Base64
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import org.json.JSONArray
import okhttp3.OkHttpClient
import okhttp3.Request
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

class RealChatTransport(
    private val nodeConfigService: INodeConfigService,
    private val client: OkHttpClient
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
    private val identityPins = Collections.synchronizedMap(mutableMapOf<String, String>())

    private var webSocket: WebSocket? = null
    private val joinedChatIds = Collections.synchronizedSet(mutableSetOf<String>())

    override fun connect() {
        if (webSocket != null || connecting.getAndSet(true)) return

        val session = nodeConfigService.getActiveSession()
        if (session == null) {
            _serverStatus.value = ServerStatus("DISCONNECTED", "No node", 0)
            connecting.set(false)
            return
        }

        _serverStatus.value = ServerStatus("CONNECTING", session.nodeId, 0)
        val request = Request.Builder()
            .url("${session.endpoint.wsBaseUrl}/v1/ws")
            .header("Sec-WebSocket-Protocol", "abyssal-v1, bearer.${session.token}")
            .build()

        webSocket = client.newWebSocket(request, listener(session.nodeId))
    }

    override fun disconnect() {
        connecting.set(false)
        webSocket?.close(1000, "client disconnect")
        webSocket = null
        joinedChatIds.clear()
        identityPins.clear()
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
        joinedChatIds.add(chatId)
        sendJoinFrame(chatId)
    }

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
        usedPrekeyId: String
    ): Boolean {
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
                .put("used_prekey_id", usedPrekeyId)
                .toString()
        ) == true
        if (!accepted) _serverStatus.value = _serverStatus.value.copy(state = "DISCONNECTED")
        return accepted
    }

    override suspend fun syncIdentityState(state: IdentityStateSnapshot): Boolean {
        val accepted = webSocket?.send(
            JSONObject()
                .put("type", "identity_state")
                .put("state_revision", state.revision.toLong())
                .put("identity_envelope_b64", encode(state.envelope))
                .put("identity_public_b64", encode(state.identityPublicKey))
                .put("prekey_id", state.prekeyId)
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

    private fun listener(nodeId: String): WebSocketListener {
        return object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                connecting.set(false)
                _serverStatus.value = ServerStatus("CONNECTED", nodeId, 0)
                joinedChatIds.toList().forEach { chatId ->
                    sendJoinFrame(chatId)
                }
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
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
                            if (users.length() > MAX_DIRECTORY_ENTRIES) return
                            var identityChanged = false
                            val nextPresence = (0 until users.length()).mapNotNull { index ->
                                var publicKey: ByteArray? = null
                                var ownershipTransferred = false
                                try {
                                    val user = users.optJSONObject(index) ?: return@mapNotNull null
                                    val username = user.optString("username").takeIf { isSafeUsername(it) }
                                        ?: return@mapNotNull null
                                    val publicKeyB64 = user.getString("identity_public_b64")
                                    val decodedPublicKey = decode(publicKeyB64)
                                    if (decodedPublicKey.size != IDENTITY_PUBLIC_KEY_BYTES) {
                                        return@mapNotNull null
                                    }
                                    publicKey = decodedPublicKey
                                    val prekeyId = user.optString("identity_prekey_id")
                                    if (!PREKEY_ID_REGEX.matches(prekeyId)) {
                                        return@mapNotNull null
                                    }
                                    val fingerprint = encode(decodedPublicKey.copyOfRange(0, 64))
                                    val pinKey = username.lowercase(Locale.ROOT)
                                    val pinned = identityPins[pinKey]
                                    if (pinned != null && pinned != fingerprint) {
                                        webSocket.close(1008, "identity changed")
                                        this@RealChatTransport.webSocket = null
                                        _serverStatus.value = ServerStatus("DISCONNECTED", nodeId, 0)
                                        identityChanged = true
                                        return@mapNotNull null
                                    }
                                    identityPins[pinKey] = fingerprint
                                    val directoryDigest = user.optString("directory_digest")
                                    if (!DIRECTORY_DIGEST_REGEX.matches(directoryDigest)) {
                                        return@mapNotNull null
                                    }
                                    val presence = UserPresence(
                                        username = username,
                                        connected = user.optBoolean("connected", false),
                                        publicKey = decodedPublicKey,
                                        prekeyId = prekeyId,
                                        directoryDigest = directoryDigest
                                    )
                                    ownershipTransferred = true
                                    presence
                                } catch (_: Exception) {
                                    null
                                } finally {
                                    if (!ownershipTransferred) publicKey?.fill(0)
                                }
                            }
                            if (identityChanged) {
                                wipePresence(nextPresence)
                                _serverStatus.value = ServerStatus("DISCONNECTED", nodeId, 0)
                                return
                            }
                            if (nextPresence.map { user -> user.directoryDigest }.distinct().size > 1) {
                                wipePresence(nextPresence)
                                webSocket.close(1008, "directory changed")
                                this@RealChatTransport.webSocket = null
                                _serverStatus.value = ServerStatus("DISCONNECTED", nodeId, 0)
                                return
                            }
                            val previousPresence = _presence.value
                            _presence.value = nextPresence
                            wipePresence(previousPresence)
                        }
                        "rooms" -> {
                            val rooms = json.optJSONArray("rooms") ?: JSONArray()
                            if (rooms.length() > MAX_DIRECTORY_ENTRIES) return
                            (0 until rooms.length()).forEach { index ->
                                rooms.optJSONObject(index)?.toChatSession()?.let { session ->
                                    joinedChatIds.add(session.id)
                                    _roomChanges.tryEmit(RoomChange("upsert", session = session))
                                }
                            }
                        }
                        "room_created" -> {
                            json.optJSONObject("room")?.toChatSession()?.let { session ->
                                joinedChatIds.add(session.id)
                                _roomChanges.tryEmit(RoomChange("upsert", session = session))
                            }
                        }
                        "room_deleted" -> {
                            val chatId = json.optString("chat_id").takeIf { it.isNotBlank() } ?: return
                            joinedChatIds.remove(chatId)
                            _roomChanges.tryEmit(RoomChange("delete", chatId = chatId))
                        }
                        "directs" -> {
                            val directs = json.optJSONArray("directs") ?: JSONArray()
                            if (directs.length() > MAX_DIRECTORY_ENTRIES) return
                            (0 until directs.length()).forEach { index ->
                                directs.optJSONObject(index)?.toDirectSession()?.let { session ->
                                    joinedChatIds.add(session.id)
                                    _roomChanges.tryEmit(RoomChange("upsert", session = session))
                                }
                            }
                        }
                        "direct_opened" -> {
                            json.optJSONObject("direct")?.toDirectSession()?.let { session ->
                                joinedChatIds.add(session.id)
                                _roomChanges.tryEmit(RoomChange("upsert", session = session))
                            }
                        }
                        else -> Unit
                    }
                }
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                connecting.set(false)
                this@RealChatTransport.webSocket = null
                clearPresence()
                _serverStatus.value = ServerStatus("DISCONNECTED", nodeId, 0)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
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

    private fun wipePresence(presence: List<UserPresence>) {
        presence.forEach { it.publicKey.fill(0) }
    }

    private fun JSONObject.toIncomingPayload(): IncomingTransportPayload? {
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
                decodedIdentityPublicKey.size != IDENTITY_PUBLIC_KEY_BYTES
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
        val chatId = optString("id").takeIf { it.startsWith("forum_") && isSafeIdentifier(it) } ?: return null
        val name = optString("name", chatId.removePrefix("forum_")
            .takeIf { it.isNotBlank() } ?: chatId)
            .takeIf { it.isNotBlank() && it.length <= MAX_ROOM_NAME_CHARS }
            ?: return null
        return ChatSession(
            id = chatId,
            name = name,
            isForum = true,
            lastMessage = null,
            unreadCount = 0,
            selfDestructTimerSec = optInt("self_destruct_timer_sec", 5).coerceIn(0, 86_400),
            overallExpirySec = optInt("overall_expiry_sec", 0).coerceIn(0, MAX_RETENTION_SEC),
            allowImages = optBoolean("allow_images", true),
            allowVideos = optBoolean("allow_videos", true),
            allowFiles = optBoolean("allow_files", true),
            enforceTextAbsoluteExpiry = optBoolean("enforce_text_absolute_expiry", false),
            imageReadTimerSec = optInt("image_read_timer_sec", 5).coerceIn(0, 86_400),
            imageOverallExpirySec = optInt("image_overall_expiry_sec", 0).coerceIn(0, MAX_RETENTION_SEC),
            enforceImageAbsoluteExpiry = optBoolean("enforce_image_absolute_expiry", false),
            videoReadTimerSec = optInt("video_read_timer_sec", 5).coerceIn(0, 86_400),
            videoOverallExpirySec = optInt("video_overall_expiry_sec", 0).coerceIn(0, MAX_RETENTION_SEC),
            enforceVideoAbsoluteExpiry = optBoolean("enforce_video_absolute_expiry", false),
            fileReadTimerSec = optInt("file_read_timer_sec", 5).coerceIn(0, 86_400),
            fileOverallExpirySec = optInt("file_overall_expiry_sec", 0).coerceIn(0, MAX_RETENTION_SEC),
            enforceFileAbsoluteExpiry = optBoolean("enforce_file_absolute_expiry", false),
            ownerUsername = optString("owner_username").takeIf { it.isNotBlank() }
        )
    }

    private fun JSONObject.toDirectSession(): ChatSession? {
        val chatId = optString("id").takeIf { it.matches(DIRECT_ID_REGEX) } ?: return null
        val peerUsername = optString("peer_username")
            .trim()
            .takeIf { isSafeUsername(it) }
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

    private companion object {
        const val PROTOCOL_VERSION = 6
        const val MAX_WEBSOCKET_FRAME_BYTES = 1 * 1024 * 1024
        const val MAX_CIPHERTEXT_BYTES = 1 * 1024 * 1024
        const val MAX_WRAPPED_KEY_BYTES = 4096
        const val MESSAGE_NONCE_BYTES = 12
        const val MESSAGE_SIGNATURE_BYTES = 64
        const val IDENTITY_PUBLIC_KEY_BYTES = 128
        const val MAX_USERNAME_CHARS = 80
        const val MAX_ROOM_NAME_CHARS = 128
        const val MAX_RETENTION_SEC = 86_400
        // The relay's room quota can reach 100 rooms per account. The inbound
        // WebSocket frame is capped at 1 MiB, so this bounds JSON work without
        // rejecting a valid catalog before the frame-size guard does.
        const val MAX_DIRECTORY_ENTRIES = 4096
        val PREKEY_ID_REGEX = Regex("^[A-Za-z0-9_-]{1,32}$")
        val DIRECTORY_DIGEST_REGEX = Regex("^[A-Za-z0-9_-]{43}$")
        val DIRECT_ID_REGEX = Regex("^dm_[A-Za-z0-9_-]{1,125}$")

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

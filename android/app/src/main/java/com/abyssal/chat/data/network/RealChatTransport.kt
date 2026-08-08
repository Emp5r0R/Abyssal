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
        _presence.value = emptyList()
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
        val frame = JSONObject()
            .put("type", "message")
            .put("chat_id", chatId)
            .put("version", payload.version)
            .put("message_id", payload.messageId)
            .put("nonce_b64", encode(payload.nonce))
            .put("ciphertext_b64", encode(payload.ciphertext))
            .put("signature_b64", encode(payload.signature))
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
                    )
                }
            })
            .toString()

        val accepted = webSocket?.send(frame) == true
        if (!accepted) {
            _serverStatus.value = _serverStatus.value.copy(state = "DISCONNECTED")
        }
        payload.nonce.fill(0)
        payload.ciphertext.fill(0)
        payload.signature.fill(0)
        payload.identityEnvelope.fill(0)
        payload.identityPublicKey.fill(0)
        payload.envelopes.forEach { it.wrappedKey.fill(0) }
        return accepted
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
                runCatching {
                    val json = JSONObject(text)
                    when (json.optString("type")) {
                        "GLOBAL_WIPE", "global_wipe" -> _wipeCommands.tryEmit(Unit)
                        "message" -> {
                            if (json.optInt("version") != PROTOCOL_VERSION) return
                            val chatId = json.optString("chat_id").takeIf { it.isNotBlank() } ?: return
                            val messageId = json.optString("message_id").takeIf { it.isNotBlank() } ?: return
                            val senderUsername = json.optString("sender_username").takeIf { it.isNotBlank() } ?: return
                            val payload = IncomingTransportPayload(
                                chatId = chatId,
                                messageId = messageId,
                                nonce = decode(json.getString("nonce_b64")),
                                ciphertext = decode(json.getString("ciphertext_b64")),
                                signature = decode(json.getString("signature_b64")),
                                wrappedKey = decode(json.getString("wrapped_key_b64")),
                                senderUsername = senderUsername,
                                senderPublicKey = decode(json.getString("sender_public_key_b64")),
                                prekeyId = json.optString("prekey_id"),
                                isPrekey = json.optBoolean("is_prekey", false)
                            )
                            if (!_incomingPayloads.trySend(payload).isSuccess) wipeIncomingPayload(payload)
                            Unit
                        }
                        "presence" -> {
                            val users = json.optJSONArray("users") ?: return
                            val nextPresence = (0 until users.length()).mapNotNull { index ->
                                val user = users.optJSONObject(index) ?: return@mapNotNull null
                                val username = user.optString("username").takeIf { it.isNotBlank() }
                                    ?: return@mapNotNull null
                                val publicKeyB64 = user.getString("identity_public_b64")
                                val publicKey = decode(publicKeyB64)
                                if (publicKey.size != IDENTITY_PUBLIC_KEY_BYTES) {
                                    publicKey.fill(0)
                                    return@mapNotNull null
                                }
                                val prekeyId = user.optString("identity_prekey_id")
                                if (!PREKEY_ID_REGEX.matches(prekeyId)) {
                                    publicKey.fill(0)
                                    return@mapNotNull null
                                }
                                val fingerprint = encode(publicKey.copyOfRange(0, 64))
                                val pinKey = username.lowercase()
                                val pinned = identityPins[pinKey]
                                if (pinned != null && pinned != fingerprint) {
                                    publicKey.fill(0)
                                    webSocket.close(1008, "identity changed")
                                    this@RealChatTransport.webSocket = null
                                    _serverStatus.value = ServerStatus("DISCONNECTED", nodeId, 0)
                                    return
                                }
                                identityPins[pinKey] = fingerprint
                                val directoryDigest = user.optString("directory_digest")
                                if (!DIRECTORY_DIGEST_REGEX.matches(directoryDigest)) {
                                    publicKey.fill(0)
                                    return@mapNotNull null
                                }
                                UserPresence(
                                    username = username,
                                    connected = user.optBoolean("connected", false),
                                    publicKey = publicKey,
                                    prekeyId = prekeyId,
                                    directoryDigest = directoryDigest
                                )
                            }
                            if (nextPresence.map { user -> user.directoryDigest }.distinct().size > 1) {
                                webSocket.close(1008, "directory changed")
                                this@RealChatTransport.webSocket = null
                                _serverStatus.value = ServerStatus("DISCONNECTED", nodeId, 0)
                                return
                            }
                            _presence.value = nextPresence
                        }
                        "rooms" -> {
                            val rooms = json.optJSONArray("rooms") ?: JSONArray()
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
                _serverStatus.value = ServerStatus("DISCONNECTED", nodeId, 0)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                connecting.set(false)
                this@RealChatTransport.webSocket = null
                _serverStatus.value = ServerStatus("DISCONNECTED", nodeId, 0)
            }
        }
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
        val chatId = optString("id").takeIf { it.isNotBlank() } ?: return null
        return ChatSession(
            id = chatId,
            name = optString("name", chatId.removePrefix("forum_")),
            isForum = true,
            lastMessage = null,
            unreadCount = 0,
            selfDestructTimerSec = optInt("self_destruct_timer_sec", 5).coerceIn(0, 86_400),
            overallExpirySec = optInt("overall_expiry_sec", 0).coerceAtLeast(0),
            allowImages = optBoolean("allow_images", true),
            allowVideos = optBoolean("allow_videos", true),
            allowFiles = optBoolean("allow_files", true),
            enforceTextAbsoluteExpiry = optBoolean("enforce_text_absolute_expiry", false),
            imageReadTimerSec = optInt("image_read_timer_sec", 5).coerceIn(0, 86_400),
            imageOverallExpirySec = optInt("image_overall_expiry_sec", 0).coerceAtLeast(0),
            enforceImageAbsoluteExpiry = optBoolean("enforce_image_absolute_expiry", false),
            videoReadTimerSec = optInt("video_read_timer_sec", 5).coerceIn(0, 86_400),
            videoOverallExpirySec = optInt("video_overall_expiry_sec", 0).coerceAtLeast(0),
            enforceVideoAbsoluteExpiry = optBoolean("enforce_video_absolute_expiry", false),
            fileReadTimerSec = optInt("file_read_timer_sec", 5).coerceIn(0, 86_400),
            fileOverallExpirySec = optInt("file_overall_expiry_sec", 0).coerceAtLeast(0),
            enforceFileAbsoluteExpiry = optBoolean("enforce_file_absolute_expiry", false),
            ownerUsername = optString("owner_username").takeIf { it.isNotBlank() }
        )
    }

    private fun JSONObject.toDirectSession(): ChatSession? {
        val chatId = optString("id").takeIf { it.matches(DIRECT_ID_REGEX) } ?: return null
        val peerUsername = optString("peer_username")
            .trim()
            .takeIf { it.isNotEmpty() && it.length <= 80 }
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
        const val PROTOCOL_VERSION = 5
        const val IDENTITY_PUBLIC_KEY_BYTES = 128
        val PREKEY_ID_REGEX = Regex("^[A-Za-z0-9_-]{1,32}$")
        val DIRECTORY_DIGEST_REGEX = Regex("^[A-Za-z0-9_-]{43}$")
        val DIRECT_ID_REGEX = Regex("^dm_[A-Za-z0-9_-]{1,125}$")

        fun encode(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

        fun decode(value: String): ByteArray = Base64.getUrlDecoder().decode(value)
    }
}

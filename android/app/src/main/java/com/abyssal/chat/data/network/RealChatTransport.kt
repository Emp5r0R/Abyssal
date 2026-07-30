package com.abyssal.chat.data.network

import android.util.Base64
import com.abyssal.chat.domain.model.ChatSession
import com.abyssal.chat.domain.model.IncomingTransportPayload
import com.abyssal.chat.domain.model.RoomChange
import com.abyssal.chat.domain.model.ServerStatus
import com.abyssal.chat.domain.model.UserPresence
import com.abyssal.chat.domain.repository.IChatTransport
import com.abyssal.chat.domain.repository.INodeConfigService
import java.util.Collections
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
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
    private val _incomingPayloads = MutableSharedFlow<IncomingTransportPayload>(extraBufferCapacity = 32)
    private val _roomChanges = MutableSharedFlow<RoomChange>(extraBufferCapacity = 32)
    private val _presence = MutableStateFlow<List<UserPresence>>(emptyList())
    private val _serverStatus = MutableStateFlow(ServerStatus("DISCONNECTED", "No node", 0))
    private val connecting = AtomicBoolean(false)

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
        _presence.value = emptyList()
        _serverStatus.value = ServerStatus("DISCONNECTED", "No node", 0)
    }

    override fun getServerStatus(): Flow<ServerStatus> = _serverStatus.asStateFlow()

    override fun getIncomingWipeCommands(): Flow<Unit> = _wipeCommands.asSharedFlow()

    override fun getIncomingPayloads(): Flow<IncomingTransportPayload> = _incomingPayloads.asSharedFlow()

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

    override suspend fun sendEncryptedPayload(chatId: String, payload: ByteArray): Boolean {
        val encodedPayload = Base64.encodeToString(payload, Base64.NO_WRAP)
        val frame = JSONObject()
            .put("type", "message")
            .put("chat_id", chatId)
            .put("payload_b64", encodedPayload)
            .toString()

        val accepted = webSocket?.send(frame) == true
        if (!accepted) {
            _serverStatus.value = _serverStatus.value.copy(state = "DISCONNECTED")
        }
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
                            val chatId = json.optString("chat_id").takeIf { it.isNotBlank() } ?: return
                            val payload = Base64.decode(json.optString("payload_b64"), Base64.NO_WRAP)
                            val senderUsername = json.optString("sender_username").takeIf { it.isNotBlank() }
                            _incomingPayloads.tryEmit(IncomingTransportPayload(chatId, payload, senderUsername))
                        }
                        "presence" -> {
                            val users = json.optJSONArray("users") ?: return
                            _presence.value = (0 until users.length()).mapNotNull { index ->
                                val user = users.optJSONObject(index) ?: return@mapNotNull null
                                val username = user.optString("username").takeIf { it.isNotBlank() }
                                    ?: return@mapNotNull null
                                UserPresence(
                                    username = username,
                                    connected = user.optBoolean("connected", false)
                                )
                            }
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
            selfDestructTimerSec = optInt("self_destruct_timer_sec", 5).coerceAtLeast(1),
            overallExpirySec = optInt("overall_expiry_sec", 0).coerceAtLeast(0),
            allowImages = optBoolean("allow_images", true),
            allowVideos = optBoolean("allow_videos", true),
            allowFiles = optBoolean("allow_files", true),
            enforceTextAbsoluteExpiry = optBoolean("enforce_text_absolute_expiry", false),
            imageReadTimerSec = optInt("image_read_timer_sec", 5).coerceAtLeast(1),
            imageOverallExpirySec = optInt("image_overall_expiry_sec", 0).coerceAtLeast(0),
            enforceImageAbsoluteExpiry = optBoolean("enforce_image_absolute_expiry", false),
            videoReadTimerSec = optInt("video_read_timer_sec", 5).coerceAtLeast(1),
            videoOverallExpirySec = optInt("video_overall_expiry_sec", 0).coerceAtLeast(0),
            enforceVideoAbsoluteExpiry = optBoolean("enforce_video_absolute_expiry", false),
            fileReadTimerSec = optInt("file_read_timer_sec", 5).coerceAtLeast(1),
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
        val DIRECT_ID_REGEX = Regex("^dm_[A-Za-z0-9_-]{1,125}$")
    }
}

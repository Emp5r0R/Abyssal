package com.abyssal.chat.data.network

import android.util.Base64
import com.abyssal.chat.domain.model.IncomingTransportPayload
import com.abyssal.chat.domain.model.ServerStatus
import com.abyssal.chat.domain.repository.IChatTransport
import com.abyssal.chat.domain.repository.INodeConfigService
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
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
    private val _serverStatus = MutableStateFlow(ServerStatus("DISCONNECTED", "No node", 0))
    private val connecting = AtomicBoolean(false)

    private var webSocket: WebSocket? = null

    override fun connect() {
        if (webSocket != null || connecting.getAndSet(true)) return

        val session = nodeConfigService.getActiveSession()
        if (session == null) {
            _serverStatus.value = ServerStatus("DISCONNECTED", "No node", 0)
            connecting.set(false)
            return
        }

        _serverStatus.value = ServerStatus("CONNECTING", session.nodeId, 0)
        val token = URLEncoder.encode(session.token, StandardCharsets.UTF_8.name())
        val request = Request.Builder()
            .url("${session.endpoint.wsBaseUrl}/v1/ws?token=$token")
            .build()

        webSocket = client.newWebSocket(request, listener(session.nodeId))
    }

    override fun disconnect() {
        connecting.set(false)
        webSocket?.close(1000, "client disconnect")
        webSocket = null
        _serverStatus.value = ServerStatus("DISCONNECTED", "No node", 0)
    }

    override fun getServerStatus(): Flow<ServerStatus> = _serverStatus.asStateFlow()

    override fun getIncomingWipeCommands(): Flow<Unit> = _wipeCommands.asSharedFlow()

    override fun getIncomingPayloads(): Flow<IncomingTransportPayload> = _incomingPayloads.asSharedFlow()

    override suspend fun joinChat(chatId: String) {
        val frame = JSONObject()
            .put("type", "join")
            .put("chat_id", chatId)
            .toString()

        webSocket?.send(frame)
    }

    override suspend fun sendEncryptedPayload(chatId: String, payload: ByteArray) {
        val encodedPayload = Base64.encodeToString(payload, Base64.NO_WRAP)
        val frame = JSONObject()
            .put("type", "message")
            .put("chat_id", chatId)
            .put("payload_b64", encodedPayload)
            .toString()

        if (webSocket?.send(frame) != true) {
            _serverStatus.value = _serverStatus.value.copy(state = "DISCONNECTED")
        }
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
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                runCatching {
                    val json = JSONObject(text)
                    when (json.optString("type")) {
                        "GLOBAL_WIPE", "global_wipe" -> _wipeCommands.tryEmit(Unit)
                        "message" -> {
                            val chatId = json.optString("chat_id").takeIf { it.isNotBlank() } ?: return
                            val payload = Base64.decode(json.optString("payload_b64"), Base64.NO_WRAP)
                            _incomingPayloads.tryEmit(IncomingTransportPayload(chatId, payload))
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
}

package com.abyssal.chat.data.network.v11

import com.abyssal.chat.domain.model.TransportKeys
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString
import uniffi.abyssal_core.WsClientConnection

/** The v11 WebSocket record layer for one connection. */
internal interface WsRecordLayer : AutoCloseable {
    fun clientHello(): ByteArray
    fun openServerHello(record: ByteArray)
    fun ready(): Boolean
    fun seal(plaintext: ByteArray): ByteArray
    fun open(record: ByteArray): ByteArray
}

internal class UniffiWsRecordLayer(keys: TransportKeys, ticket: String) : WsRecordLayer {
    private val connection: WsClientConnection = ticket.toByteArray(StandardCharsets.US_ASCII).let { bytes ->
        try {
            WsClientConnection(keys.nodePublicKey, keys.sessionId, keys.transportRoot, bytes)
        } finally {
            bytes.fill(0)
        }
    }

    override fun clientHello() = connection.clientHelloBytes()
    override fun openServerHello(record: ByteArray) = connection.openServerHello(record)
    override fun ready() = connection.ready()
    override fun seal(plaintext: ByteArray) = connection.sealFrame(plaintext)
    override fun open(record: ByteArray) = connection.openFrame(record)
    override fun close() = connection.close()
}

/** The upgrade request: the ticket travels inside the sealed ClientHello, never in a header. */
internal fun sealedWebSocketRequest(wsBaseUrl: String): Request = Request.Builder()
    .url("$wsBaseUrl${SealedRecordHttp.WEBSOCKET_PATH}")
    .header("Sec-WebSocket-Protocol", SealedRecordHttp.WEBSOCKET_PROTOCOL)
    .build()

/**
 * An OkHttp WebSocket whose text frames travel as v11 AEAD records with a
 * monotonic counter, so replayed, reordered or altered frames fail closed.
 *
 * Frames sent before the relay's ServerHello are queued in order, as OkHttp
 * itself queues frames sent before a socket opens, and are sealed once the
 * handshake completes. Sealing and sending are one step under a lock so the
 * record counter always matches the order frames reach the wire.
 */
internal class SealedWebSocket(
    private val raw: WebSocket,
    private val layer: WsRecordLayer
) : WebSocket {
    private val lock = Any()
    private val queued = ArrayDeque<String>()
    private var queuedBytes = 0L
    private var ready = false
    private var closed = false

    val isReady: Boolean get() = synchronized(lock) { ready }

    override fun send(text: String): Boolean = synchronized(lock) {
        if (closed) return false
        if (!ready) {
            val size = text.toByteArray(StandardCharsets.UTF_8).size.toLong()
            if (queuedBytes + size > MAX_QUEUED_BYTES) return false
            queued.addLast(text)
            queuedBytes += size
            return true
        }
        sealAndSendLocked(text)
    }

    /** Only sealed text frames exist on a v11 socket. */
    override fun send(bytes: ByteString): Boolean = false

    /** Completes the handshake and flushes the frames queued before it, in order. */
    fun markReady(): Boolean = synchronized(lock) {
        if (closed) return false
        ready = true
        while (queued.isNotEmpty()) {
            if (!sealAndSendLocked(queued.removeFirst())) return false
        }
        queuedBytes = 0
        true
    }

    private fun sealAndSendLocked(text: String): Boolean {
        val plaintext = text.toByteArray(StandardCharsets.UTF_8)
        val record = try {
            layer.seal(plaintext)
        } catch (_: Exception) {
            return false
        } finally {
            plaintext.fill(0)
        }
        return try {
            raw.send(record.toByteString())
        } finally {
            record.fill(0)
        }
    }

    override fun close(code: Int, reason: String?): Boolean {
        stop()
        return raw.close(code, reason)
    }

    override fun cancel() {
        stop()
        raw.cancel()
    }

    override fun queueSize(): Long = raw.queueSize() + synchronized(lock) { queuedBytes }

    override fun request(): Request = raw.request()

    private fun stop() = synchronized(lock) {
        closed = true
        queued.clear()
        queuedBytes = 0
    }

    /** Releases the record layer once the socket has ended. */
    fun destroy() {
        stop()
        runCatching { layer.close() }
    }

    private companion object {
        /** OkHttp's own bound for frames queued on a socket. */
        const val MAX_QUEUED_BYTES = 16L * 1024L * 1024L
    }
}

/**
 * Adapts the transport's listener to a sealed socket: it sends the ClientHello
 * on open, reports the socket open only after the ServerHello authenticates,
 * and hands the listener opened text. [onUnauthenticated] runs for any frame
 * that does not authenticate, including a plaintext text frame.
 */
internal class SealedWebSocketListener(
    private val layer: WsRecordLayer,
    private val inner: WebSocketListener,
    private val onUnauthenticated: (SealedWebSocket) -> Unit
) : WebSocketListener() {
    private var sealed: SealedWebSocket? = null
    @Volatile
    private var openResponse: Response? = null

    /** The one sealed wrapper for [raw]; the transport keeps this as its socket. */
    @Synchronized
    fun wrap(raw: WebSocket): SealedWebSocket =
        sealed ?: SealedWebSocket(raw, layer).also { sealed = it }

    override fun onOpen(webSocket: WebSocket, response: Response) {
        wrap(webSocket)
        openResponse = response
        val hello = runCatching { layer.clientHello() }.getOrNull()
        val sent = try {
            hello != null && webSocket.send(hello.toByteString())
        } finally {
            hello?.fill(0)
        }
        if (!sent) webSocket.cancel()
    }

    override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
        val socket = wrap(webSocket)
        val record = bytes.toByteArray()
        val text: String?
        try {
            if (!socket.isReady) {
                val opened = runCatching {
                    layer.openServerHello(record)
                    layer.ready()
                }.getOrDefault(false)
                if (!opened) {
                    onUnauthenticated(socket)
                } else if (!socket.markReady()) {
                    webSocket.cancel()
                } else {
                    openResponse?.let { inner.onOpen(socket, it) } ?: webSocket.cancel()
                }
                return
            }
            text = openText(record)
        } finally {
            record.fill(0)
        }
        if (text == null) onUnauthenticated(socket) else inner.onMessage(socket, text)
    }

    override fun onMessage(webSocket: WebSocket, text: String) {
        onUnauthenticated(wrap(webSocket))
    }

    override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
        inner.onClosing(wrap(webSocket), code, reason)
    }

    override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
        val socket = wrap(webSocket)
        try {
            inner.onClosed(socket, code, reason)
        } finally {
            socket.destroy()
        }
    }

    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
        val socket = wrap(webSocket)
        try {
            inner.onFailure(socket, t, response)
        } finally {
            socket.destroy()
        }
    }

    private fun openText(record: ByteArray): String? {
        val plaintext = runCatching { layer.open(record) }.getOrNull() ?: return null
        return try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(plaintext))
                .toString()
        } catch (_: Exception) {
            null
        } finally {
            plaintext.fill(0)
        }
    }
}

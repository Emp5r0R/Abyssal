package com.abyssal.chat.data.network.v11

import com.abyssal.chat.data.network.awaitHttpResponse
import com.abyssal.chat.domain.model.TransportKeys
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.Response
import okio.BufferedSink
import uniffi.abyssal_core.AttachmentClientExchange
import uniffi.abyssal_core.AttachmentTransportFrame
import uniffi.abyssal_core.AttachmentTransportResult
import uniffi.abyssal_core.AttachmentUploadInput

/**
 * Attachment transport v3: every operation is one sealed action record to a
 * fixed URL, so the chat, message, attachment ID, sizes and options are not
 * visible outside the relay. The end-to-end encrypted bytes travel in
 * fixed-size sealed frames, padded to a power-of-two bucket.
 */
internal object AttachmentFraming {
    const val ACTION_RECORD_BYTES = 4_170
    const val STREAM_PAYLOAD_BYTES = 256 * 1024
    const val STREAM_FRAME_BYTES = 262_184
}

internal interface AttachmentExchange : AutoCloseable {
    fun requestBytes(): ByteArray
    fun uploadDataFrameCount(): Int
    fun uploadBucketFrameCount(): Int
    fun sealDataFrame(payload: ByteArray): ByteArray
    fun sealPaddingFrame(): ByteArray
    fun sealEndFrame(): ByteArray
    fun openResponse(reply: ByteArray): AttachmentTransportResult
    fun openStreamFrame(frame: ByteArray): AttachmentTransportFrame
    fun streamComplete(): Boolean
}

internal interface AttachmentExchanges {
    fun beginUpload(keys: TransportKeys, input: AttachmentUploadInput): AttachmentExchange
    fun beginDownload(keys: TransportKeys, attachmentId: ByteArray): AttachmentExchange
    fun completeDownload(keys: TransportKeys, attachmentId: ByteArray, claimId: ByteArray): AttachmentExchange
    fun releaseDownload(keys: TransportKeys, attachmentId: ByteArray, claimId: ByteArray): AttachmentExchange
    fun deleteAttachment(keys: TransportKeys, attachmentId: ByteArray): AttachmentExchange
}

internal object UniffiAttachmentExchanges : AttachmentExchanges {
    private class Wrapped(private val exchange: AttachmentClientExchange) : AttachmentExchange {
        override fun requestBytes() = exchange.requestBytes()
        override fun uploadDataFrameCount() = exchange.uploadDataFrameCount().toInt()
        override fun uploadBucketFrameCount() = exchange.uploadBucketFrameCount().toInt()
        override fun sealDataFrame(payload: ByteArray) = exchange.sealDataFrame(payload)
        override fun sealPaddingFrame() = exchange.sealPaddingFrame()
        override fun sealEndFrame() = exchange.sealEndFrame()
        override fun openResponse(reply: ByteArray) = exchange.openResponse(reply)
        override fun openStreamFrame(frame: ByteArray) = exchange.openStreamFrame(frame)
        override fun streamComplete() = exchange.streamComplete()
        override fun close() = exchange.close()
    }

    override fun beginUpload(keys: TransportKeys, input: AttachmentUploadInput): AttachmentExchange =
        Wrapped(AttachmentClientExchange.beginUpload(keys.nodePublicKey, keys.sessionId, keys.transportRoot, input))

    override fun beginDownload(keys: TransportKeys, attachmentId: ByteArray): AttachmentExchange =
        Wrapped(AttachmentClientExchange.beginDownload(keys.nodePublicKey, keys.sessionId, keys.transportRoot, attachmentId))

    override fun completeDownload(keys: TransportKeys, attachmentId: ByteArray, claimId: ByteArray): AttachmentExchange =
        Wrapped(
            AttachmentClientExchange.completeDownload(
                keys.nodePublicKey, keys.sessionId, keys.transportRoot, attachmentId, claimId
            )
        )

    override fun releaseDownload(keys: TransportKeys, attachmentId: ByteArray, claimId: ByteArray): AttachmentExchange =
        Wrapped(
            AttachmentClientExchange.releaseDownload(
                keys.nodePublicKey, keys.sessionId, keys.transportRoot, attachmentId, claimId
            )
        )

    override fun deleteAttachment(keys: TransportKeys, attachmentId: ByteArray): AttachmentExchange =
        Wrapped(AttachmentClientExchange.deleteAttachment(keys.nodePublicKey, keys.sessionId, keys.transportRoot, attachmentId))
}

/** A canonical UUID string as the relay's 16 bytes, or null when it is not one. */
internal fun uuidBytes(id: String): ByteArray? {
    val uuid = runCatching { UUID.fromString(id) }.getOrNull() ?: return null
    if (uuid.toString() != id.lowercase()) return null
    return ByteBuffer.allocate(16).putLong(uuid.mostSignificantBits).putLong(uuid.leastSignificantBits).array()
}

internal fun uuidString(bytes: ByteArray): String? {
    if (bytes.size != 16) return null
    val buffer = ByteBuffer.wrap(bytes)
    return UUID(buffer.long, buffer.long).toString()
}

/** End-to-end encrypted attachment bytes that stream identically every time. */
internal interface ReplayableCiphertext {
    val length: Long

    /** Streams the ciphertext in order; [consumer] must not keep the arrays. */
    fun stream(consumer: (ByteArray) -> Unit)
}

internal class AttachmentUploadRequest(
    val chatId: String,
    val messageId: String,
    val mediaType: String,
    val cipherVersion: Int,
    val oneTime: Boolean,
    val deleteAfterDownload: Boolean,
    val ttlSec: Int
)

internal class AttachmentTransportClient(
    private val callFactory: Call.Factory,
    private val exchanges: AttachmentExchanges = UniffiAttachmentExchanges
) {
    /**
     * Uploads [ciphertext] and returns the relay's attachment ID, or null when
     * the relay refused it. Streams the ciphertext twice: once to declare its
     * SHA-256 in the sealed action record, and once into the sealed frames.
     */
    suspend fun upload(
        apiBaseUrl: String,
        keys: TransportKeys,
        request: AttachmentUploadRequest,
        ciphertext: ReplayableCiphertext,
        onProgress: (sentBytes: Long, totalBytes: Long) -> Unit
    ): String? {
        val digest = MessageDigest.getInstance("SHA-256").let { hash ->
            ciphertext.stream(hash::update)
            hash.digest()
        }
        val exchange = try {
            exchanges.beginUpload(
                keys,
                AttachmentUploadInput(
                    chatId = request.chatId,
                    messageId = request.messageId,
                    mediaType = request.mediaType,
                    cipherVersion = request.cipherVersion.toUByte(),
                    ciphertextLen = ciphertext.length.toULong(),
                    ciphertextSha256 = digest,
                    oneTime = request.oneTime,
                    // A one-time attachment is always deleted after its download.
                    deleteAfterDownload = request.deleteAfterDownload || request.oneTime,
                    requestedTtlSec = request.ttlSec.coerceAtLeast(0).toUInt()
                )
            )
        } finally {
            digest.fill(0)
        }
        exchange.use {
            val body = SealedUploadBody(exchange, ciphertext, onProgress)
            val call = callFactory.newCall(
                Request.Builder()
                    .url("$apiBaseUrl${SealedRecordHttp.ATTACHMENT_PATH}")
                    .header("Accept", "application/octet-stream")
                    .header("Cache-Control", "no-store")
                    .post(body)
                    .build()
            )
            return try {
                awaitHttpResponse(call) { response ->
                    val reply = SealedRecordHttp.readReply(response, AttachmentFraming.ACTION_RECORD_BYTES.toLong())
                        ?: return@awaitHttpResponse null
                    try {
                        val result = runCatching { exchange.openResponse(reply) }.getOrNull()
                        (result as? AttachmentTransportResult.UploadAccepted)?.attachmentId?.let(::uuidString)
                    } finally {
                        reply.fill(0)
                    }
                }
            } finally {
                body.wipe()
            }
        }
    }

    /**
     * Sends one download request; on success [onClaim] receives any destructive
     * claim before a single payload is read, and [onPayload] each opened payload
     * in order (wiped after it returns). Returns true only when exactly
     * [expectedCiphertextBytes] arrived and the stream ended authentically.
     * Blocking: call it from the HTTP response consumer.
     */
    fun readDownload(
        response: Response,
        exchange: AttachmentExchange,
        expectedCiphertextBytes: Long,
        onClaim: (ByteArray) -> Unit,
        onPayload: (ByteArray) -> Unit
    ): Boolean {
        if (!response.isSuccessful) return false
        val input = response.body?.byteStream() ?: return false
        val head = ByteArray(AttachmentFraming.ACTION_RECORD_BYTES)
        try {
            readExactly(input, head)
            val accepted = runCatching { exchange.openResponse(head) }.getOrNull()
                as? AttachmentTransportResult.DownloadAccepted ?: return false
            accepted.claimId?.let(onClaim)
            accepted.ciphertextSha256.fill(0)
            if (accepted.ciphertextLen.toLong() != expectedCiphertextBytes) return false
        } finally {
            head.fill(0)
        }
        val frame = ByteArray(AttachmentFraming.STREAM_FRAME_BYTES)
        var received = 0L
        try {
            while (true) {
                readExactly(input, frame)
                when (val opened = exchange.openStreamFrame(frame)) {
                    is AttachmentTransportFrame.Data -> try {
                        received += opened.payload.size
                        if (received > expectedCiphertextBytes) return false
                        onPayload(opened.payload)
                    } finally {
                        opened.payload.fill(0)
                    }
                    AttachmentTransportFrame.Padding -> Unit
                    AttachmentTransportFrame.End -> break
                }
            }
        } finally {
            frame.fill(0)
        }
        return received == expectedCiphertextBytes && exchange.streamComplete() && input.read() < 0
    }

    /** Runs complete, release or delete; true only for an authenticated Success. */
    suspend fun action(apiBaseUrl: String, exchange: AttachmentExchange): Boolean = exchange.use {
        val record = exchange.requestBytes()
        try {
            val reply = SealedRecordHttp.post(
                callFactory,
                "$apiBaseUrl${SealedRecordHttp.ATTACHMENT_PATH}",
                record,
                AttachmentFraming.ACTION_RECORD_BYTES.toLong()
            ) ?: return false
            try {
                runCatching { exchange.openResponse(reply) }.getOrNull() == AttachmentTransportResult.Success
            } finally {
                reply.fill(0)
            }
        } finally {
            record.fill(0)
        }
    }

    /**
     * Sends an action from a callback thread without waiting for the reply;
     * the request and exchange are released when the call ends.
     */
    fun actionAsync(apiBaseUrl: String, exchange: AttachmentExchange) {
        val record = runCatching { exchange.requestBytes() }.getOrNull()
        val finished = AtomicBoolean(false)
        val finish = {
            if (finished.compareAndSet(false, true)) {
                record?.fill(0)
                runCatching { exchange.close() }
            }
        }
        if (record == null) {
            finish()
            return
        }
        runCatching {
            callFactory.newCall(SealedRecordHttp.request("$apiBaseUrl${SealedRecordHttp.ATTACHMENT_PATH}", record))
                .enqueue(object : Callback {
                    override fun onFailure(call: Call, e: IOException) = finish()

                    override fun onResponse(call: Call, response: Response) {
                        response.close()
                        finish()
                    }
                })
        }.onFailure { finish() }
    }

    fun beginDownload(keys: TransportKeys, attachmentId: ByteArray) = exchanges.beginDownload(keys, attachmentId)
    fun completeDownload(keys: TransportKeys, attachmentId: ByteArray, claimId: ByteArray) =
        exchanges.completeDownload(keys, attachmentId, claimId)
    fun releaseDownload(keys: TransportKeys, attachmentId: ByteArray, claimId: ByteArray) =
        exchanges.releaseDownload(keys, attachmentId, claimId)
    fun deleteAttachment(keys: TransportKeys, attachmentId: ByteArray) = exchanges.deleteAttachment(keys, attachmentId)

    /** The download request body: the sealed action record. The caller wipes it after the call. */
    fun downloadRequest(apiBaseUrl: String, record: ByteArray): Request =
        SealedRecordHttp.request("$apiBaseUrl${SealedRecordHttp.ATTACHMENT_PATH}", record)
}

/**
 * The upload body: the action record, the ciphertext re-cut into sealed data
 * frames, padding frames up to the bucket and the end frame. Streaming keeps
 * at most one payload of ciphertext in memory.
 */
private class SealedUploadBody(
    private val exchange: AttachmentExchange,
    private val ciphertext: ReplayableCiphertext,
    private val onProgress: (sentBytes: Long, totalBytes: Long) -> Unit
) : RequestBody() {
    private val record = exchange.requestBytes()
    private val bucketFrames = exchange.uploadBucketFrameCount()

    override fun contentType(): MediaType = SealedRecordHttp.OCTET_STREAM

    override fun contentLength(): Long =
        record.size.toLong() + (bucketFrames.toLong() + 1L) * AttachmentFraming.STREAM_FRAME_BYTES

    override fun isOneShot(): Boolean = true

    override fun writeTo(sink: BufferedSink) {
        val payload = ByteArray(AttachmentFraming.STREAM_PAYLOAD_BYTES)
        var filled = 0
        var dataFrames = 0
        var sent = 0L
        fun emit(bytes: ByteArray) {
            try {
                sink.write(bytes)
            } finally {
                bytes.fill(0)
            }
        }
        fun flush() {
            val slice = if (filled == payload.size) payload else payload.copyOf(filled)
            try {
                emit(exchange.sealDataFrame(slice))
            } finally {
                slice.fill(0)
            }
            dataFrames += 1
            sent += filled
            filled = 0
            onProgress(sent, ciphertext.length)
        }
        try {
            sink.write(record)
            onProgress(0L, ciphertext.length)
            ciphertext.stream { chunk ->
                var offset = 0
                while (offset < chunk.size) {
                    val count = minOf(payload.size - filled, chunk.size - offset)
                    chunk.copyInto(payload, filled, offset, offset + count)
                    filled += count
                    offset += count
                    if (filled == payload.size) flush()
                }
            }
            if (filled > 0) flush()
            if (dataFrames != exchange.uploadDataFrameCount() || sent != ciphertext.length) {
                throw IOException("Attachment unavailable")
            }
            repeat(bucketFrames - dataFrames) { emit(exchange.sealPaddingFrame()) }
            emit(exchange.sealEndFrame())
        } finally {
            payload.fill(0)
        }
    }

    fun wipe() = record.fill(0)
}

private fun readExactly(input: InputStream, destination: ByteArray) {
    var offset = 0
    while (offset < destination.size) {
        val count = input.read(destination, offset, destination.size - offset)
        if (count < 0) throw EOFException("Attachment unavailable")
        offset += count
    }
}

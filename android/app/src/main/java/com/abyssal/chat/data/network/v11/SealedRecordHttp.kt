package com.abyssal.chat.data.network.v11

import com.abyssal.chat.data.network.BoundedInputReader
import com.abyssal.chat.data.network.awaitHttpResponse
import okhttp3.Call
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response

/**
 * Protocol-v11 HTTP: every request is one opaque sealed record posted to a
 * fixed path, so the relay's routes reveal nothing about the operation, and
 * no bearer token or readable field ever leaves the device.
 */
internal object SealedRecordHttp {
    const val BOOTSTRAP_PATH = "/v1/bootstrap"
    const val CONTROL_PATH = "/v1/control"
    const val ATTACHMENT_PATH = "/v3/attachment"
    const val WEBSOCKET_PATH = "/v1/ws"
    const val WEBSOCKET_PROTOCOL = "abyssal-v11"

    /** Upper bound for a sealed account-entry reply read into memory. */
    const val MAX_BOOTSTRAP_REPLY_BYTES = 256L * 1024L

    val OCTET_STREAM = "application/octet-stream".toMediaType()

    fun request(url: String, record: ByteArray): Request = Request.Builder()
        .url(url)
        .header("Accept", "application/octet-stream")
        .header("Cache-Control", "no-store")
        .header("Pragma", "no-cache")
        .post(record.toRequestBody(OCTET_STREAM))
        .build()

    /** Reads a successful reply of at most [maxBytes]; null for anything else. */
    fun readReply(response: Response, maxBytes: Long): ByteArray? {
        if (!response.isSuccessful) return null
        val body = response.body ?: return null
        if (body.contentLength() > maxBytes) return null
        return BoundedInputReader.read(body.byteStream(), maxBytes)?.takeIf { it.isNotEmpty() }
    }

    /**
     * Posts one sealed record and returns the sealed reply, or null when the
     * relay or a proxy answered with an error. The caller owns both buffers.
     */
    suspend fun post(callFactory: Call.Factory, url: String, record: ByteArray, maxReplyBytes: Long): ByteArray? =
        awaitHttpResponse(
            call = callFactory.newCall(request(url, record)),
            onCancellation = { reply: ByteArray? -> reply?.fill(0) }
        ) { response -> readReply(response, maxReplyBytes) }
}

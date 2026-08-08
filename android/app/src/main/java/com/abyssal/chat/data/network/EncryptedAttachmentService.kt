package com.abyssal.chat.data.network

import android.content.Context
import android.net.Uri
import com.abyssal.chat.domain.model.AttachmentUploadResult
import com.abyssal.chat.domain.model.DecryptedAttachment
import com.abyssal.chat.domain.repository.IEncryptedAttachmentService
import com.abyssal.chat.domain.repository.INodeConfigService
import java.io.IOException
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.MediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okio.BufferedSink
import org.json.JSONObject

private const val CHACHA20_POLY1305_TAG_BYTES = 16L
private const val SERIALIZED_ATTACHMENT_FIXED_BYTES = 16L * 1024L

// The attachment ciphertext is base64 encoded inside the encrypted JSON payload.
// Keep a deterministic envelope budget for recipient-specific wrapped keys rather
// than pretending JSON adds only the AEAD tag size.
internal const val MAX_RECIPIENT_ENVELOPE_OVERHEAD_BYTES = 4L * 1024L * 1024L

internal fun base64NoPaddingLength(rawBytes: Long): Long {
    require(rawBytes >= 0L)
    val groups = rawBytes / 3L
    return groups * 4L + when (rawBytes % 3L) {
        0L -> 0L
        1L -> 2L
        else -> 3L
    }
}

internal fun maxSerializedAttachmentBytes(mediaType: String): Long {
    val plainLimit = when (mediaType.uppercase()) {
        "IMAGE" -> 20L * 1024L * 1024L
        "VIDEO" -> 100L * 1024L * 1024L
        else -> 200L * 1024L * 1024L
    }
    val ciphertextB64Bytes = base64NoPaddingLength(plainLimit + CHACHA20_POLY1305_TAG_BYTES)
    return SERIALIZED_ATTACHMENT_FIXED_BYTES +
        ciphertextB64Bytes +
        MAX_RECIPIENT_ENVELOPE_OVERHEAD_BYTES
}

internal val MAX_ENCRYPTED_ATTACHMENT_BYTES: Long = maxSerializedAttachmentBytes("FILE")
internal const val MAX_ATTACHMENT_UPLOAD_RESPONSE_BYTES = 64L * 1024L

internal fun readBoundedAttachmentBody(body: okhttp3.ResponseBody): ByteArray? {
    if (body.contentLength() > MAX_ENCRYPTED_ATTACHMENT_BYTES) return null
    return BoundedInputReader.read(body.byteStream(), MAX_ENCRYPTED_ATTACHMENT_BYTES)
}

internal fun readBoundedAttachmentResponse(body: okhttp3.ResponseBody): JSONObject? {
    if (body.contentLength() > MAX_ATTACHMENT_UPLOAD_RESPONSE_BYTES) return null
    val raw = BoundedInputReader.read(body.byteStream(), MAX_ATTACHMENT_UPLOAD_RESPONSE_BYTES)
        ?: return null
    return try {
        JSONObject(String(raw, StandardCharsets.UTF_8))
    } catch (_: Exception) {
        null
    } finally {
        raw.fill(0)
    }
}

class EncryptedAttachmentService(
    private val appContext: Context,
    private val nodeConfigService: INodeConfigService,
    private val client: OkHttpClient
) : IEncryptedAttachmentService {

    init {
        removeLegacyExportKey()
    }

    override suspend fun uploadEncryptedAttachment(
        chatId: String,
        mediaType: String,
        encryptedBytes: ByteArray,
        oneTimeView: Boolean,
        deleteAfterDownload: Boolean,
        ttlSec: Int,
        onProgress: (sentBytes: Long, totalBytes: Long) -> Unit
    ): AttachmentUploadResult = withContext(Dispatchers.IO) {
        val session = nodeConfigService.getActiveSession() ?: return@withContext AttachmentUploadResult(false)
        if (
            encryptedBytes.isEmpty() ||
            encryptedBytes.size.toLong() > maxSerializedAttachmentBytes(mediaType)
        ) {
            return@withContext AttachmentUploadResult(false)
        }
        val query = listOf(
            "chat_id" to chatId,
            "media_type" to mediaType.uppercase(),
            "one_time" to oneTimeView.toString(),
            "delete_after_download" to deleteAfterDownload.toString(),
            "ttl_sec" to ttlSec.coerceAtLeast(0).toString()
        ).joinToString("&") { (key, value) ->
            "${key}=${URLEncoder.encode(value, StandardCharsets.UTF_8.name())}"
        }
        val body = ProgressRequestBody(
            bytes = encryptedBytes,
            mediaType = "application/octet-stream".toMediaType(),
            onProgress = onProgress
        )
        val request = Request.Builder()
            .url("${session.endpoint.apiBaseUrl}/v1/attachment?$query")
            .header("Authorization", "Bearer ${session.token}")
            .post(body)
            .build()

        runCatching {
            client.newCall(request).execute().use { response ->
                val json = response.body?.let(::readBoundedAttachmentResponse)
                AttachmentUploadResult(
                    accepted = response.isSuccessful && json?.optBoolean("accepted", false) == true,
                    attachmentId = json?.optString("attachment_id")?.takeIf { it.isNotBlank() }
                )
            }
        }.getOrElse {
            AttachmentUploadResult(false)
        }
    }

    override suspend fun downloadEncryptedAttachment(attachmentId: String): ByteArray? = withContext(Dispatchers.IO) {
        val session = nodeConfigService.getActiveSession() ?: return@withContext null
        val request = Request.Builder()
            .url("${session.endpoint.apiBaseUrl}/v1/attachment/$attachmentId")
            .header("Authorization", "Bearer ${session.token}")
            .get()
            .build()

        try {
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return@use null
                val body = response.body ?: return@use null
                readBoundedAttachmentBody(body)
            }
        } catch (e: IOException) {
            null
        } catch (e: Exception) {
            null
        }
    }

    override suspend fun saveDecryptedAttachment(
        attachment: DecryptedAttachment,
        outputUri: Uri
    ): Boolean = withContext(Dispatchers.IO) {
        try {
            appContext.contentResolver.openOutputStream(outputUri, "w")?.use { output ->
                AttachmentDocumentWriter.write(attachment.bytes, output)
            } != null
        } catch (e: Exception) {
            false
        }
    }

    private fun removeLegacyExportKey() {
        runCatching {
            KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }.let { keyStore ->
                if (keyStore.containsAlias(LEGACY_EXPORT_KEY_ALIAS)) {
                    keyStore.deleteEntry(LEGACY_EXPORT_KEY_ALIAS)
                }
            }
        }
    }

    private class ProgressRequestBody(
        private val bytes: ByteArray,
        private val mediaType: MediaType,
        private val onProgress: (sentBytes: Long, totalBytes: Long) -> Unit
    ) : RequestBody() {
        override fun contentType(): MediaType = mediaType

        override fun contentLength(): Long = bytes.size.toLong()

        override fun writeTo(sink: BufferedSink) {
            val total = bytes.size.toLong()
            var sent = 0L
            var offset = 0
            onProgress(0L, total)
            while (offset < bytes.size) {
                val count = minOf(CHUNK_BYTES, bytes.size - offset)
                sink.write(bytes, offset, count)
                offset += count
                sent += count
                onProgress(sent, total)
            }
        }

        private companion object {
            const val CHUNK_BYTES = 64 * 1024
        }
    }

    private companion object {
        const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        const val LEGACY_EXPORT_KEY_ALIAS = "abyssal_attachment_export_v1"

    }
}

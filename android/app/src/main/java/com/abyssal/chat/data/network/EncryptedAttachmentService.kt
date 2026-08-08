package com.abyssal.chat.data.network

import android.content.Context
import android.net.Uri
import com.abyssal.chat.domain.model.AttachmentUploadResult
import com.abyssal.chat.domain.model.DecryptedAttachment
import com.abyssal.chat.domain.model.EncryptedAttachmentDownload
import com.abyssal.chat.domain.repository.IEncryptedAttachmentService
import com.abyssal.chat.domain.repository.INodeConfigService
import java.io.IOException
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.util.UUID
import java.util.concurrent.CancellationException
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.MediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okio.BufferedSink
import org.json.JSONObject

internal const val ATTACHMENT_WIRE_OVERHEAD_BYTES = 41L
internal const val ATTACHMENT_CLAIM_HEADER = "X-Abyssal-Attachment-Claim"

internal fun maxSerializedAttachmentBytes(mediaType: String): Long {
    val plainLimit = when (mediaType.uppercase()) {
        "IMAGE" -> 20L * 1024L * 1024L
        "VIDEO" -> 100L * 1024L * 1024L
        else -> 200L * 1024L * 1024L
    }
    return plainLimit + ATTACHMENT_WIRE_OVERHEAD_BYTES
}

internal val MAX_ENCRYPTED_ATTACHMENT_BYTES: Long = maxSerializedAttachmentBytes("FILE")
internal const val MAX_ATTACHMENT_UPLOAD_RESPONSE_BYTES = 64L * 1024L
private val ATTACHMENT_ID_REGEX = Regex(
    "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
private val ATTACHMENT_CLAIM_REGEX = Regex(
    "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)

internal fun readBoundedAttachmentBody(body: okhttp3.ResponseBody): ByteArray? {
    val contentLength = body.contentLength()
    if (
        contentLength <= 0L ||
        contentLength > MAX_ENCRYPTED_ATTACHMENT_BYTES ||
        contentLength > Int.MAX_VALUE.toLong()
    ) return null
    return BoundedInputReader.readExact(
        input = body.byteStream(),
        expectedBytes = contentLength,
        maxBytes = MAX_ENCRYPTED_ATTACHMENT_BYTES
    )
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

internal fun normalizeAttachmentId(value: String): String? {
    val candidate = value.trim()
    if (!candidate.matches(ATTACHMENT_ID_REGEX)) return null
    return runCatching { UUID.fromString(candidate).toString() }.getOrNull()
}

internal fun normalizeAttachmentClaim(value: String): String? {
    val candidate = value.trim()
    if (!candidate.matches(ATTACHMENT_CLAIM_REGEX)) return null
    return runCatching { UUID.fromString(candidate).toString() }.getOrNull()
}

/** Plaintext is returned only after the relay acknowledges a valid destructive claim. */
internal suspend fun decryptAndCompleteAttachment(
    downloaded: EncryptedAttachmentDownload,
    decrypt: suspend () -> ByteArray?,
    complete: suspend (claim: String) -> Boolean,
    release: suspend (claim: String) -> Boolean
): ByteArray? {
    var plaintext: ByteArray? = null
    var exposed = false
    var completed = false
    try {
        val candidate = decrypt() ?: return null
        plaintext = candidate
        if (candidate.isEmpty()) return null
        downloaded.claim?.let { claim ->
            if (!complete(claim)) return null
            completed = true
        }
        exposed = true
        return candidate
    } catch (error: CancellationException) {
        throw error
    } catch (_: Exception) {
        return null
    } finally {
        downloaded.bytes.fill(0)
        if (!exposed) plaintext?.fill(0)
        downloaded.claim?.takeUnless { completed }?.let { claim ->
            withContext(NonCancellable) {
                runCatching { release(claim) }
            }
        }
    }
}

class EncryptedAttachmentService(
    private val appContext: Context,
    private val nodeConfigService: INodeConfigService,
    client: OkHttpClient,
    private val callFactory: okhttp3.Call.Factory = client
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

        try {
            awaitHttpResponse(callFactory.newCall(request)) { response ->
                val json = response.body?.let(::readBoundedAttachmentResponse)
                AttachmentUploadResult(
                    accepted = response.isSuccessful && json?.optBoolean("accepted", false) == true,
                    attachmentId = json?.optString("attachment_id")?.takeIf { it.isNotBlank() }
                )
            }
        } catch (error: CancellationException) {
            throw error
        } catch (_: Exception) {
            AttachmentUploadResult(false)
        }
    }

    override suspend fun downloadEncryptedAttachment(attachmentId: String): EncryptedAttachmentDownload? = withContext(Dispatchers.IO) {
        val session = nodeConfigService.getActiveSession() ?: return@withContext null
        val normalizedAttachmentId = normalizeAttachmentId(attachmentId) ?: return@withContext null
        val request = Request.Builder()
            .url("${session.endpoint.apiBaseUrl}/v1/attachment/$normalizedAttachmentId")
            .header("Authorization", "Bearer ${session.token}")
            .get()
            .build()

        // OkHttp invokes the response consumer on its callback thread while cancellation
        // cleanup runs on the coroutine thread. Keep the destructive claim synchronized so
        // cancellation after headers are observed cannot miss the release request.
        val claimRef = AtomicReference<String?>(null)
        val downloaded = try {
            awaitHttpResponse(
                call = callFactory.newCall(request),
                onCancellation = { result -> result?.bytes?.fill(0) }
            ) { response ->
                val rawClaim = response.header(ATTACHMENT_CLAIM_HEADER)
                val normalizedClaim = rawClaim?.let(::normalizeAttachmentClaim)
                claimRef.set(normalizedClaim)
                if ((rawClaim != null && normalizedClaim == null) || !response.isSuccessful) {
                    null
                } else {
                    val body = response.body
                    val bytes = body?.let(::readBoundedAttachmentBody)
                    if (bytes == null || bytes.isEmpty()) {
                        null
                    } else {
                        EncryptedAttachmentDownload(bytes = bytes, claim = claimRef.get())
                    }
                }
            }
        } catch (e: CancellationException) {
            val cancelledClaim = claimRef.get()
            if (cancelledClaim != null) {
                withContext(NonCancellable) {
                    releaseAttachmentDownloadClaim(normalizedAttachmentId, cancelledClaim)
                }
            }
            throw e
        } catch (e: IOException) {
            null
        } catch (e: Exception) {
            null
        }
        val failedClaim = claimRef.get()
        if (downloaded == null && failedClaim != null) {
            withContext(NonCancellable) {
                releaseAttachmentDownloadClaim(normalizedAttachmentId, failedClaim)
            }
        }
        downloaded
    }

    override suspend fun completeAttachmentDownload(attachmentId: String, claim: String): Boolean =
        attachmentClaimRequest(attachmentId, claim, complete = true)

    override suspend fun releaseAttachmentDownloadClaim(attachmentId: String, claim: String): Boolean =
        attachmentClaimRequest(attachmentId, claim, complete = false)

    private suspend fun attachmentClaimRequest(
        attachmentId: String,
        claim: String,
        complete: Boolean
    ): Boolean = withContext(Dispatchers.IO) {
        val session = nodeConfigService.getActiveSession() ?: return@withContext false
        val normalizedAttachmentId = normalizeAttachmentId(attachmentId) ?: return@withContext false
        val normalizedClaim = normalizeAttachmentClaim(claim) ?: return@withContext false
        val suffix = if (complete) "/complete" else "/claim"
        val builder = Request.Builder()
            .url("${session.endpoint.apiBaseUrl}/v1/attachment/$normalizedAttachmentId$suffix")
            .header("Authorization", "Bearer ${session.token}")
            .header(ATTACHMENT_CLAIM_HEADER, normalizedClaim)
        val request = if (complete) {
            builder.post(ByteArray(0).toRequestBody(null)).build()
        } else {
            builder.delete().build()
        }
        try {
            awaitHttpResponse(callFactory.newCall(request)) { response -> response.isSuccessful }
        } catch (error: CancellationException) {
            throw error
        } catch (_: Exception) {
            false
        }
    }

    override suspend fun saveDecryptedAttachment(
        attachment: DecryptedAttachment,
        outputUri: Uri
    ): Boolean = withContext(Dispatchers.IO) {
        AttachmentDocumentWriter.writeIfNonEmptyOrDelete(
            bytes = attachment.bytes,
            openOutput = {
                runCatching { appContext.contentResolver.openOutputStream(outputUri, "w") }
                    .getOrNull()
            },
            deleteOutput = {
                runCatching { appContext.contentResolver.delete(outputUri, null, null) }
            }
        )
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

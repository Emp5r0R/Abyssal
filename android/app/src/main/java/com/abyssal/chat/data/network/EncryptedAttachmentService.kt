package com.abyssal.chat.data.network

import android.content.Context
import android.net.Uri
import com.abyssal.chat.domain.model.AttachmentUploadResult
import com.abyssal.chat.domain.model.AttachmentProtocol
import com.abyssal.chat.domain.model.DecryptedAttachment
import com.abyssal.chat.domain.model.DecryptedAttachmentDownload
import com.abyssal.chat.domain.model.NodeSession
import com.abyssal.chat.domain.repository.IAttachmentPlaintextSource
import com.abyssal.chat.domain.repository.IEncryptedAttachmentService
import java.io.EOFException
import java.io.IOException
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.util.Locale
import java.util.UUID
import java.util.concurrent.CancellationException
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.MediaType
import okhttp3.Call
import okhttp3.Callback
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.Response
import okhttp3.RequestBody.Companion.toRequestBody
import okio.BufferedSink
import org.json.JSONObject
import uniffi.abyssal_core.decryptAttachmentChunk
import uniffi.abyssal_core.encryptAttachmentChunk
import uniffi.abyssal_core.generateAttachmentKey

internal const val ATTACHMENT_CHUNK_PLAINTEXT_BYTES = 256L * 1024L
internal const val ATTACHMENT_CHUNK_RECORD_BYTES = 1L + 4L + 4L + 8L + 24L +
    ATTACHMENT_CHUNK_PLAINTEXT_BYTES + 16L
internal const val ATTACHMENT_CLAIM_HEADER = "X-Abyssal-Attachment-Claim"

internal fun maxSerializedAttachmentBytes(mediaType: String): Long =
    expectedEncryptedAttachmentBytes(protocolAttachmentLimitBytes(mediaType)) ?: 0L

internal fun expectedEncryptedAttachmentBytes(plaintextBytes: Long): Long? =
    if (plaintextBytes <= 0L) null else run {
        val chunkCount = ((plaintextBytes - 1L) / ATTACHMENT_CHUNK_PLAINTEXT_BYTES) + 1L
        if (chunkCount > Long.MAX_VALUE / ATTACHMENT_CHUNK_RECORD_BYTES) null
        else chunkCount * ATTACHMENT_CHUNK_RECORD_BYTES
    }

internal const val MAX_ATTACHMENT_UPLOAD_RESPONSE_BYTES = 64L * 1024L
private val ATTACHMENT_ID_REGEX = Regex(
    "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
private val ATTACHMENT_CLAIM_REGEX = Regex(
    "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
private val SUPPORTED_ATTACHMENT_MEDIA_TYPES = setOf("IMAGE", "VIDEO", "FILE")

internal fun readAndDecryptAttachmentBody(
    body: okhttp3.ResponseBody,
    chatId: String,
    messageId: String,
    senderUsername: String,
    mediaType: String,
    key: ByteArray,
    expectedPlaintextBytes: Long,
    expectedWireBytes: Long
): ByteArray? {
    if (key.size != AttachmentProtocol.KEY_BYTES ||
        expectedPlaintextBytes !in 1L..Int.MAX_VALUE.toLong() ||
        expectedWireBytes <= 0L ||
        expectedWireBytes % ATTACHMENT_CHUNK_RECORD_BYTES != 0L ||
        (body.contentLength() >= 0L && body.contentLength() != expectedWireBytes)
    ) return null
    val plaintext = ByteArray(expectedPlaintextBytes.toInt())
    val record = ByteArray(ATTACHMENT_CHUNK_RECORD_BYTES.toInt())
    var plaintextOffset = 0
    var complete = false
    return try {
        val input = body.byteStream()
        val recordCount = expectedWireBytes / ATTACHMENT_CHUNK_RECORD_BYTES
        for (chunkIndex in 0L until recordCount) {
            readFully(input, record)
            val chunk = decryptAttachmentChunk(
                chatId = chatId,
                messageId = messageId,
                senderUsername = senderUsername,
                mediaType = mediaType,
                key = key,
                expectedTotalPlaintextBytes = expectedPlaintextBytes.toULong(),
                expectedChunkIndex = chunkIndex.toUInt(),
                record = record
            )
            try {
                val expectedChunkBytes = minOf(
                    ATTACHMENT_CHUNK_PLAINTEXT_BYTES.toInt(),
                    plaintext.size - plaintextOffset
                )
                if (chunk.size != expectedChunkBytes) return null
                chunk.copyInto(plaintext, plaintextOffset)
                plaintextOffset += chunk.size
            } finally {
                chunk.fill(0)
                record.fill(0)
            }
        }
        if (plaintextOffset != plaintext.size || input.read() >= 0) return null
        complete = true
        plaintext
    } catch (error: CancellationException) {
        throw error
    } catch (_: Exception) {
        null
    } finally {
        record.fill(0)
        if (!complete) plaintext.fill(0)
    }
}

private fun readFully(
    input: java.io.InputStream,
    destination: ByteArray,
    bytesToRead: Int = destination.size
) {
    if (bytesToRead !in 1..destination.size) throw EOFException("Attachment unavailable")
    var offset = 0
    while (offset < bytesToRead) {
        val count = input.read(destination, offset, bytesToRead - offset)
        when {
            count < 0 -> throw EOFException("Attachment unavailable")
            count == 0 -> {
                val next = input.read()
                if (next < 0) throw EOFException("Attachment unavailable")
                destination[offset++] = next.toByte()
            }
            else -> offset += count
        }
    }
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
    downloaded: DecryptedAttachmentDownload,
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
    client: OkHttpClient,
    private val callFactory: okhttp3.Call.Factory = client
) : IEncryptedAttachmentService {

    init {
        removeLegacyExportKey()
    }

    override suspend fun uploadEncryptedAttachment(
        session: NodeSession,
        chatId: String,
        messageId: String,
        senderUsername: String,
        mediaType: String,
        source: IAttachmentPlaintextSource,
        oneTimeView: Boolean,
        deleteAfterDownload: Boolean,
        ttlSec: Int,
        onProgress: (sentBytes: Long, totalBytes: Long) -> Unit
    ): AttachmentUploadResult = withContext(Dispatchers.IO) {
        val normalizedMediaType = mediaType.uppercase(Locale.ROOT)
        var key: ByteArray? = null
        var keyTransferred = false
        try {
            val expectedWireBytes = expectedEncryptedAttachmentBytes(source.sizeBytes)
            if (!messageId.matches(ATTACHMENT_ID_REGEX) ||
                normalizedMediaType !in SUPPORTED_ATTACHMENT_MEDIA_TYPES ||
                source.sizeBytes !in 1L..protocolAttachmentLimitBytes(normalizedMediaType) ||
                expectedWireBytes == null ||
                expectedWireBytes > maxSerializedAttachmentBytes(normalizedMediaType)
            ) return@withContext AttachmentUploadResult(false)
            key = generateAttachmentKey()
            if (key.size != AttachmentProtocol.KEY_BYTES) {
                return@withContext AttachmentUploadResult(false)
            }
            val query = listOf(
                "chat_id" to chatId,
                "message_id" to messageId,
                "media_type" to normalizedMediaType,
                "one_time" to oneTimeView.toString(),
                "delete_after_download" to deleteAfterDownload.toString(),
                "ttl_sec" to ttlSec.coerceAtLeast(0).toString()
            ).joinToString("&") { (queryKey, value) ->
                "${queryKey}=${URLEncoder.encode(value, StandardCharsets.UTF_8.name())}"
            }
            val body = EncryptedChunkRequestBody(
                source = source,
                chatId = chatId,
                messageId = messageId,
                senderUsername = senderUsername,
                mediaTypeName = normalizedMediaType,
                key = key,
                onProgress = onProgress
            )
            val request = Request.Builder()
                .url("${session.endpoint.apiBaseUrl}/v1/attachment?$query")
                .header("Authorization", "Bearer ${session.token}")
                .post(body)
                .build()
            val result = awaitHttpResponse(callFactory.newCall(request)) { response ->
                val json = response.body?.let(::readBoundedAttachmentResponse)
                AttachmentUploadResult(
                    accepted = response.isSuccessful && json?.optBoolean("accepted", false) == true,
                    attachmentId = json?.optString("attachment_id")?.takeIf { it.isNotBlank() }
                )
            }
            if (result.accepted && result.attachmentId != null) {
                keyTransferred = true
                result.copy(
                    cipherVersion = AttachmentProtocol.CIPHER_VERSION,
                    encryptionKey = key
                )
            } else {
                result
            }
        } catch (error: CancellationException) {
            throw error
        } catch (_: Exception) {
            AttachmentUploadResult(false)
        } finally {
            source.destroy()
            if (!keyTransferred) key?.fill(0)
        }
    }

    override suspend fun downloadDecryptedAttachment(
        session: NodeSession,
        attachmentId: String,
        chatId: String,
        messageId: String,
        senderUsername: String,
        mediaType: String,
        encryptionKey: ByteArray,
        expectedPlaintextBytes: Long
    ): DecryptedAttachmentDownload? = withContext(Dispatchers.IO) {
        val normalizedAttachmentId = normalizeAttachmentId(attachmentId) ?: return@withContext null
        val normalizedMediaType = mediaType.uppercase(Locale.ROOT)
            .takeIf { it in SUPPORTED_ATTACHMENT_MEDIA_TYPES }
            ?: return@withContext null
        val maxWireBytes = attachmentWireSelectionLimitBytes(normalizedMediaType)
        val expectedWireBytes = expectedEncryptedAttachmentBytes(expectedPlaintextBytes)
        if (expectedWireBytes == null ||
            encryptionKey.size != AttachmentProtocol.KEY_BYTES ||
            expectedPlaintextBytes > attachmentSelectionLimitBytes(normalizedMediaType) ||
            expectedWireBytes > maxWireBytes
        ) return@withContext null
        val request = Request.Builder()
            .url("${session.endpoint.apiBaseUrl}/v1/attachment/$normalizedAttachmentId")
            .header("Authorization", "Bearer ${session.token}")
            .get()
            .build()

        // OkHttp invokes the response consumer on its callback thread while cancellation
        // cleanup runs on the coroutine thread. Keep the destructive claim synchronized so
        // cancellation after headers are observed cannot miss the release request.
        val claimRef = AtomicReference<String?>(null)
        val claimReleaseScheduled = AtomicReference(false)
        fun releaseClaimOnce(claim: String) {
            if (claimReleaseScheduled.compareAndSet(false, true)) {
                releaseAttachmentDownloadClaimAsync(
                    session,
                    normalizedAttachmentId,
                    claim
                )
            }
        }
        val downloaded = try {
            awaitHttpResponse(
                call = callFactory.newCall(request),
                onCancellation = { result ->
                    result?.bytes?.fill(0)
                    result?.claim?.let(::releaseClaimOnce)
                },
                onLateResponse = { response ->
                    response.header(ATTACHMENT_CLAIM_HEADER)
                        ?.let(::normalizeAttachmentClaim)
                        ?.let(::releaseClaimOnce)
                }
            ) { response ->
                val rawClaim = response.header(ATTACHMENT_CLAIM_HEADER)
                val normalizedClaim = rawClaim?.let(::normalizeAttachmentClaim)
                claimRef.set(normalizedClaim)
                if ((rawClaim != null && normalizedClaim == null) || !response.isSuccessful) {
                    null
                } else {
                    val body = response.body
                    val bytes = body?.let {
                        readAndDecryptAttachmentBody(
                            body = it,
                            chatId = chatId,
                            messageId = messageId,
                            senderUsername = senderUsername,
                            mediaType = normalizedMediaType,
                            key = encryptionKey,
                            expectedPlaintextBytes = expectedPlaintextBytes,
                            expectedWireBytes = expectedWireBytes
                        )
                    }
                    if (bytes == null || bytes.isEmpty()) {
                        null
                    } else {
                        DecryptedAttachmentDownload(bytes = bytes, claim = claimRef.get())
                    }
                }
            }
        } catch (e: CancellationException) {
            val cancelledClaim = claimRef.get()
            if (cancelledClaim != null) {
                withContext(NonCancellable) {
                    if (claimReleaseScheduled.compareAndSet(false, true)) {
                        releaseAttachmentDownloadClaim(session, normalizedAttachmentId, cancelledClaim)
                    }
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
                if (claimReleaseScheduled.compareAndSet(false, true)) {
                    releaseAttachmentDownloadClaim(session, normalizedAttachmentId, failedClaim)
                }
            }
        }
        downloaded
    }

    override suspend fun deleteUploadedAttachment(
        session: NodeSession,
        attachmentId: String
    ): Boolean = withContext(Dispatchers.IO) {
        val normalizedAttachmentId = normalizeAttachmentId(attachmentId) ?: return@withContext false
        val request = Request.Builder()
            .url("${session.endpoint.apiBaseUrl}/v1/attachment/$normalizedAttachmentId")
            .header("Authorization", "Bearer ${session.token}")
            .delete()
            .build()
        try {
            awaitHttpResponse(callFactory.newCall(request)) { response ->
                response.isSuccessful || response.code == 404
            }
        } catch (error: CancellationException) {
            throw error
        } catch (_: Exception) {
            false
        }
    }

    override suspend fun completeAttachmentDownload(
        session: NodeSession,
        attachmentId: String,
        claim: String
    ): Boolean = attachmentClaimRequest(session, attachmentId, claim, complete = true)

    override suspend fun releaseAttachmentDownloadClaim(
        session: NodeSession,
        attachmentId: String,
        claim: String
    ): Boolean = attachmentClaimRequest(session, attachmentId, claim, complete = false)

    private suspend fun attachmentClaimRequest(
        session: NodeSession,
        attachmentId: String,
        claim: String,
        complete: Boolean
    ): Boolean = withContext(Dispatchers.IO) {
        val request = buildAttachmentClaimRequest(session, attachmentId, claim, complete)
            ?: return@withContext false
        try {
            awaitHttpResponse(callFactory.newCall(request)) { response -> response.isSuccessful }
        } catch (error: CancellationException) {
            throw error
        } catch (_: Exception) {
            false
        }
    }

    private fun buildAttachmentClaimRequest(
        session: NodeSession,
        attachmentId: String,
        claim: String,
        complete: Boolean
    ): Request? {
        val normalizedAttachmentId = normalizeAttachmentId(attachmentId) ?: return null
        val normalizedClaim = normalizeAttachmentClaim(claim) ?: return null
        val suffix = if (complete) "/complete" else "/claim"
        val builder = Request.Builder()
            .url("${session.endpoint.apiBaseUrl}/v1/attachment/$normalizedAttachmentId$suffix")
            .header("Authorization", "Bearer ${session.token}")
            .header(ATTACHMENT_CLAIM_HEADER, normalizedClaim)
        return if (complete) {
            builder.post(ByteArray(0).toRequestBody(null)).build()
        } else {
            builder.delete().build()
        }
    }

    private fun releaseAttachmentDownloadClaimAsync(
        session: NodeSession,
        attachmentId: String,
        claim: String
    ) {
        val request = buildAttachmentClaimRequest(session, attachmentId, claim, complete = false)
            ?: return
        runCatching {
            callFactory.newCall(request).enqueue(object : Callback {
                override fun onFailure(call: Call, e: IOException) = Unit

                override fun onResponse(call: Call, response: Response) {
                    response.close()
                }
            })
        }
    }

    override suspend fun saveDecryptedAttachment(
        attachment: DecryptedAttachment,
        outputUri: Uri
    ): Boolean = withContext(Dispatchers.IO) {
        val operationJob = currentCoroutineContext()[kotlinx.coroutines.Job]
        AttachmentDocumentWriter.writeIfNonEmptyOrDelete(
            bytes = attachment.bytes,
            openOutput = {
                runCatching { appContext.contentResolver.openOutputStream(outputUri, "w") }
                    .getOrNull()
            },
            deleteOutput = {
                runCatching { appContext.contentResolver.delete(outputUri, null, null) }
            },
            shouldCancel = { operationJob?.isActive == false }
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

    private class EncryptedChunkRequestBody(
        private val source: IAttachmentPlaintextSource,
        private val chatId: String,
        private val messageId: String,
        private val senderUsername: String,
        private val mediaTypeName: String,
        private val key: ByteArray,
        private val onProgress: (sentBytes: Long, totalBytes: Long) -> Unit
    ) : RequestBody() {
        private val wireBytes = expectedEncryptedAttachmentBytes(source.sizeBytes)
            ?: throw IllegalArgumentException("Attachment unavailable")

        override fun contentType(): MediaType = "application/octet-stream".toMediaType()

        override fun contentLength(): Long = wireBytes

        override fun isOneShot(): Boolean = true

        override fun writeTo(sink: BufferedSink) {
            val plaintextBuffer = ByteArray(ATTACHMENT_CHUNK_PLAINTEXT_BYTES.toInt())
            var plaintextRead = 0L
            var chunkIndex = 0L
            onProgress(0L, source.sizeBytes)
            try {
                source.openStream().use { input ->
                    while (plaintextRead < source.sizeBytes) {
                        val chunkBytes = minOf(
                            plaintextBuffer.size.toLong(),
                            source.sizeBytes - plaintextRead
                        ).toInt()
                        readFully(input, plaintextBuffer, chunkBytes)
                        val plaintext = if (chunkBytes == plaintextBuffer.size) {
                            plaintextBuffer
                        } else {
                            plaintextBuffer.copyOf(chunkBytes)
                        }
                        val record = try {
                            encryptAttachmentChunk(
                                chatId = chatId,
                                messageId = messageId,
                                senderUsername = senderUsername,
                                mediaType = mediaTypeName,
                                key = key,
                                totalPlaintextBytes = source.sizeBytes.toULong(),
                                chunkIndex = chunkIndex.toUInt(),
                                plaintext = plaintext
                            )
                        } finally {
                            plaintext.fill(0)
                        }
                        try {
                            if (record.size.toLong() != ATTACHMENT_CHUNK_RECORD_BYTES ||
                                record.firstOrNull()?.toInt() != AttachmentProtocol.CIPHER_VERSION
                            ) throw IOException("Attachment unavailable")
                            sink.write(record)
                        } finally {
                            record.fill(0)
                        }
                        plaintextRead += chunkBytes
                        chunkIndex += 1L
                        onProgress(plaintextRead, source.sizeBytes)
                    }
                    if (input.read() >= 0 ||
                        chunkIndex * ATTACHMENT_CHUNK_RECORD_BYTES != wireBytes
                    ) throw IOException("Attachment unavailable")
                }
            } finally {
                plaintextBuffer.fill(0)
            }
        }
    }

    private companion object {
        const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        const val LEGACY_EXPORT_KEY_ALIAS = "abyssal_attachment_export_v1"
    }
}

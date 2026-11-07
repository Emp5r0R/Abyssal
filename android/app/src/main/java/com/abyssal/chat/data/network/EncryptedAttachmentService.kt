package com.abyssal.chat.data.network

import android.content.Context
import android.net.Uri
import com.abyssal.chat.data.network.v11.AttachmentExchange
import com.abyssal.chat.data.network.v11.AttachmentTransportClient
import com.abyssal.chat.data.network.v11.AttachmentUploadRequest
import com.abyssal.chat.data.network.v11.ReplayableCiphertext
import com.abyssal.chat.data.network.v11.uuidBytes
import com.abyssal.chat.data.network.v11.uuidString
import com.abyssal.chat.domain.model.AttachmentProtocol
import com.abyssal.chat.domain.model.AttachmentUploadResult
import com.abyssal.chat.domain.model.DecryptedAttachment
import com.abyssal.chat.domain.model.DecryptedAttachmentDownload
import com.abyssal.chat.domain.model.NodeSession
import com.abyssal.chat.domain.repository.IAttachmentPlaintextSource
import com.abyssal.chat.domain.repository.IEncryptedAttachmentService
import java.io.EOFException
import java.io.IOException
import java.security.KeyStore
import java.util.Locale
import java.util.UUID
import java.util.concurrent.CancellationException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import uniffi.abyssal_core.AttachmentUploadEncryptor
import uniffi.abyssal_core.decryptAttachmentChunk
import uniffi.abyssal_core.generateAttachmentKey

internal const val ATTACHMENT_CHUNK_PLAINTEXT_BYTES = 256L * 1024L
internal const val ATTACHMENT_CHUNK_RECORD_BYTES = 1L + 4L + 4L + 8L + 24L +
    ATTACHMENT_CHUNK_PLAINTEXT_BYTES + 16L

internal fun maxSerializedAttachmentBytes(mediaType: String): Long =
    expectedEncryptedAttachmentBytes(protocolAttachmentLimitBytes(mediaType)) ?: 0L

internal fun expectedEncryptedAttachmentBytes(plaintextBytes: Long): Long? =
    if (plaintextBytes <= 0L) null else run {
        val chunkCount = ((plaintextBytes - 1L) / ATTACHMENT_CHUNK_PLAINTEXT_BYTES) + 1L
        if (chunkCount > Long.MAX_VALUE / ATTACHMENT_CHUNK_RECORD_BYTES) null
        else chunkCount * ATTACHMENT_CHUNK_RECORD_BYTES
    }

private val ATTACHMENT_ID_REGEX = Regex(
    "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
private val ATTACHMENT_CLAIM_REGEX = ATTACHMENT_ID_REGEX
private val SUPPORTED_ATTACHMENT_MEDIA_TYPES = setOf("IMAGE", "VIDEO", "FILE")

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

/**
 * Decrypts an attachment's chunk records as their bytes arrive, in any
 * slicing, into one plaintext buffer; the whole ciphertext is never held.
 * [finish] hands the plaintext over only when every chunk authenticated;
 * otherwise everything is wiped.
 */
internal class AttachmentChunkDecryptor(
    private val chatId: String,
    private val messageId: String,
    private val senderUsername: String,
    private val mediaType: String,
    private val key: ByteArray,
    private val expectedPlaintextBytes: Long
) {
    private val plaintext = ByteArray(expectedPlaintextBytes.toInt())
    private val record = ByteArray(ATTACHMENT_CHUNK_RECORD_BYTES.toInt())
    private var recordFill = 0
    private var chunkIndex = 0L
    private var plaintextOffset = 0
    private var failed = false
    private var handedOver = false

    init {
        require(key.size == AttachmentProtocol.KEY_BYTES && expectedPlaintextBytes in 1L..Int.MAX_VALUE.toLong())
    }

    /** Feeds the next ciphertext bytes; false once anything failed to authenticate. */
    fun feed(bytes: ByteArray): Boolean {
        if (failed || handedOver) return false
        var offset = 0
        while (offset < bytes.size) {
            val count = minOf(record.size - recordFill, bytes.size - offset)
            bytes.copyInto(record, recordFill, offset, offset + count)
            recordFill += count
            offset += count
            if (recordFill == record.size && !decryptRecord()) {
                failed = true
                wipe()
                return false
            }
        }
        return true
    }

    private fun decryptRecord(): Boolean {
        val chunk = try {
            decryptAttachmentChunk(
                chatId = chatId,
                messageId = messageId,
                senderUsername = senderUsername,
                mediaType = mediaType,
                key = key,
                expectedTotalPlaintextBytes = expectedPlaintextBytes.toULong(),
                expectedChunkIndex = chunkIndex.toUInt(),
                record = record
            )
        } catch (error: CancellationException) {
            throw error
        } catch (_: Exception) {
            return false
        } finally {
            record.fill(0)
            recordFill = 0
        }
        try {
            val expected = minOf(ATTACHMENT_CHUNK_PLAINTEXT_BYTES.toInt(), plaintext.size - plaintextOffset)
            if (chunk.size != expected) return false
            chunk.copyInto(plaintext, plaintextOffset)
            plaintextOffset += chunk.size
            chunkIndex += 1L
            return true
        } finally {
            chunk.fill(0)
        }
    }

    /** The plaintext when every chunk arrived and authenticated; else null, with everything wiped. */
    fun finish(): ByteArray? {
        if (failed || handedOver || recordFill != 0 || plaintextOffset != plaintext.size) {
            wipe()
            return null
        }
        handedOver = true
        return plaintext
    }

    fun wipe() {
        record.fill(0)
        if (!handedOver) plaintext.fill(0)
    }
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
        // The download already holds decrypted bytes, and callers usually return
        // that same array as the plaintext: never wipe what is being handed back.
        if (!(exposed && plaintext === downloaded.bytes)) downloaded.bytes.fill(0)
        if (!exposed) plaintext?.fill(0)
        downloaded.claim?.takeUnless { completed }?.let { claim ->
            withContext(NonCancellable) {
                runCatching { release(claim) }
            }
        }
    }
}

class EncryptedAttachmentService internal constructor(
    private val appContext: Context,
    private val callFactory: okhttp3.Call.Factory,
    private val transport: AttachmentTransportClient
) : IEncryptedAttachmentService {

    constructor(appContext: Context, client: OkHttpClient) :
        this(appContext, client, AttachmentTransportClient(client))

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
            val attachmentKey = generateAttachmentKey()
            key = attachmentKey
            if (attachmentKey.size != AttachmentProtocol.KEY_BYTES) {
                return@withContext AttachmentUploadResult(false)
            }
            val attachmentId = AttachmentUploadEncryptor(
                chatId,
                messageId,
                senderUsername,
                normalizedMediaType,
                attachmentKey,
                source.sizeBytes.toULong()
            ).use { encryptor ->
                val ciphertext = SourceCiphertext(source, encryptor)
                if (ciphertext.length != expectedWireBytes) return@withContext AttachmentUploadResult(false)
                transport.upload(
                    apiBaseUrl = session.endpoint.apiBaseUrl,
                    keys = session.transport,
                    request = AttachmentUploadRequest(
                        chatId = chatId,
                        messageId = messageId,
                        mediaType = normalizedMediaType,
                        cipherVersion = AttachmentProtocol.CIPHER_VERSION,
                        oneTime = oneTimeView,
                        deleteAfterDownload = deleteAfterDownload,
                        ttlSec = ttlSec
                    ),
                    ciphertext = ciphertext
                ) { sent, total ->
                    // Report progress on the plaintext scale the UI shows.
                    val plaintextSent = if (total <= 0L) 0L else
                        (sent.toDouble() / total.toDouble() * source.sizeBytes.toDouble()).toLong()
                    onProgress(plaintextSent.coerceIn(0L, source.sizeBytes), source.sizeBytes)
                }
            } ?: return@withContext AttachmentUploadResult(false)
            keyTransferred = true
            AttachmentUploadResult(
                accepted = true,
                attachmentId = attachmentId,
                cipherVersion = AttachmentProtocol.CIPHER_VERSION,
                encryptionKey = attachmentKey
            )
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
        val idBytes = uuidBytes(normalizedAttachmentId) ?: return@withContext null
        val exchange = try {
            transport.beginDownload(session.transport, idBytes)
        } catch (_: Exception) {
            return@withContext null
        } finally {
            idBytes.fill(0)
        }
        val record = exchange.requestBytes()

        // OkHttp invokes the response consumer on its callback thread while cancellation
        // cleanup runs on the coroutine thread. Keep the destructive claim synchronized so
        // cancellation after the head record is opened cannot miss the release request.
        val claimRef = AtomicReference<String?>(null)
        val claimReleaseScheduled = AtomicBoolean(false)
        val responseSeen = AtomicBoolean(false)
        val exchangeClosed = AtomicBoolean(false)
        fun closeExchange() {
            if (exchangeClosed.compareAndSet(false, true)) runCatching { exchange.close() }
        }
        fun releaseClaimOnce(claim: String) {
            if (claimReleaseScheduled.compareAndSet(false, true)) {
                releaseAttachmentDownloadClaimAsync(session, normalizedAttachmentId, claim)
            }
        }
        var cancelled = false
        val downloaded = try {
            awaitHttpResponse(
                call = callFactory.newCall(transport.downloadRequest(session.endpoint.apiBaseUrl, record)),
                onCancellation = { result: DecryptedAttachmentDownload? ->
                    result?.bytes?.fill(0)
                    result?.claim?.let(::releaseClaimOnce)
                },
                onLateResponse = { response ->
                    responseSeen.set(true)
                    try {
                        readClaimOnly(response, exchange)?.let(::releaseClaimOnce)
                    } finally {
                        closeExchange()
                    }
                }
            ) { response ->
                responseSeen.set(true)
                val decryptor = AttachmentChunkDecryptor(
                    chatId = chatId,
                    messageId = messageId,
                    senderUsername = senderUsername,
                    mediaType = normalizedMediaType,
                    key = encryptionKey,
                    expectedPlaintextBytes = expectedPlaintextBytes
                )
                try {
                    val complete = transport.readDownload(
                        response = response,
                        exchange = exchange,
                        expectedCiphertextBytes = expectedWireBytes,
                        onClaim = { claim ->
                            claimRef.set(uuidString(claim))
                            claim.fill(0)
                        },
                        onPayload = { payload ->
                            if (!decryptor.feed(payload)) throw IOException("Attachment unavailable")
                        }
                    )
                    val bytes = if (complete) decryptor.finish() else null
                    if (bytes == null || bytes.isEmpty()) {
                        null
                    } else {
                        DecryptedAttachmentDownload(bytes = bytes, claim = claimRef.get())
                    }
                } finally {
                    decryptor.wipe()
                    closeExchange()
                }
            }
        } catch (e: CancellationException) {
            cancelled = true
            val cancelledClaim = claimRef.get()
            if (cancelledClaim != null) {
                withContext(NonCancellable) {
                    if (claimReleaseScheduled.compareAndSet(false, true)) {
                        releaseAttachmentDownloadClaim(session, normalizedAttachmentId, cancelledClaim)
                    }
                }
            }
            throw e
        } catch (e: Exception) {
            null
        } finally {
            record.fill(0)
            // A canceled call may still deliver a late response that needs the
            // exchange to find its claim; otherwise nothing will use it again.
            if (!cancelled && !responseSeen.get()) closeExchange()
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

    /** Opens only the head of a late download response to find a claim to release. */
    private fun readClaimOnly(response: okhttp3.Response, exchange: AttachmentExchange): String? {
        if (!response.isSuccessful) return null
        val input = response.body?.byteStream() ?: return null
        val head = ByteArray(com.abyssal.chat.data.network.v11.AttachmentFraming.ACTION_RECORD_BYTES)
        return try {
            readFully(input, head)
            val accepted = exchange.openResponse(head)
                as? uniffi.abyssal_core.AttachmentTransportResult.DownloadAccepted ?: return null
            accepted.ciphertextSha256.fill(0)
            accepted.claimId?.let { claim -> uuidString(claim).also { claim.fill(0) } }
        } catch (_: Exception) {
            null
        } finally {
            head.fill(0)
        }
    }

    override suspend fun deleteUploadedAttachment(
        session: NodeSession,
        attachmentId: String
    ): Boolean = withContext(Dispatchers.IO) {
        val id = normalizeAttachmentId(attachmentId)?.let(::uuidBytes) ?: return@withContext false
        try {
            transport.action(session.endpoint.apiBaseUrl, transport.deleteAttachment(session.transport, id))
        } catch (error: CancellationException) {
            throw error
        } catch (_: Exception) {
            false
        } finally {
            id.fill(0)
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
        val exchange = claimExchange(session, attachmentId, claim, complete) ?: return@withContext false
        try {
            transport.action(session.endpoint.apiBaseUrl, exchange)
        } catch (error: CancellationException) {
            throw error
        } catch (_: Exception) {
            false
        }
    }

    private fun claimExchange(
        session: NodeSession,
        attachmentId: String,
        claim: String,
        complete: Boolean
    ): AttachmentExchange? {
        val id = normalizeAttachmentId(attachmentId)?.let(::uuidBytes) ?: return null
        val claimId = normalizeAttachmentClaim(claim)?.let(::uuidBytes)
        return try {
            when {
                claimId == null -> null
                complete -> transport.completeDownload(session.transport, id, claimId)
                else -> transport.releaseDownload(session.transport, id, claimId)
            }
        } catch (_: Exception) {
            null
        } finally {
            id.fill(0)
            claimId?.fill(0)
        }
    }

    /** Releases a claim from an OkHttp callback thread, without waiting for the reply. */
    private fun releaseAttachmentDownloadClaimAsync(
        session: NodeSession,
        attachmentId: String,
        claim: String
    ) {
        val exchange = claimExchange(session, attachmentId, claim, complete = false) ?: return
        transport.actionAsync(session.endpoint.apiBaseUrl, exchange)
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

    /** Encrypts the plaintext source on demand, identically on every pass. */
    private class SourceCiphertext(
        private val source: IAttachmentPlaintextSource,
        private val encryptor: AttachmentUploadEncryptor
    ) : ReplayableCiphertext {
        override val length: Long = encryptor.ciphertextLen().toLong()

        override fun stream(consumer: (ByteArray) -> Unit) {
            val buffer = ByteArray(ATTACHMENT_CHUNK_PLAINTEXT_BYTES.toInt())
            var read = 0L
            var chunkIndex = 0L
            try {
                source.openStream().use { input ->
                    while (read < source.sizeBytes) {
                        val chunkBytes = minOf(buffer.size.toLong(), source.sizeBytes - read).toInt()
                        readFully(input, buffer, chunkBytes)
                        val plaintext = if (chunkBytes == buffer.size) buffer else buffer.copyOf(chunkBytes)
                        val record = try {
                            encryptor.encryptChunk(chunkIndex.toUInt(), plaintext)
                        } finally {
                            plaintext.fill(0)
                        }
                        try {
                            if (record.size.toLong() != ATTACHMENT_CHUNK_RECORD_BYTES ||
                                record.firstOrNull()?.toInt() != AttachmentProtocol.CIPHER_VERSION
                            ) throw IOException("Attachment unavailable")
                            consumer(record)
                        } finally {
                            record.fill(0)
                        }
                        read += chunkBytes
                        chunkIndex += 1L
                    }
                    if (input.read() >= 0 || chunkIndex.toUInt() != encryptor.chunkCount()) {
                        throw IOException("Attachment unavailable")
                    }
                }
            } finally {
                buffer.fill(0)
            }
        }
    }

    private companion object {
        const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        const val LEGACY_EXPORT_KEY_ALIAS = "abyssal_attachment_export_v1"
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

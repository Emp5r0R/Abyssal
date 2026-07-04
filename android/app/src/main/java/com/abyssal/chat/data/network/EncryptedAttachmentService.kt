package com.abyssal.chat.data.network

import android.content.Context
import android.net.Uri
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.abyssal.chat.domain.model.AttachmentUploadResult
import com.abyssal.chat.domain.model.DecryptedAttachment
import com.abyssal.chat.domain.repository.IEncryptedAttachmentService
import com.abyssal.chat.domain.repository.INodeConfigService
import java.io.IOException
import java.net.URLEncoder
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.MediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okio.BufferedSink
import org.json.JSONObject

class EncryptedAttachmentService(
    private val appContext: Context,
    private val nodeConfigService: INodeConfigService,
    private val client: OkHttpClient
) : IEncryptedAttachmentService {

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
                val json = response.body?.string()?.takeIf { it.isNotBlank() }?.let { JSONObject(it) }
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
                response.body?.bytes()
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
            val exportBytes = encryptForExplicitExport(attachment)
            appContext.contentResolver.openOutputStream(outputUri, "w")?.use { output ->
                output.write(exportBytes)
                output.flush()
            } != null
        } catch (e: Exception) {
            false
        }
    }

    private fun encryptForExplicitExport(attachment: DecryptedAttachment): ByteArray {
        val key = getOrCreateExportKey()
        val nonce = ByteArray(GCM_NONCE_BYTES).also { SecureRandom().nextBytes(it) }
        val metadata = JSONObject()
            .put("version", 1)
            .put("name", attachment.name)
            .put("media_type", attachment.mediaType)
            .put("mime_type", attachment.mimeType)
            .put("created_at_ms", System.currentTimeMillis())
            .toString()
            .toByteArray(StandardCharsets.UTF_8)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, nonce))
        cipher.updateAAD(metadata)
        val ciphertext = cipher.doFinal(attachment.bytes)

        return ByteBuffer.allocate(EXPORT_MAGIC.size + 4 + nonce.size + 4 + metadata.size + ciphertext.size)
            .put(EXPORT_MAGIC)
            .putInt(nonce.size)
            .put(nonce)
            .putInt(metadata.size)
            .put(metadata)
            .put(ciphertext)
            .array()
    }

    private fun getOrCreateExportKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (keyStore.getKey(EXPORT_KEY_ALIAS, null) as? SecretKey)?.let { return it }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val builder = KeyGenParameterSpec.Builder(
            EXPORT_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            runCatching {
                generator.init(builder.setIsStrongBoxBacked(true).build())
                generator.generateKey()
            }.getOrElse {
                generator.init(builder.setIsStrongBoxBacked(false).build())
                generator.generateKey()
            }
        } else {
            generator.init(builder.build())
            generator.generateKey()
        }

        return KeyStore.getInstance(ANDROID_KEYSTORE)
            .apply { load(null) }
            .getKey(EXPORT_KEY_ALIAS, null) as SecretKey
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
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val EXPORT_KEY_ALIAS = "abyssal_explicit_attachment_export_v1"
        const val GCM_NONCE_BYTES = 12
        const val GCM_TAG_BITS = 128
        val EXPORT_MAGIC = "ABYSSAL-EXPORT-V1\n".toByteArray(StandardCharsets.US_ASCII)
    }
}

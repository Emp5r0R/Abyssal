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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject

class EncryptedAttachmentService(
    private val appContext: Context,
    private val nodeConfigService: INodeConfigService,
    private val client: OkHttpClient
) : IEncryptedAttachmentService {

    override suspend fun uploadEncryptedAttachment(
        chatId: String,
        encryptedBytes: ByteArray,
        oneTimeView: Boolean,
        deleteAfterDownload: Boolean,
        ttlSec: Int
    ): AttachmentUploadResult = withContext(Dispatchers.IO) {
        val session = nodeConfigService.getActiveSession() ?: return@withContext AttachmentUploadResult(false)
        val query = listOf(
            "chat_id" to chatId,
            "one_time" to oneTimeView.toString(),
            "delete_after_download" to deleteAfterDownload.toString(),
            "ttl_sec" to ttlSec.coerceAtLeast(0).toString()
        ).joinToString("&") { (key, value) ->
            "${key}=${URLEncoder.encode(value, StandardCharsets.UTF_8.name())}"
        }
        val body = encryptedBytes.toRequestBody("application/octet-stream".toMediaType())
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
            appContext.contentResolver.openOutputStream(outputUri, "w")?.use { output ->
                output.write(attachment.bytes)
                output.flush()
            } != null
        } catch (e: Exception) {
            false
        }
    }
}

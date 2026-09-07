package com.abyssal.chat.data.network

import org.json.JSONObject

internal object AttachmentUploadEnvelope {
    const val PREFIX_BYTES = 1024

    fun encode(
        chatId: String, messageId: String, mediaType: String,
        oneTime: Boolean, deleteAfterDownload: Boolean, ttlSec: Int
    ): ByteArray {
        require(chatId.matches(Regex("[A-Za-z0-9_-]{1,128}")) &&
            messageId.matches(Regex("[A-Za-z0-9_-]{1,128}")) &&
            mediaType in setOf("IMAGE", "VIDEO", "FILE"))
        val json = JSONObject().put("chat_id", chatId).put("message_id", messageId)
            .put("media_type", mediaType).put("one_time", oneTime)
            .put("delete_after_download", deleteAfterDownload || oneTime)
            .put("ttl_sec", ttlSec.coerceAtLeast(0)).toString().toByteArray(Charsets.UTF_8)
        return try {
            require(json.size in 1..PREFIX_BYTES - 10)
            ByteArray(PREFIX_BYTES).apply {
                "ABYUP001".toByteArray(Charsets.US_ASCII).copyInto(this)
                this[8] = (json.size ushr 8).toByte()
                this[9] = json.size.toByte()
                json.copyInto(this, 10)
            }
        } finally { json.fill(0) }
    }
}

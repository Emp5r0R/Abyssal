package com.abyssal.chat.domain.model

import org.json.JSONArray
import org.json.JSONObject
import java.util.Base64

/**
 * What Android keeps on disk when the relay allows device storage: messages
 * per conversation (with attachment keys, so attachments stay viewable while
 * the relay holds them), room names, and display names of contacts. Rooms and
 * direct chats themselves come back from the relay's catalog after sign-in.
 *
 * Decoding is strict and bounded; anything malformed is dropped, never
 * partially trusted. Expired messages are not restored.
 */
data class DeviceStoreSnapshot(
    val messages: Map<String, List<Message>>,
    val roomNames: Map<String, String>,
    val displayNames: Map<String, String>
) {
    companion object {
        const val VERSION = 1
        const val MAX_CHATS = 512
        const val MAX_MESSAGES_PER_CHAT = 500
        const val MAX_MESSAGES_TOTAL = 5_000
        private const val MAX_TEXT_CHARS = 8_000
        private val ID = Regex("^[A-Za-z0-9_-]{1,128}$")
        private val MEDIA_TYPES = setOf("IMAGE", "VIDEO", "FILE")

        fun encode(snapshot: DeviceStoreSnapshot): ByteArray {
            val chats = JSONObject()
            var total = 0
            snapshot.messages.entries.take(MAX_CHATS).forEach { (chatId, list) ->
                if (!ID.matches(chatId)) return@forEach
                val kept = list.filterNot { it.isExpired }.takeLast(MAX_MESSAGES_PER_CHAT)
                    .take((MAX_MESSAGES_TOTAL - total).coerceAtLeast(0))
                total += kept.size
                if (kept.isNotEmpty()) chats.put(chatId, JSONArray().apply { kept.forEach { put(encodeMessage(it)) } })
            }
            val json = JSONObject()
                .put("version", VERSION)
                .put("messages", chats)
                .put("room_names", JSONObject(snapshot.roomNames.filterKeys(ID::matches).entries.take(MAX_CHATS).associate { it.key to it.value.take(36) }))
                .put("display_names", JSONObject(snapshot.displayNames.entries.take(MAX_KNOWN_DISPLAY_NAMES).associate { it.key to it.value.take(64) }))
            return json.toString().toByteArray(Charsets.UTF_8)
        }

        /** Returns null for anything that is not a well-formed snapshot of this version. */
        fun decode(bytes: ByteArray, nowMs: Long = System.currentTimeMillis()): DeviceStoreSnapshot? = runCatching {
            val json = JSONObject(String(bytes, Charsets.UTF_8))
            if (json.optInt("version", -1) != VERSION) return null
            val chats = json.getJSONObject("messages")
            require(chats.length() <= MAX_CHATS)
            var total = 0
            val messages = LinkedHashMap<String, List<Message>>()
            chats.keys().forEach { chatId ->
                require(ID.matches(chatId))
                val array = chats.getJSONArray(chatId)
                require(array.length() <= MAX_MESSAGES_PER_CHAT)
                total += array.length()
                require(total <= MAX_MESSAGES_TOTAL)
                val list = (0 until array.length()).map { decodeMessage(array.getJSONObject(it)) }
                    .filterNot { it.isExpiredAt(nowMs) }
                if (list.isNotEmpty()) messages[chatId] = list
            }
            DeviceStoreSnapshot(
                messages = messages,
                roomNames = stringMap(json.getJSONObject("room_names"), MAX_CHATS, 36).filterKeys(ID::matches),
                displayNames = stringMap(json.getJSONObject("display_names"), MAX_KNOWN_DISPLAY_NAMES, 64)
            )
        }.getOrNull()

        private fun Message.isExpiredAt(nowMs: Long): Boolean {
            val absolute = absoluteExpirySec > 0 && nowMs - timestampMs >= absoluteExpirySec * 1000L
            val read = readTimestampMs?.takeIf { selfDestructDurationSec > 0 }?.let { nowMs - it >= selfDestructDurationSec * 1000L } ?: false
            return absolute || read
        }

        private fun stringMap(json: JSONObject, maxEntries: Int, maxChars: Int): Map<String, String> {
            require(json.length() <= maxEntries)
            val out = LinkedHashMap<String, String>()
            json.keys().forEach { key ->
                val value = json.getString(key)
                require(key.length <= 128 && value.length <= maxChars)
                out[key] = value
            }
            return out
        }

        private fun encodeMessage(m: Message): JSONObject = JSONObject()
            .put("id", m.id)
            .put("sender", m.sender)
            .put("receiver", m.receiver ?: JSONObject.NULL)
            .put("content", m.content)
            .put("timestamp_ms", m.timestampMs)
            .put("self_destruct_sec", m.selfDestructDurationSec)
            .put("read_ms", m.readTimestampMs ?: JSONObject.NULL)
            .put("absolute_expiry_sec", m.absoluteExpirySec)
            .put("is_media", m.isMedia)
            .put("media_type", m.mediaType ?: JSONObject.NULL)
            .put("attachment_id", m.attachmentId ?: JSONObject.NULL)
            .put("attachment_cipher_version", m.attachmentCipherVersion)
            .put("attachment_key_b64", m.attachmentKey?.let { Base64.getUrlEncoder().withoutPadding().encodeToString(it) } ?: JSONObject.NULL)
            .put("attachment_name", m.attachmentName ?: JSONObject.NULL)
            .put("attachment_mime_type", m.attachmentMimeType ?: JSONObject.NULL)
            .put("attachment_size_bytes", m.attachmentSizeBytes)
            .put("one_time", m.oneTimeView)
            .put("delete_after_download", m.deleteAfterDownload)
            .put("reply_to_id", m.replyToMessageId ?: JSONObject.NULL)
            .put("reaction_shortcode", m.reactionShortcode ?: JSONObject.NULL)
            .put("mentions_you", m.mentionsCurrentUser)
            .put("replies_to_you", m.repliesToCurrentUser)
            .put("sender_client", m.senderClient.wireName)
            .put("sender_display_name", m.senderDisplayName ?: JSONObject.NULL)
            .put("reactions", JSONObject(m.reactions.mapValues { JSONArray(it.value) }))
            .put("edited_ms", m.editedAtMs ?: JSONObject.NULL)
            .put("voice_ms", m.voiceDurationMs ?: JSONObject.NULL)

        private fun decodeMessage(j: JSONObject): Message {
            fun optString(name: String, max: Int): String? = if (j.isNull(name)) null else j.getString(name).also { require(it.length <= max) }
            fun optLong(name: String): Long? = if (j.isNull(name)) null else j.getLong(name)
            val id = j.getString("id").also { require(ID.matches(it)) }
            val mediaType = optString("media_type", 8)?.also { require(it in MEDIA_TYPES) }
            val key = optString("attachment_key_b64", 64)?.let { Base64.getUrlDecoder().decode(it) }
            val reactionsJson = j.getJSONObject("reactions")
            val reactions = LinkedHashMap<String, List<String>>()
            reactionsJson.keys().forEach { emoji ->
                require(emoji in MessageActionCodec.REACTION_EMOJI)
                val people = reactionsJson.getJSONArray(emoji)
                require(people.length() <= MessageActionPolicy.MAX_REACTORS_PER_EMOJI)
                reactions[emoji] = (0 until people.length()).map { people.getString(it).also { name -> require(name.length <= 128) } }
            }
            return Message(
                id = id,
                sender = j.getString("sender").also { require(it.length <= 128) },
                receiver = optString("receiver", 128),
                content = j.getString("content").also { require(it.length <= MAX_TEXT_CHARS) },
                timestampMs = j.getLong("timestamp_ms"),
                selfDestructDurationSec = j.getInt("self_destruct_sec").also { require(it in 0..86_400) },
                readTimestampMs = optLong("read_ms"),
                isMedia = j.getBoolean("is_media"),
                mediaType = mediaType,
                attachmentId = optString("attachment_id", 128),
                attachmentCipherVersion = j.getInt("attachment_cipher_version"),
                attachmentKey = key,
                attachmentName = optString("attachment_name", 160),
                attachmentMimeType = optString("attachment_mime_type", 120),
                attachmentSizeBytes = j.getLong("attachment_size_bytes"),
                oneTimeView = j.getBoolean("one_time"),
                saveAllowed = !j.getBoolean("one_time"),
                deleteAfterDownload = j.getBoolean("delete_after_download"),
                absoluteExpirySec = j.getInt("absolute_expiry_sec").also { require(it >= 0) },
                replyToMessageId = optString("reply_to_id", 128),
                reactionShortcode = optString("reaction_shortcode", 80),
                mentionsCurrentUser = j.getBoolean("mentions_you"),
                repliesToCurrentUser = j.getBoolean("replies_to_you"),
                senderClient = SenderClient.fromWire(j.getString("sender_client")) ?: SenderClient.ANDROID,
                senderDisplayName = optString("sender_display_name", 64),
                reactions = reactions,
                editedAtMs = optLong("edited_ms"),
                voiceDurationMs = optLong("voice_ms")?.coerceIn(0L, VoiceNotes.MAX_DURATION_MS)
            )
        }
    }
}

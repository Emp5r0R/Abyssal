package com.abyssal.chat.data.network

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class AttachmentUploadEnvelopeTest {
    @Test
    fun fixedPrefixContainsOnlyBoundedMetadataAndZeroPadding() {
        val prefix = AttachmentUploadEnvelope.encode("dm_Alice_Bob", "message", "FILE", true, false, -1)
        assertEquals(1024, prefix.size)
        assertEquals("ABYUP001", String(prefix, 0, 8, Charsets.US_ASCII))
        val length = ((prefix[8].toInt() and 255) shl 8) or (prefix[9].toInt() and 255)
        val metadata = JSONObject(String(prefix, 10, length, Charsets.UTF_8))
        assertEquals(6, metadata.length())
        assertEquals("dm_Alice_Bob", metadata.getString("chat_id"))
        assertEquals("message", metadata.getString("message_id"))
        assertEquals("FILE", metadata.getString("media_type"))
        assertTrue(metadata.getBoolean("one_time"))
        assertTrue(metadata.getBoolean("delete_after_download"))
        assertEquals(0, metadata.getInt("ttl_sec"))
        assertTrue(prefix.drop(10 + length).all { it == 0.toByte() })
    }

    @Test
    fun invalidOrOversizedMetadataFailsBeforeEncoding() {
        for (chat in listOf("", "a".repeat(129), "dm/secret", "dm\u0000secret")) {
            assertThrows(IllegalArgumentException::class.java) {
                AttachmentUploadEnvelope.encode(chat, "message", "FILE", false, false, 0)
            }
        }
        assertThrows(IllegalArgumentException::class.java) {
            AttachmentUploadEnvelope.encode("dm_chat", "message", "image/jpeg", false, false, 0)
        }
    }
}

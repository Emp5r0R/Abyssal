package com.abyssal.chat.data.network

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.abyssal_core.decryptAttachment
import uniffi.abyssal_core.encryptAttachment

class StatelessAttachmentCipherTest {
    @Test
    fun attachmentRoundTripBindsMessageContextAndMediaType() {
        val plaintext = "attachment payload".encodeToByteArray()
        val encrypted = encryptAttachment(
            chatId = CHAT_ID,
            messageId = MESSAGE_ID,
            senderUsername = SENDER,
            mediaType = MEDIA_TYPE,
            plaintext = plaintext
        )
        val key = encrypted.key
        val blob = encrypted.blob

        try {
            assertEquals(2u, encrypted.version)
            assertArrayEquals(
                plaintext,
                decryptAttachment(
                    chatId = CHAT_ID,
                    messageId = MESSAGE_ID,
                    senderUsername = SENDER,
                    mediaType = MEDIA_TYPE,
                    key = key,
                    blob = blob
                )
            )
            assertTrue(runCatching {
                decryptAttachment(
                    chatId = CHAT_ID,
                    messageId = OTHER_MESSAGE_ID,
                    senderUsername = SENDER,
                    mediaType = MEDIA_TYPE,
                    key = key,
                    blob = blob
                )
            }.isFailure)
            assertTrue(runCatching {
                decryptAttachment(
                    chatId = CHAT_ID,
                    messageId = MESSAGE_ID,
                    senderUsername = SENDER,
                    mediaType = "IMAGE",
                    key = key,
                    blob = blob
                )
            }.isFailure)
        } finally {
            plaintext.fill(0)
            key.fill(0)
            blob.fill(0)
        }
    }

    @Test
    fun attachmentCipherRejectsKeyAndBlobTampering() {
        val plaintext = byteArrayOf(1, 2, 3, 4, 5)
        val encrypted = encryptAttachment(
            chatId = CHAT_ID,
            messageId = MESSAGE_ID,
            senderUsername = SENDER,
            mediaType = MEDIA_TYPE,
            plaintext = plaintext
        )
        val key = encrypted.key
        val blob = encrypted.blob
        val wrongKey = key.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        val tamperedBlob = blob.copyOf().also {
            it[it.lastIndex] = (it[it.lastIndex].toInt() xor 1).toByte()
        }

        try {
            assertTrue(runCatching {
                decryptAttachment(
                    chatId = CHAT_ID,
                    messageId = MESSAGE_ID,
                    senderUsername = SENDER,
                    mediaType = MEDIA_TYPE,
                    key = wrongKey,
                    blob = blob
                )
            }.isFailure)
            assertTrue(runCatching {
                decryptAttachment(
                    chatId = CHAT_ID,
                    messageId = MESSAGE_ID,
                    senderUsername = SENDER,
                    mediaType = MEDIA_TYPE,
                    key = key,
                    blob = tamperedBlob
                )
            }.isFailure)
        } finally {
            plaintext.fill(0)
            key.fill(0)
            blob.fill(0)
            wrongKey.fill(0)
            tamperedBlob.fill(0)
        }
    }

    private companion object {
        const val CHAT_ID = "dm_bob"
        const val MESSAGE_ID = "5dbf06b8-fca4-46c4-8f26-5589e7024d94"
        const val OTHER_MESSAGE_ID = "6ec017c9-0db5-47d5-9f37-667715134e05"
        const val SENDER = "Alice"
        const val MEDIA_TYPE = "FILE"
    }
}

package com.abyssal.chat.data.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import javax.crypto.KeyGenerator

class AttachmentCryptographyTest {

    @Test
    fun messageEncryptionAndDecryptionAcrossDMsAndRooms() {
        val senderCipher = InMemoryPayloadCipher()
        val receiverCipher = InMemoryPayloadCipher()

        // Derive keys from the same Node ID
        senderCipher.deriveSessionKey("abyssal-node-xyz")
        receiverCipher.deriveSessionKey("abyssal-node-xyz")

        // 1. Private Room message payload (prefix: forum_)
        val roomMessage = "Room broadcast payload text"
        val encryptedRoomMsg = senderCipher.encrypt("forum_ops", roomMessage)
        assertNotEquals(roomMessage, encryptedRoomMsg)
        assertEquals(roomMessage, receiverCipher.decrypt("forum_ops", encryptedRoomMsg))

        // 2. DM message payload (prefix: dm_)
        val dmMessage = "Private 1-on-1 direct message"
        val encryptedDMMsg = senderCipher.encrypt("dm_random", dmMessage)
        assertNotEquals(dmMessage, encryptedDMMsg)
        assertEquals(dmMessage, receiverCipher.decrypt("dm_random", encryptedDMMsg))
    }

    @Test
    fun attachmentDataPreEncryptionAndDecryptionRoundtrip() {
        val cipher = InMemoryPayloadCipher()
        cipher.deriveSessionKey("active-node-id")

        val documentBytes = byteArrayOf(10, 20, 30, 40, 50, 60, 70, 80)

        // 1. Client-Side Pre-Encryption: attachment bytes are encrypted before upload
        val encryptedBytes = cipher.encryptBytes("forum_docs", documentBytes)
        assertNotEquals(documentBytes.toList(), encryptedBytes.toList())

        // 2. Direct Download (stored/downloaded bytes remain encrypted)
        val downloadedBytes = encryptedBytes.clone()
        assertTrue(encryptedBytes.contentEquals(downloadedBytes))

        // 3. View/Access: decrypted in-memory using derived session key
        val decryptedBytes = cipher.decryptBytes("forum_docs", downloadedBytes)
        assertTrue(documentBytes.contentEquals(decryptedBytes))
    }

    @Test
    fun keystoreExportEnvelopeRoundTripsAndRejectsTampering() {
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(256)
        val secretKey = keyGenerator.generateKey()

        val pdfBytes = "PDF file content bytes".toByteArray(Charsets.UTF_8)
        val encrypted = AttachmentExportCipher.encrypt(secretKey, pdfBytes)
        val decrypted = AttachmentExportCipher.decrypt(secretKey, encrypted)

        assertNotEquals(pdfBytes.toList(), encrypted.toList())
        assertTrue(pdfBytes.contentEquals(decrypted))
        assertEquals("PDF file content bytes", String(decrypted, Charsets.UTF_8))

        encrypted[encrypted.lastIndex] = (encrypted.last() + 1).toByte()
        assertTrue(runCatching { AttachmentExportCipher.decrypt(secretKey, encrypted) }.isFailure)
    }
}

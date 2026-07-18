package com.abyssal.chat.data.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec

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
        val encryptedRoomMsg = senderCipher.encrypt(roomMessage)
        assertNotEquals(roomMessage, encryptedRoomMsg)
        assertEquals(roomMessage, receiverCipher.decrypt(encryptedRoomMsg))

        // 2. DM message payload (prefix: dm_)
        val dmMessage = "Private 1-on-1 direct message"
        val encryptedDMMsg = senderCipher.encrypt(dmMessage)
        assertNotEquals(dmMessage, encryptedDMMsg)
        assertEquals(dmMessage, receiverCipher.decrypt(encryptedDMMsg))
    }

    @Test
    fun attachmentDataPreEncryptionAndDecryptionRoundtrip() {
        val cipher = InMemoryPayloadCipher()
        cipher.deriveSessionKey("active-node-id")

        val documentBytes = byteArrayOf(10, 20, 30, 40, 50, 60, 70, 80)

        // 1. Client-Side Pre-Encryption: attachment bytes are encrypted before upload
        val encryptedBytes = cipher.encryptBytes(documentBytes)
        assertNotEquals(documentBytes.toList(), encryptedBytes.toList())

        // 2. Direct Download (stored/downloaded bytes remain encrypted)
        val downloadedBytes = encryptedBytes.clone()
        assertTrue(encryptedBytes.contentEquals(downloadedBytes))

        // 3. View/Access: decrypted in-memory using derived session key
        val decryptedBytes = cipher.decryptBytes(downloadedBytes)
        assertTrue(documentBytes.contentEquals(decryptedBytes))
    }

    @Test
    fun simulateKeystoreExportCryptographicRoundtrip() {
        // Since Android Keystore is unavailable in local JVM tests, we verify the AES-GCM
        // cryptographic implementation that underpins the keystore-based attachment export.
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(256)
        val secretKey = keyGenerator.generateKey()

        val pdfBytes = "PDF file content bytes".toByteArray(Charsets.UTF_8)
        val nonce = ByteArray(12).also { SecureRandom().nextBytes(it) }

        // Encrypt simulated PDF attachment
        val encryptCipher = Cipher.getInstance("AES/GCM/NoPadding")
        encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(128, nonce))
        val ciphertext = encryptCipher.doFinal(pdfBytes)

        assertNotEquals(pdfBytes.toList(), ciphertext.toList())

        // Decrypt simulated PDF attachment
        val decryptCipher = Cipher.getInstance("AES/GCM/NoPadding")
        decryptCipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, nonce))
        val decrypted = decryptCipher.doFinal(ciphertext)

        assertTrue(pdfBytes.contentEquals(decrypted))
        assertEquals("PDF file content bytes", String(decrypted, Charsets.UTF_8))
    }
}

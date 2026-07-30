package com.abyssal.chat.data.network

import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import javax.crypto.KeyGenerator

class AttachmentCryptographyTest {

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
        assertTrue("PDF file content bytes" == String(decrypted, Charsets.UTF_8))

        encrypted[encrypted.lastIndex] = (encrypted.last() + 1).toByte()
        assertTrue(runCatching { AttachmentExportCipher.decrypt(secretKey, encrypted) }.isFailure)
    }
}

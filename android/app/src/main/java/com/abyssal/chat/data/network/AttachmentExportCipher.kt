package com.abyssal.chat.data.network

import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

object AttachmentExportCipher {
    private val magic = "ABYSSAL_EXPORT_V1\u0000".toByteArray(Charsets.US_ASCII)
    private const val nonceBytes = 12

    fun encrypt(key: SecretKey, plainBytes: ByteArray): ByteArray {
        val nonce = ByteArray(nonceBytes).also(SecureRandom()::nextBytes)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, nonce))
        cipher.updateAAD(magic)
        val ciphertext = cipher.doFinal(plainBytes)
        return ByteBuffer.allocate(magic.size + nonce.size + ciphertext.size)
            .put(magic)
            .put(nonce)
            .put(ciphertext)
            .array()
    }

    fun decrypt(key: SecretKey, exportBytes: ByteArray): ByteArray {
        require(exportBytes.size > magic.size + nonceBytes + 16) { "Export unavailable." }
        require(exportBytes.copyOfRange(0, magic.size).contentEquals(magic)) { "Export unavailable." }
        val nonce = exportBytes.copyOfRange(magic.size, magic.size + nonceBytes)
        val ciphertext = exportBytes.copyOfRange(magic.size + nonceBytes, exportBytes.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, nonce))
        cipher.updateAAD(magic)
        return try {
            cipher.doFinal(ciphertext)
        } finally {
            nonce.fill(0)
            ciphertext.fill(0)
        }
    }
}

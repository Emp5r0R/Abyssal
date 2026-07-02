package com.abyssal.chat.data.network

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Locale
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class InMemoryPayloadCipher {
    private var key: SecretKey? = null
    private val random = SecureRandom()

    fun deriveSessionKey(nodeId: String) {
        val material = "ABYSSAL_NODE_PAYLOAD_V1:${normalize(nodeId)}"
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(material.toByteArray(Charsets.UTF_8))
        key = SecretKeySpec(digest, "AES")
    }

    fun encrypt(plainText: String): ByteArray {
        return encryptBytes(plainText.toByteArray(Charsets.UTF_8))
    }

    fun decrypt(payload: ByteArray): String {
        return String(decryptBytes(payload), Charsets.UTF_8)
    }

    fun encryptBytes(plainBytes: ByteArray): ByteArray {
        val nonce = ByteArray(12)
        random.nextBytes(nonce)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, requireKey(), GCMParameterSpec(128, nonce))
        val ciphertext = cipher.doFinal(plainBytes)
        return nonce + ciphertext
    }

    fun decryptBytes(payload: ByteArray): ByteArray {
        require(payload.size > NONCE_SIZE_BYTES) { "Encrypted payload is too short." }
        val nonce = payload.copyOfRange(0, NONCE_SIZE_BYTES)
        val ciphertext = payload.copyOfRange(NONCE_SIZE_BYTES, payload.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, requireKey(), GCMParameterSpec(128, nonce))
        return cipher.doFinal(ciphertext)
    }

    fun clear() {
        key = null
    }

    private fun requireKey(): SecretKey {
        return key ?: throw IllegalStateException("Payload cipher is not initialized.")
    }

    private fun normalize(value: String): String {
        return value.trim().uppercase(Locale.ROOT)
    }

    private companion object {
        const val NONCE_SIZE_BYTES = 12
    }
}

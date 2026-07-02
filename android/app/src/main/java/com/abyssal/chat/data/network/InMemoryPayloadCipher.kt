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

    fun deriveSessionKey(inviteCode: String, nodeId: String, password: String) {
        val material = "${normalize(inviteCode)}:${normalize(nodeId)}:${password}"
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(material.toByteArray(Charsets.UTF_8))
        key = SecretKeySpec(digest, "AES")
    }

    fun encrypt(plainText: String): ByteArray {
        val nonce = ByteArray(12)
        random.nextBytes(nonce)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, requireKey(), GCMParameterSpec(128, nonce))
        val ciphertext = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))
        return nonce + ciphertext
    }

    fun decrypt(payload: ByteArray): String {
        require(payload.size > NONCE_SIZE_BYTES) { "Encrypted payload is too short." }
        val nonce = payload.copyOfRange(0, NONCE_SIZE_BYTES)
        val ciphertext = payload.copyOfRange(NONCE_SIZE_BYTES, payload.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, requireKey(), GCMParameterSpec(128, nonce))
        return String(cipher.doFinal(ciphertext), Charsets.UTF_8)
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

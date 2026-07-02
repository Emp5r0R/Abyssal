package com.abyssal.chat.data.network

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class InMemoryPayloadCipher {
    private val key: SecretKey = KeyGenerator.getInstance("AES").run {
        init(256)
        generateKey()
    }
    private val random = SecureRandom()

    fun encrypt(plainText: String): ByteArray {
        val nonce = ByteArray(12)
        random.nextBytes(nonce)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, nonce))
        val ciphertext = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))
        return nonce + ciphertext
    }
}

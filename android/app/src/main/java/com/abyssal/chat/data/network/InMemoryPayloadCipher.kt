package com.abyssal.chat.data.network

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Locale
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class InMemoryPayloadCipher {
    private var nodeSecret: ByteArray? = null
    private val random = SecureRandom()

    fun deriveSessionKey(nodeId: String) {
        clear()
        val normalized = normalizeNodeId(nodeId)
        require(normalized.isNotEmpty() && normalized.toByteArray(Charsets.UTF_8).size <= MAX_NODE_ID_BYTES) {
            "Node identity unavailable."
        }
        val material = "ABYSSAL_NODE_SECRET_V2:$normalized".toByteArray(Charsets.UTF_8)
        try {
            nodeSecret = MessageDigest.getInstance("SHA-256").digest(material)
        } finally {
            material.fill(0)
        }
    }

    fun encrypt(chatId: String, plainText: String): ByteArray {
        val plainBytes = plainText.toByteArray(Charsets.UTF_8)
        return try {
            encryptBytes(chatId, plainBytes)
        } finally {
            plainBytes.fill(0)
        }
    }

    fun decrypt(chatId: String, payload: ByteArray): String {
        val plainBytes = decryptBytes(chatId, payload)
        return try {
            String(plainBytes, Charsets.UTF_8)
        } finally {
            plainBytes.fill(0)
        }
    }

    fun encryptBytes(chatId: String, plainBytes: ByteArray): ByteArray {
        val normalizedChatId = normalizeChatId(chatId)
        val nonce = ByteArray(12)
        random.nextBytes(nonce)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, conversationKey(normalizedChatId), GCMParameterSpec(128, nonce))
        val aad = additionalData(normalizedChatId)
        return try {
            cipher.updateAAD(aad)
            val ciphertext = cipher.doFinal(plainBytes)
            byteArrayOf(PAYLOAD_VERSION) + nonce + ciphertext
        } finally {
            aad.fill(0)
        }
    }

    fun decryptBytes(chatId: String, payload: ByteArray): ByteArray {
        val normalizedChatId = normalizeChatId(chatId)
        require(payload.size > VERSION_BYTES + NONCE_SIZE_BYTES && payload[0] == PAYLOAD_VERSION) {
            "Encrypted payload is unavailable."
        }
        val nonce = payload.copyOfRange(VERSION_BYTES, VERSION_BYTES + NONCE_SIZE_BYTES)
        val ciphertext = payload.copyOfRange(VERSION_BYTES + NONCE_SIZE_BYTES, payload.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, conversationKey(normalizedChatId), GCMParameterSpec(128, nonce))
        val aad = additionalData(normalizedChatId)
        return try {
            cipher.updateAAD(aad)
            cipher.doFinal(ciphertext)
        } finally {
            aad.fill(0)
            nonce.fill(0)
            ciphertext.fill(0)
        }
    }

    fun clear() {
        nodeSecret?.fill(0)
        nodeSecret = null
    }

    private fun conversationKey(chatId: String): SecretKey {
        val secret = nodeSecret ?: throw IllegalStateException("Payload cipher is not initialized.")
        val prefix = "ABYSSAL_CONVERSATION_KEY_V2:".toByteArray(Charsets.UTF_8)
        val suffix = ":$chatId".toByteArray(Charsets.UTF_8)
        val material = prefix + secret + suffix
        val digest = MessageDigest.getInstance("SHA-256").digest(material)
        material.fill(0)
        return SecretKeySpec(digest, "AES").also { digest.fill(0) }
    }

    private fun normalizeNodeId(value: String): String {
        return value.trim().uppercase(Locale.ROOT)
    }

    private fun normalizeChatId(value: String): String {
        val normalized = value.trim()
        require(CHAT_ID_REGEX.matches(normalized)) { "Conversation unavailable." }
        return normalized
    }

    private fun additionalData(chatId: String): ByteArray {
        return "ABYSSAL_CONVERSATION_PAYLOAD_V2:$chatId".toByteArray(Charsets.UTF_8)
    }

    private companion object {
        const val PAYLOAD_VERSION: Byte = 2
        const val VERSION_BYTES = 1
        const val NONCE_SIZE_BYTES = 12
        const val MAX_NODE_ID_BYTES = 128
        val CHAT_ID_REGEX = Regex("^[A-Za-z0-9_-]{1,128}$")
    }
}

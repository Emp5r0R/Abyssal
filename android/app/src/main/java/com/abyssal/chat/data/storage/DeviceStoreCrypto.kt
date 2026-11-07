package com.abyssal.chat.data.storage

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Key derivation and sealing for the on-device store. The store key needs
 * both the relay's RAM-only share and the device's Keystore-protected local
 * secret: losing either (relay restart or wipe, Keystore key deleted) makes
 * every saved file permanently unreadable.
 */
internal object DeviceStoreCrypto {
    const val KEY_BYTES = 32
    private const val VERSION: Byte = 1
    private const val NONCE_BYTES = 12
    private const val TAG_BITS = 128
    private val DOMAIN = "abyssal-device-store-v1".toByteArray(Charsets.US_ASCII)

    /** HKDF-SHA256 over the local secret and relay share, bound to the node and account. */
    fun deriveKey(localSecret: ByteArray, relayShare: ByteArray, nodeId: String, username: String): ByteArray {
        require(localSecret.size == KEY_BYTES && relayShare.size == KEY_BYTES)
        val ikm = localSecret + relayShare
        val prk = hmac(DOMAIN, ikm)
        return try {
            hmac(prk, context(nodeId, username) + byteArrayOf(1)).copyOf(KEY_BYTES)
        } finally {
            ikm.fill(0)
            prk.fill(0)
        }
    }

    /** Authenticated data binding a sealed file to its node and account. */
    fun context(nodeId: String, username: String): ByteArray =
        DOMAIN + byteArrayOf(0) + nodeId.toByteArray(Charsets.UTF_8) + byteArrayOf(0) + username.lowercase().toByteArray(Charsets.UTF_8)

    /** File name prefix for one relay node; reveals neither node nor account. */
    fun nodePrefix(nodeId: String): String = hex(DOMAIN + byteArrayOf(0) + nodeId.toByteArray(Charsets.UTF_8)) + "-"

    /** A file name that does not reveal the node or account, grouped by node. */
    fun fileName(nodeId: String, username: String): String = nodePrefix(nodeId) + hex(context(nodeId, username)) + ".store"

    private fun hex(data: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(data).take(8).joinToString("") { "%02x".format(it) }

    fun seal(key: ByteArray, plaintext: ByteArray, aad: ByteArray, random: SecureRandom = SecureRandom()): ByteArray {
        val nonce = ByteArray(NONCE_BYTES).also(random::nextBytes)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
        cipher.updateAAD(aad)
        return byteArrayOf(VERSION) + nonce + cipher.doFinal(plaintext)
    }

    /** The plaintext, or null if the data was not sealed under this key and context. */
    fun open(key: ByteArray, sealed: ByteArray, aad: ByteArray): ByteArray? {
        if (sealed.size < 1 + NONCE_BYTES + TAG_BITS / 8 || sealed[0] != VERSION) return null
        return runCatching {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, sealed, 1, NONCE_BYTES))
            cipher.updateAAD(aad)
            cipher.doFinal(sealed, 1 + NONCE_BYTES, sealed.size - 1 - NONCE_BYTES)
        }.getOrNull()
    }

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(key, "HmacSHA256"))
            doFinal(data)
        }
}

package com.abyssal.chat.data.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class InMemoryPayloadCipherTest {
    @Test
    fun sameNodeDecryptsPayloadAcrossAccounts() {
        val sender = InMemoryPayloadCipher()
        val receiver = InMemoryPayloadCipher()
        sender.deriveSessionKey("oracle-1")
        receiver.deriveSessionKey("ORACLE-1")

        val encrypted = sender.encrypt("forum_general", "hello from RAM")

        assertEquals("hello from RAM", receiver.decrypt("forum_general", encrypted))
    }

    @Test
    fun differentNodeCannotDecryptPayload() {
        val sender = InMemoryPayloadCipher()
        val receiver = InMemoryPayloadCipher()
        sender.deriveSessionKey("oracle-1")
        receiver.deriveSessionKey("oracle-2")

        val encrypted = sender.encrypt("forum_general", "secret")
        val failed = runCatching { receiver.decrypt("forum_general", encrypted) }.isFailure

        assertTrue(failed)
    }

    @Test
    fun encryptedBytesRoundTrip() {
        val sender = InMemoryPayloadCipher()
        val receiver = InMemoryPayloadCipher()
        sender.deriveSessionKey("oracle-1")
        receiver.deriveSessionKey("oracle-1")

        val encrypted = sender.encryptBytes("forum_general", byteArrayOf(1, 2, 3, 4))
        val decrypted = receiver.decryptBytes("forum_general", encrypted)

        assertTrue(byteArrayOf(1, 2, 3, 4).contentEquals(decrypted))
    }

    @Test
    fun differentConversationCannotDecryptPayload() {
        val cipher = InMemoryPayloadCipher()
        cipher.deriveSessionKey("oracle-1")
        val encrypted = cipher.encrypt("dm_private", "secret")

        assertTrue(runCatching { cipher.decrypt("forum_public", encrypted) }.isFailure)
    }

    @Test
    fun tamperingAndMalformedConversationIdsAreRejected() {
        val cipher = InMemoryPayloadCipher()
        cipher.deriveSessionKey("oracle-1")
        val encrypted = cipher.encrypt("forum_general", "secret")
        encrypted[encrypted.lastIndex] = (encrypted.last() + 1).toByte()

        assertTrue(runCatching { cipher.decrypt("forum_general", encrypted) }.isFailure)
        assertTrue(runCatching { cipher.encrypt("bad/chat", "secret") }.isFailure)
    }

    @Test
    fun clearRemovesActiveKeyMaterial() {
        val cipher = InMemoryPayloadCipher()
        cipher.deriveSessionKey("oracle-1")
        cipher.clear()

        assertTrue(runCatching { cipher.encrypt("forum_general", "secret") }.isFailure)
    }

    @Test
    fun emptyAndOversizedNodeIdentitiesAreRejected() {
        val cipher = InMemoryPayloadCipher()

        assertTrue(runCatching { cipher.deriveSessionKey("   ") }.isFailure)
        assertTrue(runCatching { cipher.deriveSessionKey("n".repeat(129)) }.isFailure)
    }
}

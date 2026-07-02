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

        val encrypted = sender.encrypt("hello from RAM")

        assertEquals("hello from RAM", receiver.decrypt(encrypted))
    }

    @Test
    fun differentNodeCannotDecryptPayload() {
        val sender = InMemoryPayloadCipher()
        val receiver = InMemoryPayloadCipher()
        sender.deriveSessionKey("oracle-1")
        receiver.deriveSessionKey("oracle-2")

        val encrypted = sender.encrypt("secret")
        val failed = runCatching { receiver.decrypt(encrypted) }.isFailure

        assertTrue(failed)
    }

    @Test
    fun encryptedBytesRoundTrip() {
        val sender = InMemoryPayloadCipher()
        val receiver = InMemoryPayloadCipher()
        sender.deriveSessionKey("oracle-1")
        receiver.deriveSessionKey("oracle-1")

        val encrypted = sender.encryptBytes(byteArrayOf(1, 2, 3, 4))
        val decrypted = receiver.decryptBytes(encrypted)

        assertTrue(byteArrayOf(1, 2, 3, 4).contentEquals(decrypted))
    }
}

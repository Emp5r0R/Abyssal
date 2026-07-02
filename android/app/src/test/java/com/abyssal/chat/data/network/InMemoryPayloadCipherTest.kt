package com.abyssal.chat.data.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class InMemoryPayloadCipherTest {
    @Test
    fun sameInviteAndNodeDecryptPayload() {
        val sender = InMemoryPayloadCipher()
        val receiver = InMemoryPayloadCipher()
        sender.deriveSessionKey("mira-4729-zx00", "oracle-1", "strong-password")
        receiver.deriveSessionKey("MIRA-4729-ZX00", "ORACLE-1", "strong-password")

        val encrypted = sender.encrypt("hello from RAM")

        assertEquals("hello from RAM", receiver.decrypt(encrypted))
    }

    @Test
    fun differentInviteCannotDecryptPayload() {
        val sender = InMemoryPayloadCipher()
        val receiver = InMemoryPayloadCipher()
        sender.deriveSessionKey("MIRA-4729-ZX00", "oracle-1", "strong-password")
        receiver.deriveSessionKey("MIRA-0000-ZX00", "oracle-1", "strong-password")

        val encrypted = sender.encrypt("secret")
        val failed = runCatching { receiver.decrypt(encrypted) }.isFailure

        assertTrue(failed)
    }

    @Test
    fun differentPasswordCannotDecryptPayload() {
        val sender = InMemoryPayloadCipher()
        val receiver = InMemoryPayloadCipher()
        sender.deriveSessionKey("MIRA-4729-ZX00", "oracle-1", "strong-password")
        receiver.deriveSessionKey("MIRA-4729-ZX00", "oracle-1", "wrong-password")

        val encrypted = sender.encrypt("secret")
        val failed = runCatching { receiver.decrypt(encrypted) }.isFailure

        assertTrue(failed)
    }
}

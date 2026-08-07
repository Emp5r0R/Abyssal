package com.abyssal.chat.data.network

import com.abyssal.chat.domain.model.IncomingTransportPayload
import com.abyssal.chat.domain.model.RecipientIdentity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class InMemoryPayloadCipherTest {
    @Test
    fun listedRecipientDecryptsAuthenticatedPayload() {
        val sender = identity(1)
        val receiver = identity(2)
        val payload = sender.encrypt(
            CHAT_ID,
            MESSAGE_ID,
            "Alice",
            "hello from RAM".encodeToByteArray(),
            listOf(RecipientIdentity("Bob", receiver.publicKey()))
        )

        val plain = receiver.decrypt(incoming(payload, sender.publicKey(), "Alice", "Bob"), "Bob")

        assertEquals(4, payload.version)
        assertEquals(1UL, payload.stateRevision)
        assertTrue(payload.identityEnvelope.size > 64)
        assertEquals("hello from RAM", plain.decodeToString())
        val state = receiver.stateSnapshot()
        val retry = receiver.stateSnapshot()
        assertEquals(1UL, state?.revision)
        assertEquals(1UL, retry?.revision)
        assertTrue(state?.envelope !== retry?.envelope)
        assertTrue(state!!.envelope.contentEquals(retry!!.envelope))
    }

    @Test
    fun unlistedIdentityCannotDecryptRecipientEnvelope() {
        val sender = identity(1)
        val receiver = identity(2)
        val intruder = identity(3)
        val payload = sender.encrypt(
            CHAT_ID,
            MESSAGE_ID,
            "Alice",
            "secret".encodeToByteArray(),
            listOf(RecipientIdentity("Bob", receiver.publicKey()))
        )
        val incoming = incoming(payload, sender.publicKey(), "Alice", "Mallory", wrappedFor = "Bob")

        assertTrue(runCatching { intruder.decrypt(incoming, "Mallory") }.isFailure)
    }

    @Test
    fun signatureCiphertextAndConversationTamperingAreRejected() {
        val sender = identity(1)
        val receiver = identity(2)
        val payload = sender.encrypt(
            CHAT_ID,
            MESSAGE_ID,
            "Alice",
            byteArrayOf(1, 2, 3, 4),
            listOf(RecipientIdentity("Bob", receiver.publicKey()))
        )
        val original = incoming(payload, sender.publicKey(), "Alice", "Bob")
        val tampered = original.copy(ciphertext = original.ciphertext.clone().also {
            it[it.lastIndex] = (it.last() + 1).toByte()
        })

        assertTrue(runCatching { receiver.decrypt(tampered, "Bob") }.isFailure)
        assertTrue(runCatching { receiver.decrypt(original.copy(chatId = "forum_other"), "Bob") }.isFailure)
        assertTrue(runCatching {
            receiver.decrypt(original.copy(senderPublicKey = ByteArray(64)), "Bob")
        }.isFailure)
    }

    @Test
    fun serializedAttachmentEnvelopeRoundTrips() {
        val sender = identity(1)
        val receiver = identity(2)
        val payload = sender.encrypt(
            CHAT_ID,
            "${MESSAGE_ID}_attachment",
            "Alice",
            byteArrayOf(9, 8, 7),
            listOf(RecipientIdentity("Bob", receiver.publicKey()))
        )
        val serialized = sender.serialize(payload)
        val incoming = receiver.deserializeForRecipient(
            CHAT_ID,
            serialized,
            "Alice",
            sender.publicKey(),
            "Bob"
        )

        assertTrue(byteArrayOf(9, 8, 7).contentEquals(receiver.decrypt(incoming, "Bob")))
    }

    @Test
    fun clearDestroysActiveIdentity() {
        val cipher = identity(1)
        cipher.clear()

        assertTrue(runCatching { cipher.publicKey() }.isFailure)
    }

    private fun identity(fill: Int): InMemoryPayloadCipher = InMemoryPayloadCipher().also {
        val exportKey = ByteArray(64) { fill.toByte() }
        val context = "ABYSSAL_IDENTITY_V2:node:CODE-12345678".encodeToByteArray()
        try {
            it.createIdentity(exportKey, context)
        } finally {
            exportKey.fill(0)
            context.fill(0)
        }
    }

    private fun incoming(
        payload: com.abyssal.chat.domain.model.EncryptedTransportPayload,
        senderPublicKey: ByteArray,
        sender: String,
        recipient: String,
        wrappedFor: String = recipient
    ): IncomingTransportPayload = IncomingTransportPayload(
        chatId = CHAT_ID,
        messageId = payload.messageId,
        nonce = payload.nonce,
        ciphertext = payload.ciphertext,
        signature = payload.signature,
        wrappedKey = payload.envelopes.single { it.recipientUsername == wrappedFor }.wrappedKey,
        senderUsername = sender,
        senderPublicKey = senderPublicKey
    )

    private companion object {
        const val CHAT_ID = "forum_general"
        const val MESSAGE_ID = "5dbf06b8-fca4-46c4-8f26-5589e7024d94"
    }
}

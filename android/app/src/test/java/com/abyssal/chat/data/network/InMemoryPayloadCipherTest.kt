package com.abyssal.chat.data.network

import com.abyssal.chat.domain.model.IncomingTransportPayload
import com.abyssal.chat.domain.model.RecipientIdentity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.json.JSONObject

class InMemoryPayloadCipherTest {
    @Test
    fun listedRecipientDecryptsAuthenticatedPayload() {
        val sender = identity(1)
        val receiver = identity(2)
        val initialPrekey = receiver.prekeyId()
        val payload = sender.encrypt(
            CHAT_ID,
            MESSAGE_ID,
            "Alice",
            "hello from RAM".encodeToByteArray(),
            listOf(RecipientIdentity("Bob", receiver.publicKey(), receiver.prekeyId()))
        )

        val decryption = receiver.decrypt(incoming(payload, sender.publicKey(), "Alice", "Bob"), "Bob")
        try {
            assertEquals(9, payload.version)
            assertTrue(payload.envelopes.single().isPrekey)
            assertEquals(initialPrekey, payload.envelopes.single().prekeyId)
            assertEquals(64, payload.envelopes.single().signature.size)
            assertEquals(64, payload.stateSignature.size)
            assertEquals(1UL, payload.stateRevision)
            assertTrue(payload.identityEnvelope.size > 64)
            assertEquals("hello from RAM", decryption.plaintext.decodeToString())
            val ack = receiver.signAcknowledgement(
                CHAT_ID,
                MESSAGE_ID,
                "Alice",
                payload.envelopes.single().prekeyId
            )
            assertEquals(64, ack.size)
            ack.fill(0)
            assertNotEquals(initialPrekey, receiver.prekeyId())
            val state = receiver.stateSnapshot()
            val retry = receiver.stateSnapshot()
            assertEquals(1UL, state?.revision)
            assertEquals(1UL, retry?.revision)
            assertEquals(608, state?.identityPublicKey?.size)
            assertTrue(state?.envelope !== retry?.envelope)
            assertTrue(state!!.envelope.contentEquals(retry!!.envelope))
            state.envelope.fill(0)
            state.identityPublicKey.fill(0)
            state.stateSignature.fill(0)
            retry.envelope.fill(0)
            retry.identityPublicKey.fill(0)
            retry.stateSignature.fill(0)
        } finally {
            decryption.plaintext.fill(0)
        }
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
            listOf(RecipientIdentity("Bob", receiver.publicKey(), receiver.prekeyId()))
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
            listOf(RecipientIdentity("Bob", receiver.publicKey(), receiver.prekeyId()))
        )
        val original = incoming(payload, sender.publicKey(), "Alice", "Bob")
        val tampered = original.copy(ciphertext = original.ciphertext.clone().also {
            it[it.lastIndex] = (it.last() + 1).toByte()
        })
        val tamperedSignature = original.copy(signature = original.signature.clone().also {
            it[it.lastIndex] = (it.last() + 1).toByte()
        })

        assertTrue(runCatching {
            receiver.decrypt(original.copy(prekeyId = "wrong-prekey"), "Bob")
        }.isFailure)
        assertTrue(runCatching {
            receiver.decrypt(original.copy(prekeyId = "", isPrekey = false), "Bob")
        }.isFailure)
        assertTrue(runCatching { receiver.decrypt(tampered, "Bob") }.isFailure)
        assertTrue(runCatching { receiver.decrypt(tamperedSignature, "Bob") }.isFailure)
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
            listOf(RecipientIdentity("Bob", receiver.publicKey(), receiver.prekeyId()))
        )
        val serialized = sender.serialize(payload)
        val serializedJson = JSONObject(serialized.decodeToString())
        assertEquals(9, serializedJson.optInt("version"))
        assertTrue(serializedJson.optString("identity_public_b64").isNotEmpty())
        assertEquals(64, java.util.Base64.getUrlDecoder().decode(serializedJson.getString("state_signature_b64")).size)
        val serializedEnvelope = serializedJson.getJSONArray("envelopes").getJSONObject(0)
        assertTrue(serializedEnvelope.optString("signature_b64").isNotEmpty())
        assertFalse(serializedJson.has("state_revision"))
        assertFalse(serializedJson.has("identity_envelope_b64"))
        val incoming = receiver.deserializeForRecipient(
            CHAT_ID,
            serialized,
            "Alice",
            sender.publicKey(),
            "Bob"
        )

        val decryption = receiver.decrypt(incoming, "Bob")
        try {
            assertTrue(byteArrayOf(9, 8, 7).contentEquals(decryption.plaintext))
        } finally {
            decryption.plaintext.fill(0)
        }
    }

    @Test
    fun emptyRecipientListIsRejectedWithoutAdvancingIdentity() {
        val sender = identity(1)
        val initialPrekey = sender.prekeyId()

        assertTrue(
            runCatching {
                sender.encrypt(
                    CHAT_ID,
                    MESSAGE_ID,
                    "Alice",
                    byteArrayOf(1, 2, 3),
                    emptyList()
                )
            }.isFailure
        )
        assertEquals(initialPrekey, sender.prekeyId())
        assertTrue(sender.stateSnapshot() == null)
    }

    @Test
    fun outboundRatchetRequiresExplicitCommitOrRollback() {
        val sender = identity(4)
        val receiver = identity(5)
        val initialPrekey = sender.prekeyId()
        val first = sender.encrypt(
            CHAT_ID,
            MESSAGE_ID,
            "Alice",
            byteArrayOf(1),
            listOf(RecipientIdentity("Bob", receiver.publicKey(), receiver.prekeyId()))
        )
        assertTrue(runCatching {
            sender.encrypt(
                CHAT_ID,
                "second-message",
                "Alice",
                byteArrayOf(2),
                emptyList()
            )
        }.isFailure)
        assertTrue(runCatching { sender.commitOutbound(first.messageId, first.stateRevision + 1UL) }.isFailure)
        sender.rollbackOutbound(first.messageId, first.stateRevision)
        assertEquals(initialPrekey, sender.prekeyId())
        assertEquals(null, sender.stateSnapshot())

        val retry = sender.encrypt(
            CHAT_ID,
            MESSAGE_ID,
            "Alice",
            byteArrayOf(3),
            listOf(RecipientIdentity("Bob", receiver.publicKey(), receiver.prekeyId()))
        )
        sender.commitOutbound(retry.messageId, retry.stateRevision)
        assertEquals(1UL, sender.stateSnapshot()?.revision)
    }

    @Test
    fun clearDestroysActiveIdentity() {
        val cipher = identity(1)
        cipher.clear()

        assertTrue(runCatching { cipher.publicKey() }.isFailure)
    }

    @Test
    fun clearDropsPendingRatchetAndLeavesCipherFailClosed() {
        val sender = identity(1)
        val receiver = identity(2)
        val payload = sender.encrypt(
            CHAT_ID,
            MESSAGE_ID,
            "Alice",
            byteArrayOf(1, 2, 3),
            listOf(RecipientIdentity("Bob", receiver.publicKey(), receiver.prekeyId()))
        )

        assertEquals(1UL, sender.stateSnapshot()?.revision)
        sender.clear()

        assertEquals(null, sender.stateSnapshot())
        assertTrue(runCatching { sender.publicKey() }.isFailure)
        assertTrue(
            runCatching { sender.commitOutbound(payload.messageId, payload.stateRevision) }
                .isFailure
        )
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
    ): IncomingTransportPayload {
        val envelope = payload.envelopes.single { it.recipientUsername == wrappedFor }
        return IncomingTransportPayload(
            chatId = CHAT_ID,
            messageId = payload.messageId,
            version = payload.version,
            identityPublicKey = payload.identityPublicKey,
            nonce = payload.nonce,
            ciphertext = payload.ciphertext,
            signature = envelope.signature,
            wrappedKey = envelope.wrappedKey,
            senderUsername = sender,
            senderPublicKey = senderPublicKey,
            prekeyId = envelope.prekeyId,
            isPrekey = envelope.isPrekey
        )
    }

    private companion object {
        const val CHAT_ID = "forum_general"
        const val MESSAGE_ID = "5dbf06b8-fca4-46c4-8f26-5589e7024d94"
    }
}

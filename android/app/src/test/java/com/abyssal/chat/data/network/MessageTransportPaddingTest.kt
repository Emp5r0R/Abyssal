package com.abyssal.chat.data.network

import java.nio.charset.StandardCharsets
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class MessageTransportPaddingTest {
    private val buckets = listOf(4096, 16_384, 65_536, 262_144, 1_048_576)

    @Test
    fun outgoingUsesExactSmallestBucketsAndRandomUrlSafeFiller() {
        val first = MessageTransportPadding.padOutgoingMessage(outgoingFrame())
        val second = MessageTransportPadding.padOutgoingMessage(outgoingFrame())
        assertNotNull(first)
        assertNotNull(second)
        assertEquals(4096, wireBytes(first!!))
        assertEquals(4096, wireBytes(second!!))
        assertTrue(MessageTransportPadding.isCanonicalWireText(first))
        assertNotEquals(
            JSONObject(first).getString("padding"),
            JSONObject(second).getString("padding")
        )
        assertTrue(JSONObject(first).getString("padding").matches(Regex("^[A-Za-z0-9_-]*$")))

        listOf(
            5_000 to 16_384,
            20_000 to 65_536,
            70_000 to 262_144,
            300_000 to 1_048_576
        ).forEach { (ciphertextSize, expectedBucket) ->
            val serialized = MessageTransportPadding.padOutgoingMessage(
                outgoingFrame("x".repeat(ciphertextSize))
            )
            assertNotNull(serialized)
            assertEquals(expectedBucket, wireBytes(serialized!!))
            assertEquals(expectedBucket, JSONObject(serialized).getInt("padding_bucket"))
        }
    }

    @Test
    fun outgoingCountsUtf8BytesAndDoesNotMutateInput() {
        val frame = outgoingFrame(chatId = "dm_e_accent_\u6e2c\u8a66")
        val before = frame.toString()
        val serialized = MessageTransportPadding.padOutgoingMessage(frame)

        assertNotNull(serialized)
        assertEquals(4096, wireBytes(serialized!!))
        assertEquals(before, frame.toString())
        assertFalse(frame.has("padding_bucket"))
        assertFalse(frame.has("padding"))
    }

    @Test
    fun outgoingRejectsMissingExtraInvalidAndOversizedShapes() {
        assertNull(MessageTransportPadding.padOutgoingMessage(
            JSONObject(outgoingFrame().toString()).apply { remove("envelopes") }
        ))
        assertNull(MessageTransportPadding.padOutgoingMessage(
            JSONObject(outgoingFrame().toString()).put("unexpected", true)
        ))
        assertNull(MessageTransportPadding.padOutgoingMessage(
            JSONObject(outgoingFrame().toString()).put("state_revision", 0)
        ))
        assertNull(MessageTransportPadding.padOutgoingMessage(
            JSONObject(outgoingFrame().toString()).put("envelopes", JSONArray())
        ))
        assertNull(MessageTransportPadding.padOutgoingMessage(
            outgoingFrame("x".repeat(MessageTransportPadding.MAX_BUCKET))
        ))
    }

    @Test
    fun incomingValidatesCanonicalPaddingThenStripsTransportFields() {
        val fixture = paddedIncoming(incomingFrame())
        assertNotNull(fixture)

        assertTrue(
            MessageTransportPadding.validateAndStripIncomingMessagePadding(
                fixture!!.raw,
                fixture.frame
            )
        )
        assertFalse(fixture.frame.has("padding_bucket"))
        assertFalse(fixture.frame.has("padding"))
        assertEquals("ciphertext", fixture.frame.getString("ciphertext_b64"))
    }

    @Test
    fun incomingUsesUtf8WireLength() {
        val fixture = paddedIncoming(incomingFrame(chatId = "dm_e_accent_\u6e2c\u8a66"))
        assertNotNull(fixture)
        assertTrue(fixture!!.raw.length < 4096)
        assertEquals(4096, wireBytes(fixture.raw))
        assertTrue(
            MessageTransportPadding.validateAndStripIncomingMessagePadding(
                fixture.raw,
                fixture.frame
            )
        )
    }

    @Test
    fun incomingRejectsTamperingWithoutStrippingFields() {
        val canonical = paddedIncoming(incomingFrame()) ?: error("fixture")
        val cases = listOf(
            JSONObject(canonical.raw).apply { remove("padding") },
            JSONObject(canonical.raw).put("unexpected", true),
            JSONObject(canonical.raw).put("padding_bucket", 16_384),
            JSONObject(canonical.raw).apply {
                put("padding", getString("padding").drop(1))
            },
            JSONObject(canonical.raw).apply {
                put("padding", "!" + getString("padding").drop(1))
            }
        )

        cases.forEach { frame ->
            val before = frame.toString()
            assertFalse(
                MessageTransportPadding.validateAndStripIncomingMessagePadding(
                    canonical.raw,
                    frame
                )
            )
            assertEquals(before, frame.toString())
        }

        val trailing = JSONObject(canonical.raw)
        assertFalse(
            MessageTransportPadding.validateAndStripIncomingMessagePadding(
                canonical.raw + " ",
                trailing
            )
        )
        assertTrue(trailing.has("padding_bucket"))
        assertTrue(trailing.has("padding"))
    }

    @Test
    fun incomingRejectsPayloadBeyondMaximumBucket() {
        assertNull(paddedIncoming(incomingFrame("x".repeat(MessageTransportPadding.MAX_BUCKET))))
        assertFalse(MessageTransportPadding.isCanonicalWireText("x".repeat(4095)))
        assertFalse(MessageTransportPadding.isCanonicalWireText("x".repeat(1_048_577)))
    }

    private fun outgoingFrame(
        ciphertext: String = "ciphertext",
        chatId: String = "dm_Alice_Bob"
    ): JSONObject = JSONObject()
        .put("type", "message")
        .put("chat_id", chatId)
        .put("version", 9)
        .put("message_id", "message-1")
        .put("nonce_b64", "nonce")
        .put("ciphertext_b64", ciphertext)
        .put("state_revision", 1L)
        .put("identity_envelope_b64", "identity-envelope")
        .put("identity_public_b64", "identity-public")
        .put("prekey_id", "prekey")
        .put("state_signature_b64", "state-signature")
        .put("envelopes", JSONArray().put(
            JSONObject()
                .put("recipient_username", "Bob")
                .put("wrapped_key_b64", "wrapped")
                .put("prekey_id", "")
                .put("is_prekey", false)
                .put("signature_b64", "signature")
        ))
        .put("directory_node_id", "node-1")
        .put("directory_revision", 1L)
        .put("directory_digest", "directory-digest")

    private fun incomingFrame(
        ciphertext: String = "ciphertext",
        chatId: String = "dm_Alice_Bob"
    ): JSONObject = JSONObject()
        .put("type", "message")
        .put("chat_id", chatId)
        .put("version", 9)
        .put("message_id", "message-1")
        .put("nonce_b64", "nonce")
        .put("ciphertext_b64", ciphertext)
        .put("signature_b64", "signature")
        .put("wrapped_key_b64", "wrapped")
        .put("prekey_id", "")
        .put("is_prekey", false)
        .put("sender_username", "Alice")
        .put("sender_public_key_b64", "sender-public")
        .put("identity_public_b64", "identity-public")
        .put("directory_node_id", "node-1")
        .put("directory_revision", 1L)
        .put("directory_digest", "directory-digest")

    private fun paddedIncoming(base: JSONObject): IncomingFixture? {
        for (bucket in buckets) {
            val frame = JSONObject(base.toString())
                .put("padding_bucket", bucket)
                .put("padding", "")
            val emptyBytes = wireBytes(frame.toString())
            if (emptyBytes > bucket) continue
            frame.put("padding", "A".repeat(bucket - emptyBytes))
            val raw = frame.toString()
            check(wireBytes(raw) == bucket)
            return IncomingFixture(raw, JSONObject(raw))
        }
        return null
    }

    private fun wireBytes(value: String): Int =
        value.toByteArray(StandardCharsets.UTF_8).size

    private data class IncomingFixture(val raw: String, val frame: JSONObject)
}

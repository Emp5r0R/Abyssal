package com.abyssal.chat.data.network

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ControlTransportPaddingTest {
    @Test
    fun smallControlsUseSameExactRandomizedMinimumBucket() {
        val first = JSONObject().put("type", "activity")
            .padOutgoingControl(ControlTransportPadding.LEGACY_DOMAIN_MAX_BYTES)
        val second = JSONObject().put("type", "message_ack").put("message_id", "message-1")
            .padOutgoingControl(ControlTransportPadding.LEGACY_DOMAIN_MAX_BYTES)

        assertNotNull(first)
        assertNotNull(second)
        assertEquals(4096, first!!.toByteArray(Charsets.UTF_8).size)
        assertEquals(4096, second!!.toByteArray(Charsets.UTF_8).size)
        assertNotEquals(JSONObject(first).getString("padding"), JSONObject(second).getString("padding"))
    }

    @Test
    fun validatesAndStripsUnicodeControlWithoutChangingDomainFields() {
        val padded = JSONObject()
            .put("type", "direct_opened")
            .put("label", "é-測試")
            .padOutgoingControl(ControlTransportPadding.LEGACY_DOMAIN_MAX_BYTES)!!
        val parsed = JSONObject(padded)

        assertTrue(parsed.validateAndStripIncomingControlPadding(
            padded,
            ControlTransportPadding.LEGACY_DOMAIN_MAX_BYTES
        ))
        assertEquals(setOf("type", "label"), parsed.keys().asSequence().toSet())
        assertEquals("é-測試", parsed.getString("label"))
    }

    @Test
    fun largeBucketsAreAvailableOnlyToMlsDomain() {
        val frame = JSONObject()
            .put("type", "mls_application")
            .put("ciphertext_b64", "A".repeat(1_100_000))

        assertNull(frame.padOutgoingControl(ControlTransportPadding.LEGACY_DOMAIN_MAX_BYTES))
        val padded = frame.padOutgoingControl(ControlTransportPadding.MLS_DOMAIN_MAX_BYTES)
        assertNotNull(padded)
        assertEquals(4_194_304, padded!!.toByteArray(Charsets.UTF_8).size)
    }

    @Test
    fun rejectsMissingChangedNoncanonicalAndEmbeddedPaddingWithoutStripping() {
        val canonical = JSONObject().put("type", "activity")
            .padOutgoingControl(ControlTransportPadding.LEGACY_DOMAIN_MAX_BYTES)!!

        val missing = JSONObject().put("type", "activity")
        assertFalse(missing.validateAndStripIncomingControlPadding(
            missing.toString(),
            ControlTransportPadding.LEGACY_DOMAIN_MAX_BYTES
        ))

        val changed = canonical.replace("\"padding_bucket\":4096", "\"padding_bucket\":16384")
        val changedFrame = JSONObject(changed)
        assertFalse(changedFrame.validateAndStripIncomingControlPadding(
            changed,
            ControlTransportPadding.LEGACY_DOMAIN_MAX_BYTES
        ))
        assertTrue(changedFrame.has("padding"))

        val shortened = canonical.dropLast(3) + canonical.takeLast(2)
        val shortenedFrame = JSONObject(shortened)
        assertFalse(shortenedFrame.validateAndStripIncomingControlPadding(
            shortened,
            ControlTransportPadding.LEGACY_DOMAIN_MAX_BYTES
        ))
        assertTrue(shortenedFrame.has("padding_bucket"))

        assertNull(JSONObject()
            .put("type", "activity")
            .put("padding", "attacker")
            .padOutgoingControl(ControlTransportPadding.LEGACY_DOMAIN_MAX_BYTES))
        assertNull(JSONObject().put("type", "message")
            .padOutgoingControl(ControlTransportPadding.LEGACY_DOMAIN_MAX_BYTES))
    }
}

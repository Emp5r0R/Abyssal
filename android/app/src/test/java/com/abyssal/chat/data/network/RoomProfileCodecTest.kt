package com.abyssal.chat.data.network

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RoomProfileCodecTest {
    @Test
    fun sharedV1VectorAndBoundedUnicodeNames() {
        val vector = JSONObject("""{"version":1,"name":"Private incident response"}""")
        assertEquals("Private incident response", RoomProfileCodec.decode(vector))
        for (name in listOf("A", "x".repeat(36), "\uD83D\uDD12 room", "caf\u00e9", "a b")) {
            assertEquals(name, RoomProfileCodec.decode(RoomProfileCodec.encode(name)))
        }
        assertEquals("A", RoomProfileCodec.decode(JSONObject("""{"version":1.0,"name":"A"}""")))
    }

    @Test
    fun malformedExtendedAndNoncanonicalProfilesFailClosed() {
        for (name in listOf("", "x".repeat(37), " a", "a ", "a\n", "a\u0085b", "\u00a0a", "a\ufeff", "\ud800", "\udfff")) {
            assertTrue(runCatching { RoomProfileCodec.encode(name) }.isFailure)
        }
        for (value in listOf(null, JSONObject.NULL, "name", JSONObject(),
            JSONObject("""{"version":2,"name":"A"}"""), JSONObject("""{"version":"1","name":"A"}"""),
            JSONObject("""{"version":1,"name":5}"""), JSONObject("""{"version":1,"name":"A","extra":true}"""))) {
            assertTrue(runCatching { RoomProfileCodec.decode(value) }.isFailure)
        }
    }
}

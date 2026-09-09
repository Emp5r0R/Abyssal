package com.abyssal.chat.data.network

import com.abyssal.chat.domain.model.User
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class SenderProfileCodecTest {
    @Test fun sharedVectorAndBoundedRandomProfiles() {
        assertEquals("SilentSignal0203040506FF", SenderProfileCodec.displayNameFromEntropy(byteArrayOf(0, 1, 2, 3, 4, 5, 6, -1)))
        val names = (1..128).map { SenderProfileCodec.newDisplayName() }.toSet()
        assertEquals(128, names.size)
        names.forEach { assertEquals(it, SenderProfileCodec.decode(SenderProfileCodec.encode(it))) }
        assertNull(SenderProfileCodec.decode(null))
        assertTrue(runCatching { SenderProfileCodec.displayNameFromEntropy(ByteArray(9)) }.isFailure)
    }

    @Test fun malformedNamesAndExtendedProfilesFailClosed() {
        for (name in listOf("", "a".repeat(37), " A", "A\n", "@Alice", "<script>", "a\u202eb", "\ud800")) {
            assertTrue(runCatching { SenderProfileCodec.encode(name) }.isFailure)
        }
        for (value in listOf(JSONObject.NULL, JSONObject(), JSONObject("""{"version":2,"display_name":"Alice"}"""),
            JSONObject("""{"version":"1","display_name":"Alice"}"""), JSONObject("""{"version":1,"display_name":9}"""),
            JSONObject("""{"version":1,"display_name":"Alice","username":"Bob"}"""))) {
            assertTrue(runCatching { SenderProfileCodec.decode(value) }.isFailure)
        }
        val user = User("acct_test", ByteArray(608), displayName = "Alice")
        assertEquals(user, user.copy())
        assertNotEquals(user, user.copy(displayName = "Bob"))
    }
}

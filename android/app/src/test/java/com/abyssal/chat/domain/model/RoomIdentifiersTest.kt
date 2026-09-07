package com.abyssal.chat.domain.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

class RoomIdentifiersTest {
    @Test fun forumIdentifiersKeepFullRandomUuidWithoutDisplayData() {
        val ids = List(1024) { RoomIdentifiers.newForumId() }
        assertEquals(ids.size, ids.toSet().size)
        ids.forEach { id ->
            assertTrue(id.matches(Regex("forum_[0-9a-f]{32}")))
            val hex = id.removePrefix("forum_")
            val uuid = UUID.fromString("${hex.take(8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}")
            assertEquals(4, uuid.version())
            assertEquals(2, uuid.variant())
        }
    }
}

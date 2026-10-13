package com.abyssal.chat.domain.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Test

class DisplayLabelsTest {
    private val bob = "acct_10bae1a3659440688930a460dd27ce30"

    @Test
    fun accountAndRoomIdsAreShortenedLikeTheWebClient() {
        assertEquals("10ba…ce30", shortAccountId(bob))
        assertEquals("alice", shortAccountId("alice"))
        assertEquals("9f2c…beef", shortRoomId("forum_9f2c1a7b0000000000000000deadbeef"))
        assertEquals("short", shortRoomId("forum_short"))
        assertEquals("Operations", roomLabel("forum_9f2c1a7b0000000000000000deadbeef", "Operations"))
        assertEquals("Room 9f2c…beef", roomLabel("forum_9f2c1a7b0000000000000000deadbeef", "9f2c1a7b0000000000000000deadbeef"))
        assertEquals("Room 9f2c…beef", roomLabel("forum_9f2c1a7b0000000000000000deadbeef", ""))
    }

    @Test
    fun initialsComeFromTheAccountHexOrTheName() {
        assertEquals("10", accountInitials(bob))
        assertEquals("SI", accountInitials("SilverComet41AB2C"))
        assertEquals("?", accountInitials("—"))
    }

    @Test
    fun peersShowTheirLatestDisplayNameOrTheirShortId() {
        var names = withDisplayName(emptyMap(), bob.uppercase(), "SilverComet")
        assertEquals("SilverComet", peerLabel(bob, names))
        names = withDisplayName(names, bob, "  Renamed  ")
        assertEquals("Renamed", peerLabel(bob, names))
        assertSame(names, withDisplayName(names, bob, " "))
        assertSame(names, withDisplayName(names, bob, "Renamed"))
        assertEquals("33aa…0000", peerLabel("acct_33aa00000000", names))
    }

    @Test
    fun knownDisplayNamesStayBoundedDroppingTheOldest() {
        var names: Map<String, String> = emptyMap()
        repeat(MAX_KNOWN_DISPLAY_NAMES + 3) { names = withDisplayName(names, "acct_${it.toString().padStart(8, '0')}", "n$it") }
        assertEquals(MAX_KNOWN_DISPLAY_NAMES, names.size)
        assertEquals(null, names["acct_00000000"])
        assertEquals("n${MAX_KNOWN_DISPLAY_NAMES + 2}", names["acct_${(MAX_KNOWN_DISPLAY_NAMES + 2).toString().padStart(8, '0')}"])
    }

    @Test
    fun searchMatchesLabelsAndUnderlyingIds() {
        val sessions = listOf(
            ChatSession("forum_ops", "Operations", true, null, 0, 5),
            ChatSession("dm_1", bob, false, null, 0, 5)
        )
        val entries = conversationEntries(sessions, mapOf(bob to "SilverComet"))
        assertEquals(listOf("Operations", "SilverComet"), entries.map { it.label })
        assertEquals(listOf("dm_1"), filterConversations(entries, " silver ").map { it.id })
        assertEquals(listOf("dm_1"), filterConversations(entries, "10BAE1").map { it.id })
        assertEquals(listOf("forum_ops"), filterConversations(entries, "forum_o").map { it.id })
        assertEquals(2, filterConversations(entries, "  ").size)
    }
}

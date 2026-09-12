package com.abyssal.chat.presentation.screens

import com.abyssal.chat.domain.model.UserPresence
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DashboardPeoplePolicyTest {
    @Test
    fun directoryExcludesOnlyCurrentAccountAndRetainsOfflinePeers() {
        val peers = directPeersForDirectory(
            presence = listOf(
                presence("Current", connected = true),
                presence("OfflinePeer", connected = false),
                presence("OnlinePeer", connected = true)
            ),
            currentUsername = "current"
        )

        assertEquals(listOf("OfflinePeer", "OnlinePeer"), peers.map { it.username })
        assertTrue(peers.any { it.username == "OfflinePeer" && !it.connected })
    }

    @Test
    fun directoryExcludesEstablishedPeersCaseInsensitively() {
        val peers = directPeersForDirectory(
            presence = listOf(
                presence("OfflinePeer", connected = false),
                presence("OnlinePeer", connected = true)
            ),
            currentUsername = "Current",
            establishedDirectPeerUsernames = setOf("onlinepeer")
        )

        assertEquals(listOf("OfflinePeer"), peers.map { it.username })
    }

    @Test
    fun directoryEntryLabelsExposeActionTargetAndPresence() {
        assertEquals(
            "Open direct conversation with OnlinePeer · ONLINE",
            peopleDirectoryEntryLabel("OnlinePeer", connected = true)
        )
        assertEquals(
            "Open direct conversation with OfflinePeer · OFFLINE",
            peopleDirectoryEntryLabel("OfflinePeer", connected = false)
        )
    }

    @Test
    fun emptyCopyDistinguishesNoPeersFromNoDirectConversations() {
        assertEquals("No peers active", peopleDirectoryEmptyStateLabel())
        assertEquals("No direct conversations", directConversationEmptyStateTitle())
        assertEquals(
            "No peers are currently available on this relay.",
            directConversationEmptyStateDetail(peerCount = 0)
        )
        assertEquals(
            "Select a peer from People to start a conversation.",
            directConversationEmptyStateDetail(peerCount = 2)
        )
    }

    private fun presence(username: String, connected: Boolean) = UserPresence(
        username = username,
        connected = connected,
        publicKey = ByteArray(32)
    )
}

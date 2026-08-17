package com.abyssal.chat.domain.model

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DirectChatTrustTest {
    private fun context(generation: Long = 7L) = DirectTrustContext(
        chatId = "dm_peer",
        peerUsername = "Peer",
        safetyNumber = "1234 5678 9012",
        sessionGeneration = 3L,
        connectionGeneration = generation,
        localIdentity = ByteArray(608) { if (it < STABLE_IDENTITY_BYTES) 1 else 2 },
        peerIdentity = ByteArray(608) { if (it < STABLE_IDENTITY_BYTES) 4 else 5 }
    )

    @Test
    fun verificationRequiresExactNumberIdentitiesAndGeneration() {
        val store = DirectChatTrustStore()
        val trusted = context()
        assertFalse(store.markVerified(trusted, "1234 5678 9013"))
        assertFalse(store.isVerified(trusted))
        assertTrue(store.markVerified(trusted, trusted.safetyNumber))
        assertTrue(store.isVerified(trusted))
        assertFalse(store.isVerified(context(8L)))
        assertFalse(store.isVerified(trusted.copy(sessionGeneration = 4L)))
        assertFalse(store.isVerified(trusted.copy(chatId = "dm_other")))
        assertFalse(store.isVerified(trusted.copy(peerUsername = "Other")))
        assertTrue(store.isVerified(trusted.copy(localIdentity = ByteArray(608) { if (it < STABLE_IDENTITY_BYTES) 1 else 9 })))
        assertTrue(store.isVerified(trusted.copy(peerIdentity = ByteArray(608) { if (it < STABLE_IDENTITY_BYTES) 4 else 9 })))
        assertFalse(store.isVerified(trusted.copy(localIdentity = ByteArray(608) { if (it == 0) 9 else if (it < STABLE_IDENTITY_BYTES) 1 else 2 })))
        assertFalse(store.isVerified(trusted.copy(peerIdentity = ByteArray(608) { if (it == STABLE_IDENTITY_BYTES - 1) 9 else if (it < STABLE_IDENTITY_BYTES) 4 else 5 })))
        assertFalse(store.isVerified(trusted.copy(safetyNumber = "1234 5678 9013")))
    }

    @Test
    fun invalidContextsAndStaleNumbersCannotCreateTrust() {
        val store = DirectChatTrustStore()
        val trusted = context()
        assertFalse(store.markVerified(trusted, "1234 5678 9013"))
        assertFalse(store.markVerified(trusted.copy(chatId = ""), trusted.safetyNumber))
        assertFalse(store.markVerified(trusted.copy(peerUsername = ""), trusted.safetyNumber))
        assertFalse(store.markVerified(trusted.copy(safetyNumber = ""), ""))
        assertFalse(store.markVerified(trusted.copy(sessionGeneration = -1L), trusted.safetyNumber))
        assertFalse(store.markVerified(trusted.copy(connectionGeneration = -1L), trusted.safetyNumber))
        assertFalse(store.markVerified(trusted.copy(localIdentity = ByteArray(STABLE_IDENTITY_BYTES - 1)), trusted.safetyNumber))
        assertFalse(store.markVerified(trusted.copy(peerIdentity = ByteArray(STABLE_IDENTITY_BYTES - 1)), trusted.safetyNumber))
        assertFalse(store.isVerified(null))
    }

    @Test
    fun prekeyRotationDoesNotChangeIdentityTrustAndClearWipesTrust() {
        val store = DirectChatTrustStore()
        val trusted = context()
        assertTrue(store.markVerified(trusted, trusted.safetyNumber))
        // Prekey IDs are deliberately not part of the trust context.
        assertTrue(store.isVerified(trusted))
        store.clear()
        assertFalse(store.isVerified(trusted))
    }

    @Test
    fun verificationIsBoundPerPeerWithBoundedMemory() {
        val store = DirectChatTrustStore()
        val first = context()
        assertTrue(store.markVerified(first, first.safetyNumber))
        repeat(DirectChatTrustStore.MAX_PEERS) { index ->
            val peer = first.copy(chatId = "dm_peer_$index", peerUsername = "Peer$index")
            assertTrue(store.markVerified(peer, peer.safetyNumber))
        }
        assertFalse(store.isVerified(first))
        val newest = first.copy(
            chatId = "dm_peer_${DirectChatTrustStore.MAX_PEERS - 1}",
            peerUsername = "Peer${DirectChatTrustStore.MAX_PEERS - 1}"
        )
        assertTrue(store.isVerified(newest))
    }
}

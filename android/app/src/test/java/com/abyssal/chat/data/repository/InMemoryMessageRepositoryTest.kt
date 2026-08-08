package com.abyssal.chat.data.repository

import com.abyssal.chat.domain.model.ChatSession
import com.abyssal.chat.domain.model.Message
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class InMemoryMessageRepositoryTest {
    @Test
    fun startsWithoutDefaultRoomsOrMessages() = runBlocking {
        val repository = InMemoryMessageRepository()

        assertTrue(repository.getChatSessions().first().isEmpty())
        assertTrue(repository.getMessages("forum_missing").first().isEmpty())
    }

    @Test
    fun deduplicatesMessagesAndCreatesDirectSession() = runBlocking {
        val repository = InMemoryMessageRepository()
        val message = testMessage("message-1")

        repository.saveMessage("dm_canonical", message)
        repository.saveMessage("dm_canonical", message)

        assertEquals(listOf(message), repository.getMessages("dm_canonical").first())
        val session = repository.getChatSessions().first().single()
        assertEquals("Dm canonical", session.name)
        assertFalse(session.isForum)
        assertEquals("Message received", session.lastMessage?.content)
    }

    @Test
    fun roomPolicyUpdatesPreserveItsLastMessage() = runBlocking {
        val repository = InMemoryMessageRepository()
        val original = testRoom(timer = 5)
        repository.createForumSession(original)
        repository.saveMessage(original.id, testMessage("room-message"))

        repository.createForumSession(original.copy(selfDestructTimerSec = 30, allowVideos = false))

        val updated = repository.getChatSessions().first().single()
        assertTrue(updated.isForum)
        assertEquals(30, updated.selfDestructTimerSec)
        assertFalse(updated.allowVideos)
        assertEquals("payload", updated.lastMessage?.content)
    }

    @Test
    fun readDeleteAndGlobalClearMutateOnlyRamState() = runBlocking {
        val repository = InMemoryMessageRepository()
        val room = testRoom(timer = 30)
        repository.createForumSession(room)
        repository.saveMessage(room.id, testMessage("message-1"))
        repository.markAsRead(room.id, "message-1")

        assertTrue(repository.getMessages(room.id).first().single().readTimestampMs != null)
        assertEquals(0, repository.getChatSessions().first().single().unreadCount)

        repository.deleteChatSession(room.id)
        assertTrue(repository.getChatSessions().first().isEmpty())
        assertTrue(repository.getMessages(room.id).first().isEmpty())

        repository.createForumSession(testRoom(timer = 5))
        repository.clearAllData()
        assertTrue(repository.getChatSessions().first().isEmpty())
    }

    @Test
    fun zeroReadTimerKeepsMessageAfterRead() = runBlocking {
        val repository = InMemoryMessageRepository()
        val message = testMessage("kept").copy(selfDestructDurationSec = 0)
        repository.saveMessage("dm_kept", message)
        repository.markAsRead("dm_kept", message.id)

        delay(250)

        assertEquals(message.id, repository.getMessages("dm_kept").first().single().id)
        assertFalse(repository.getMessages("dm_kept").first().single().isExpired)
    }

    @Test
    fun messageSenderKeysAreOwnedAndWipedOnDuplicateAndClear() = runBlocking {
        val repository = InMemoryMessageRepository()
        val firstKey = ByteArray(32) { 7 }
        val message = testMessage("keyed").copy(senderPublicKey = firstKey)

        repository.saveMessage("dm_keys", message)

        val stored = repository.getMessages("dm_keys").first().single()
        assertArrayEquals(ByteArray(32), firstKey)
        assertArrayEquals(ByteArray(32) { 7 }, stored.senderPublicKey)

        val duplicateKey = ByteArray(32) { 9 }
        repository.saveMessage("dm_keys", message.copy(senderPublicKey = duplicateKey))
        assertArrayEquals(ByteArray(32), duplicateKey)

        repository.clearAllData()
        assertArrayEquals(ByteArray(32), stored.senderPublicKey)
    }

    private fun testMessage(id: String) = Message(
        id = id,
        sender = "Alice",
        receiver = null,
        content = "payload",
        timestampMs = System.currentTimeMillis(),
        selfDestructDurationSec = 30
    )

    private fun testRoom(timer: Int) = ChatSession(
        id = "forum_ops",
        name = "Operations",
        isForum = true,
        lastMessage = null,
        unreadCount = 0,
        selfDestructTimerSec = timer
    )
}

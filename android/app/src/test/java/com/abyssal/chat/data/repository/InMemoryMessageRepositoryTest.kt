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
        assertEquals(null, session.lastMessage)
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
        assertEquals(null, updated.lastMessage)
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
    fun repositoryEpochRejectsEveryStaleGuardedMutationButAcceptsCurrentEpoch() = runBlocking {
        val repository = InMemoryMessageRepository()
        val room = testRoom(timer = 30)
        val message = testMessage("epoch-message")
        val capturedEpoch = repository.currentEpoch()

        assertTrue(repository.createForumSessionIfCurrent(capturedEpoch, room))
        assertTrue(repository.saveMessageIfCurrent(capturedEpoch, room.id, message))
        assertTrue(repository.markAsReadIfCurrent(capturedEpoch, room.id, message.id))

        repository.clearAllDataNow()
        val currentEpoch = repository.currentEpoch()
        assertEquals(capturedEpoch + 1uL, currentEpoch)

        assertFalse(repository.saveMessageIfCurrent(capturedEpoch, room.id, message))
        assertFalse(repository.markAsReadIfCurrent(capturedEpoch, room.id, message.id))
        assertFalse(repository.createForumSessionIfCurrent(capturedEpoch, room))
        assertFalse(repository.deleteChatSessionIfCurrent(capturedEpoch, room.id))
        assertTrue(repository.getChatSessions().first().isEmpty())
        assertTrue(repository.getMessages(room.id).first().isEmpty())

        assertTrue(repository.createForumSessionIfCurrent(currentEpoch, room))
        assertTrue(repository.saveMessageIfCurrent(currentEpoch, room.id, message))
        assertTrue(repository.markAsReadIfCurrent(currentEpoch, room.id, message.id))
        assertTrue(repository.deleteChatSessionIfCurrent(currentEpoch, room.id))
        assertTrue(repository.getChatSessions().first().isEmpty())
    }

    @Test
    fun clearBetweenEpochCaptureAndMutationRejectsTheStaleOperation() = runBlocking {
        val repository = InMemoryMessageRepository()
        val room = testRoom(timer = 30)
        val capturedEpoch = repository.currentEpoch()
        assertTrue(repository.createForumSessionIfCurrent(capturedEpoch, room))

        repository.clearAllDataNow()
        val staleKey = ByteArray(32) { 8 }
        val staleMessage = testMessage("stale-after-clear").copy(senderPublicKey = staleKey)

        assertFalse(repository.saveMessageIfCurrent(capturedEpoch, room.id, staleMessage))
        assertArrayEquals(ByteArray(32) { 8 }, staleKey)
        assertTrue(repository.getMessages(room.id).first().isEmpty())
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

    @Test
    fun attachmentKeysAreOwnedWipedAndNeverReachDashboardPreview() = runBlocking {
        val repository = InMemoryMessageRepository()
        val senderKey = ByteArray(608) { 3 }
        val attachmentKey = ByteArray(32) { 7 }
        val message = testMessage("attachment-keyed").copy(
            isMedia = true,
            attachmentId = "123e4567-e89b-12d3-a456-426614174000",
            attachmentCipherVersion = 1,
            attachmentKey = attachmentKey,
            senderPublicKey = senderKey
        )

        repository.saveMessage("forum_keys", message)

        val stored = repository.getMessages("forum_keys").first().single()
        assertArrayEquals(ByteArray(32), attachmentKey)
        assertArrayEquals(ByteArray(608), senderKey)
        assertArrayEquals(ByteArray(32) { 7 }, stored.attachmentKey)
        assertArrayEquals(ByteArray(608) { 3 }, stored.senderPublicKey)
        val preview = repository.getChatSessions().first().single().lastMessage
        assertEquals(null, preview)
        assertEquals(null, preview?.attachmentKey)
        assertEquals(null, preview?.senderPublicKey)

        repository.markAsRead("forum_keys", stored.id)
        val marked = repository.getMessages("forum_keys").first().single()
        assertArrayEquals(ByteArray(32) { 7 }, marked.attachmentKey)

        repository.forgetAttachmentKey("forum_keys", stored.id)
        assertEquals(null, repository.getMessages("forum_keys").first().single().attachmentKey)
        assertArrayEquals(ByteArray(32), marked.attachmentKey)

        repository.clearAllData()
        assertArrayEquals(ByteArray(32), stored.attachmentKey)
        assertArrayEquals(ByteArray(608), stored.senderPublicKey)
    }

    @Test
    fun nonExpiringChatHistoryEvictsOldestByCountAndWipesKeys() = runBlocking {
        val repository = InMemoryMessageRepository()
        val firstSenderKey = ByteArray(608) { 1 }
        val firstAttachmentKey = ByteArray(32) { 2 }
        val first = testMessage("oldest").copy(
            timestampMs = 1L,
            selfDestructDurationSec = 0,
            senderPublicKey = firstSenderKey,
            attachmentKey = firstAttachmentKey
        )
        repository.saveMessage("dm_flood", first)

        repeat(MAX_MESSAGES_PER_CHAT) { index ->
            repository.saveMessage(
                "dm_flood",
                testMessage("message-$index").copy(
                    timestampMs = 2L + index,
                    selfDestructDurationSec = 0
                )
            )
        }

        val messages = repository.getMessages("dm_flood").first()
        assertEquals(MAX_MESSAGES_PER_CHAT, messages.size)
        assertTrue(messages.none { it.id == "oldest" })
        assertArrayEquals(ByteArray(608), firstSenderKey)
        assertArrayEquals(ByteArray(32), firstAttachmentKey)
    }

    @Test
    fun perChatEvictionUsesTimestampThenIdInsteadOfArrivalOrder() = runBlocking {
        val repository = InMemoryMessageRepository()
        repository.saveMessage(
            "dm_ordered",
            testMessage("late-arrival").copy(timestampMs = 2_000L, selfDestructDurationSec = 0)
        )
        repository.saveMessage(
            "dm_ordered",
            testMessage("early-timestamp").copy(timestampMs = 1_000L, selfDestructDurationSec = 0)
        )
        repeat(MAX_MESSAGES_PER_CHAT - 1) { index ->
            repository.saveMessage(
                "dm_ordered",
                testMessage("filler-$index").copy(timestampMs = 3_000L + index, selfDestructDurationSec = 0)
            )
        }

        val messages = repository.getMessages("dm_ordered").first()
        assertEquals(MAX_MESSAGES_PER_CHAT, messages.size)
        assertTrue(messages.any { it.id == "late-arrival" })
        assertTrue(messages.none { it.id == "early-timestamp" })
    }

    @Test
    fun globalHistoryEvictsOldestAcrossChatsWithoutExpiry() = runBlocking {
        val repository = InMemoryMessageRepository()
        repeat(MAX_MESSAGES_TOTAL + 1) { index ->
            repository.saveMessage(
                "dm_${index % 11}",
                testMessage("global-$index").copy(selfDestructDurationSec = 0)
            )
        }

        val messages = (0 until 11).flatMap { chatIndex ->
            repository.getMessages("dm_$chatIndex").first()
        }
        assertEquals(MAX_MESSAGES_TOTAL, messages.size)
        assertTrue(messages.none { it.id == "global-0" })
    }

    @Test
    fun byteCapsEvictOldestAndRejectSingleOversizedMessage() = runBlocking {
        val repository = InMemoryMessageRepository()
        val firstSenderKey = ByteArray(608) { 7 }
        val firstAttachmentKey = ByteArray(32) { 8 }
        val large = "x".repeat(3 * 1024 * 1024)
        val first = testMessage("large-first").copy(
            content = large,
            selfDestructDurationSec = 0,
            senderPublicKey = firstSenderKey,
            attachmentKey = firstAttachmentKey
        )
        repository.saveMessage("dm_bytes", first)
        repository.saveMessage(
            "dm_bytes",
            testMessage("large-second").copy(content = large, selfDestructDurationSec = 0)
        )

        val afterEviction = repository.getMessages("dm_bytes").first()
        assertEquals(1, afterEviction.size)
        assertEquals("large-second", afterEviction.single().id)
        assertArrayEquals(ByteArray(608), firstSenderKey)
        assertArrayEquals(ByteArray(32), firstAttachmentKey)

        val oversizedKey = ByteArray(32) { 9 }
        repository.saveMessage(
            "dm_oversized",
            testMessage("too-large").copy(
                content = "y".repeat(5 * 1024 * 1024),
                senderPublicKey = ByteArray(608) { 6 },
                attachmentKey = oversizedKey,
                selfDestructDurationSec = 0
            )
        )
        assertTrue(repository.getMessages("dm_oversized").first().isEmpty())
        assertArrayEquals(ByteArray(32), oversizedKey)
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

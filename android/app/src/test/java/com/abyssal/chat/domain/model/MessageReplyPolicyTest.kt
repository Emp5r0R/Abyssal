package com.abyssal.chat.domain.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class MessageReplyPolicyTest {
    @Test
    fun sanitizeMessageId_trimsValidId() {
        assertEquals("message-1", MessageReplyPolicy.sanitizeMessageId("  message-1  "))
    }

    @Test
    fun sanitizeMessageId_rejectsBlankAndOversizedIds() {
        assertNull(MessageReplyPolicy.sanitizeMessageId("   "))
        assertNull(MessageReplyPolicy.sanitizeMessageId("x".repeat(129)))
        assertNull(MessageReplyPolicy.sanitizeMessageId("message\n1"))
    }

    @Test
    fun findAvailableTargetId_requiresMessageInCurrentRamState() {
        val message = Message(
            id = "message-1",
            sender = "You",
            receiver = null,
            content = "Ephemeral text",
            timestampMs = System.currentTimeMillis(),
            selfDestructDurationSec = 30
        )

        assertEquals(
            "message-1",
            MessageReplyPolicy.findAvailableTargetId("message-1", listOf(message))
        )
        assertNull(MessageReplyPolicy.findAvailableTargetId("missing", listOf(message)))
    }

    @Test
    fun findAvailableTargetId_rejectsExpiredMessage() {
        val expired = Message(
            id = "expired",
            sender = "Remote node",
            receiver = null,
            content = "Gone",
            timestampMs = System.currentTimeMillis() - 2_000L,
            selfDestructDurationSec = 1,
            readTimestampMs = System.currentTimeMillis() - 2_000L
        )

        assertNull(MessageReplyPolicy.findAvailableTargetId("expired", listOf(expired)))
    }

    @Test
    fun findAvailableTargetId_rejectsAbsoluteExpiryBeforeRead() {
        val expired = Message(
            id = "absolute-expired",
            sender = "Remote node",
            receiver = null,
            content = "Gone",
            timestampMs = System.currentTimeMillis() - 2_000L,
            selfDestructDurationSec = 30,
            absoluteExpirySec = 1
        )

        assertNull(MessageReplyPolicy.findAvailableTargetId("absolute-expired", listOf(expired)))
    }
}

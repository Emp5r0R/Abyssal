package com.abyssal.chat.domain.model

import org.junit.Assert.assertEquals
import org.junit.Test

class MessageSearchTest {
    private fun message(id: String, content: String, name: String? = null, file: String? = null) = Message(
        id = id, sender = "acct_x", receiver = null, content = content, timestampMs = 1L,
        selfDestructDurationSec = 0, isMedia = file != null, attachmentName = file, senderDisplayName = name
    )

    @Test
    fun matchesTextAttachmentNamesAndSendersCaseInsensitively() {
        val list = listOf(
            message("m1", "Meet at NOON", name = "Alice"),
            message("m2", "plan.pdf", file = "plan.pdf"),
            message("m3", "ok", name = "Carol Noonan")
        )
        assertEquals(listOf("m1", "m3"), searchMessages(list, " noon ").map { it.id })
        assertEquals(listOf("m2"), searchMessages(list, "PLAN").map { it.id })
        assertEquals(3, searchMessages(list, "").size)
        assertEquals(emptyList<Message>(), searchMessages(list, "zzz"))
    }
}

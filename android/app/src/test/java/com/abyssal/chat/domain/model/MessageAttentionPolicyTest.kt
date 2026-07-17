package com.abyssal.chat.domain.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class MessageAttentionPolicyTest {
    @Test
    fun `mentions match username boundaries case insensitively`() {
        assertTrue(MessageAttentionPolicy.mentionsUsername("ping @NebulaTiger93 now", "nebulatiger93"))
        assertFalse(MessageAttentionPolicy.mentionsUsername("ping @NebulaTiger930 now", "NebulaTiger93"))
        assertFalse(MessageAttentionPolicy.mentionsUsername("mail@NebulaTiger93 now", "NebulaTiger93"))
    }

    @Test
    fun `reply attention belongs only to original sender`() {
        val ownIds = setOf("mine-1")
        assertTrue(MessageAttentionPolicy.replyTargetsCurrentUser("Remote", "Local", "mine-1", ownIds))
        assertFalse(MessageAttentionPolicy.replyTargetsCurrentUser("Remote", "Local", "other", ownIds))
        assertFalse(MessageAttentionPolicy.replyTargetsCurrentUser("Local", "Local", "mine-1", ownIds))
    }

    @Test
    fun `reaction shortcuts require matching safe image metadata`() {
        assertEquals(":fire:", MessageAttentionPolicy.shortcodeForFileName("fire.gif"))
        assertEquals(
            ":gura_swag:",
            MessageAttentionPolicy.validatedReactionShortcode(":GURA_SWAG:", "gura_swag.png", "image/png")
        )
        assertNull(MessageAttentionPolicy.validatedReactionShortcode(":fire:", "other.gif", "image/gif"))
        assertNull(MessageAttentionPolicy.shortcodeForFileName("unsafe name.gif"))
    }

    @Test
    fun `exact shortcut resolves bundled filename`() {
        assertEquals(
            "fire.gif",
            MessageAttentionPolicy.exactReactionFileName(" :FIRE: ", listOf("fire.gif", "wave.gif"))
        )
        assertNull(MessageAttentionPolicy.exactReactionFileName(":missing:", listOf("fire.gif")))
    }
}

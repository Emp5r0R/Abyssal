package com.abyssal.chat.domain.model

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class MessageActionsTest {
    private fun message(id: String, sender: String, media: Boolean = false) = Message(
        id = id,
        sender = sender,
        receiver = null,
        content = "hello from $sender",
        timestampMs = 1L,
        selfDestructDurationSec = 0,
        isMedia = media
    )

    @Test
    fun codecRoundTripsTheWebWireFormat() {
        val actions = listOf(
            MessageAction.Reaction("m1", "👍", true),
            MessageAction.Delete("m1"),
            MessageAction.Edit("m1", "fixed")
        )
        for (action in actions) {
            val json = JSONObject(MessageActionCodec.encode("a1", action).toString())
            assertTrue(MessageActionCodec.isActionKind(json.optString("kind")))
            assertEquals(action, MessageActionCodec.decode(json, "a1"))
            assertNull(MessageActionCodec.decode(json, "other"))
        }
        // Exactly the JSON the web client sends.
        val web = JSONObject("""{"kind":"reaction","id":"a2","target_id":"m9","emoji":"❤️","active":false}""")
        assertEquals(MessageAction.Reaction("m9", "❤️", false), MessageActionCodec.decode(web, "a2"))
    }

    @Test
    fun codecRejectsUnknownEmojiBadIdsAndOversizedEdits() {
        fun decode(raw: String) = MessageActionCodec.decode(JSONObject(raw), "a1")
        assertNull(decode("""{"kind":"reaction","id":"a1","target_id":"m1","emoji":"🔥","active":true}"""))
        assertNull(decode("""{"kind":"reaction","id":"a1","target_id":"m1","emoji":"👍","active":"yes"}"""))
        assertNull(decode("""{"kind":"delete","id":"a1","target_id":"../x"}"""))
        assertNull(decode("""{"kind":"delete","id":"a1","target_id":"a1"}"""))
        assertNull(decode("""{"kind":"edit","id":"a1","target_id":"m1","content":"   "}"""))
        val long = "x".repeat(MessageActionCodec.MAX_EDIT_CHARS + 1)
        assertNull(decode("""{"kind":"edit","id":"a1","target_id":"m1","content":"$long"}"""))
        assertFalse(MessageActionCodec.isActionKind("text"))
    }

    @Test
    fun reactionsToggleOncePerPersonAndAreCapped() {
        val list = listOf(message("m1", "alice"))
        val once = MessageActionPolicy.apply(list, MessageAction.Reaction("m1", "👍", true), "Bob", "me", 5)
        val twice = MessageActionPolicy.apply(once.messages, MessageAction.Reaction("m1", "👍", true), "bob", "me", 6)
        assertFalse(twice.changed)
        assertEquals(
            listOf(MessageActionPolicy.ReactionCount("👍", 1, mine = true)),
            MessageActionPolicy.summary(once.messages[0], "BOB")
        )
        val off = MessageActionPolicy.apply(once.messages, MessageAction.Reaction("m1", "👍", false), "bob", "me", 7)
        assertTrue(off.messages[0].reactions.isEmpty())

        var many = list
        repeat(MessageActionPolicy.MAX_REACTORS_PER_EMOJI + 3) { index ->
            many = MessageActionPolicy.apply(many, MessageAction.Reaction("m1", "❤️", true), "user$index", "me", 1).messages
        }
        assertEquals(MessageActionPolicy.MAX_REACTORS_PER_EMOJI, many[0].reactions["❤️"]?.size)
    }

    @Test
    fun onlyTheSenderEditsTextOrDeletes() {
        val list = listOf(message("m1", "alice"), message("m2", "You", media = true), message("m3", "You"))
        val edit = MessageAction.Edit("m1", "hi @me")
        assertSame(list, MessageActionPolicy.apply(list, edit, "mallory", "me", 9).messages)
        val edited = MessageActionPolicy.apply(list, edit, "ALICE", "me", 9).messages[0]
        assertEquals("hi @me", edited.content)
        assertEquals(9L, edited.editedAtMs)
        assertTrue(edited.mentionsCurrentUser)
        assertFalse(MessageActionPolicy.apply(list, MessageAction.Edit("m2", "x"), "me", "me", 9).changed)

        // Your own messages are stored as "You"; the actor is your account ID.
        assertTrue(MessageActionPolicy.allowed(list[2], MessageAction.Edit("m3", "x"), "me", "me"))
        assertFalse(MessageActionPolicy.allowed(list[2], MessageAction.Delete("m3"), "alice", "me"))
        val deleted = MessageActionPolicy.apply(list, MessageAction.Delete("m2"), "ME", "me", 9)
        assertEquals(listOf("m1", "m3"), deleted.messages.map { it.id })
        assertEquals("m2", deleted.removed?.id)
        assertFalse(MessageActionPolicy.apply(list, MessageAction.Delete("gone"), "alice", "me", 9).changed)
    }
}

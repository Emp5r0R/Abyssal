package com.abyssal.chat.domain.model

import org.json.JSONObject
import java.util.Locale

/**
 * Reactions, edits and delete-for-everyone travel as their own encrypted
 * messages, like read receipts, using the same JSON fields as the web client.
 * Clients that do not know these kinds drop them without touching other state.
 */
sealed interface MessageAction {
    val targetId: String

    data class Reaction(override val targetId: String, val emoji: String, val active: Boolean) : MessageAction
    data class Delete(override val targetId: String) : MessageAction
    data class Edit(override val targetId: String, val content: String) : MessageAction
}

object MessageActionCodec {
    /** Emoji a message can be reacted with, in display order. Shared with the web client. */
    val REACTION_EMOJI: List<String> = listOf("👍", "❤️", "😂", "😮", "😢", "🙏")
    const val MAX_EDIT_CHARS = 8_000
    private val KINDS = setOf("reaction", "delete", "edit")

    fun isActionKind(kind: String?): Boolean = kind in KINDS

    fun encode(id: String, action: MessageAction): JSONObject {
        val json = JSONObject().put("id", id).put("target_id", action.targetId)
        return when (action) {
            is MessageAction.Reaction -> json.put("kind", "reaction").put("emoji", action.emoji).put("active", action.active)
            is MessageAction.Delete -> json.put("kind", "delete")
            is MessageAction.Edit -> json.put("kind", "edit").put("content", action.content)
        }
    }

    /** Reads an action whose `id` equals the relay's authoritative message id; null if invalid. */
    fun decode(json: JSONObject, authoritativeId: String): MessageAction? {
        val kind = json.optString("kind")
        if (!isActionKind(kind)) return null
        if (MessageReplyPolicy.sanitizeMessageId(json.optString("id")) != authoritativeId) return null
        val targetId = MessageReplyPolicy.sanitizeMessageId(json.optString("target_id")) ?: return null
        if (targetId == authoritativeId) return null
        return when (kind) {
            "reaction" -> {
                val emoji = json.optString("emoji").takeIf { it in REACTION_EMOJI } ?: return null
                val active = json.opt("active") as? Boolean ?: return null
                MessageAction.Reaction(targetId, emoji, active)
            }
            "delete" -> MessageAction.Delete(targetId)
            else -> {
                val content = json.optString("content").trim()
                if (content.isEmpty() || content.length > MAX_EDIT_CHARS) return null
                MessageAction.Edit(targetId, content)
            }
        }
    }
}

object MessageActionPolicy {
    /** Matches the relay's room member limit, so every member can react once per emoji. */
    const val MAX_REACTORS_PER_EMOJI = 117

    /** Your own messages are stored with sender "You"; others with their account ID. */
    private fun sentBy(message: Message, actor: String, currentUsername: String?): Boolean =
        if (message.sender == "You") currentUsername != null && actor.equals(currentUsername, ignoreCase = true)
        else message.sender.equals(actor, ignoreCase = true)

    /** Anyone in the conversation may react; only a message's sender may edit (text) or delete it. */
    fun allowed(target: Message, action: MessageAction, actor: String, currentUsername: String?): Boolean = when (action) {
        is MessageAction.Reaction -> true
        is MessageAction.Delete -> sentBy(target, actor, currentUsername)
        is MessageAction.Edit -> sentBy(target, actor, currentUsername) && !target.isMedia
    }

    data class Applied(val messages: List<Message>, val removed: Message? = null, val changed: Boolean = false)

    /** Applies [action] from [actor]; actions on messages no longer in memory are ignored. */
    fun apply(list: List<Message>, action: MessageAction, actor: String, currentUsername: String?, nowMs: Long): Applied {
        val index = list.indexOfFirst { it.id == action.targetId }
        if (index < 0) return Applied(list)
        val target = list[index]
        if (!allowed(target, action, actor, currentUsername)) return Applied(list)
        val next = list.toMutableList()
        when (action) {
            is MessageAction.Delete -> {
                next.removeAt(index)
                return Applied(next, removed = target, changed = true)
            }
            is MessageAction.Edit -> {
                if (target.content == action.content) return Applied(list)
                next[index] = target.copy(
                    content = action.content,
                    editedAtMs = nowMs,
                    mentionsCurrentUser = target.sender != "You" &&
                        MessageAttentionPolicy.mentionsUsername(action.content, currentUsername)
                )
            }
            is MessageAction.Reaction -> {
                val reactions = withReaction(target.reactions, action.emoji, actor, action.active)
                if (reactions == target.reactions) return Applied(list)
                next[index] = target.copy(reactions = reactions)
            }
        }
        return Applied(next, changed = true)
    }

    private fun withReaction(current: Map<String, List<String>>, emoji: String, actor: String, active: Boolean): Map<String, List<String>> {
        val key = actor.lowercase(Locale.ROOT)
        val people = current[emoji].orEmpty()
        if ((key in people) == active) return current
        if (active && people.size >= MAX_REACTORS_PER_EMOJI) return current
        val updated = if (active) people + key else people - key
        val next = LinkedHashMap(current)
        if (updated.isEmpty()) next.remove(emoji) else next[emoji] = updated
        return next
    }

    data class ReactionCount(val emoji: String, val count: Int, val mine: Boolean)

    /** Reactions in display order with counts and whether you reacted. */
    fun summary(message: Message, currentUsername: String?): List<ReactionCount> {
        val me = currentUsername?.lowercase(Locale.ROOT)
        return MessageActionCodec.REACTION_EMOJI.mapNotNull { emoji ->
            val people = message.reactions[emoji].orEmpty()
            if (people.isEmpty()) null else ReactionCount(emoji, people.size, me != null && me in people)
        }
    }
}

package com.abyssal.chat.domain.model

/**
 * Messages in a conversation that match [query], case-insensitively, by text,
 * attachment name or sender display name. A blank query matches everything.
 * Only messages still in memory can be found.
 */
fun searchMessages(messages: List<Message>, query: String): List<Message> {
    val needle = query.trim()
    if (needle.isEmpty()) return messages
    return messages.filter { message ->
        (!message.isMedia && message.content.contains(needle, ignoreCase = true)) ||
            message.attachmentName?.contains(needle, ignoreCase = true) == true ||
            message.senderDisplayName?.contains(needle, ignoreCase = true) == true
    }
}

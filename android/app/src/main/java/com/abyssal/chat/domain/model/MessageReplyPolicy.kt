package com.abyssal.chat.domain.model

object MessageReplyPolicy {
    private val messageIdPattern = Regex("[A-Za-z0-9_-]{1,128}")

    fun sanitizeMessageId(value: String?): String? {
        return value
            ?.trim()
            ?.takeIf(messageIdPattern::matches)
    }

    fun findAvailableTargetId(value: String?, messages: List<Message>): String? {
        val candidate = sanitizeMessageId(value) ?: return null
        return candidate.takeIf { id ->
            messages.any { message -> message.id == id && !message.isExpired }
        }
    }
}

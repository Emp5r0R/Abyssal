package com.abyssal.chat.domain.model

import java.util.Locale

object MessageAttentionPolicy {
    private val reactionName = Regex("[a-z0-9_]+")

    fun mentionRanges(content: String, username: String?): List<IntRange> {
        val safeUsername = username?.trim().orEmpty()
        if (safeUsername.isEmpty()) return emptyList()
        val pattern = Regex(
            "(?<![A-Za-z0-9_])@${Regex.escape(safeUsername)}(?![A-Za-z0-9_])",
            RegexOption.IGNORE_CASE
        )
        return pattern.findAll(content).map { it.range }.toList()
    }

    fun mentionsUsername(content: String, username: String?): Boolean {
        return mentionRanges(content, username).isNotEmpty()
    }

    fun replyTargetsCurrentUser(
        senderUsername: String,
        currentUsername: String?,
        replyToMessageId: String?,
        ownMessageIds: Set<String>
    ): Boolean {
        val safeUsername = currentUsername?.trim().orEmpty()
        val safeReplyId = replyToMessageId?.trim().orEmpty()
        return safeUsername.isNotEmpty() &&
            safeReplyId.isNotEmpty() &&
            !senderUsername.equals(safeUsername, ignoreCase = true) &&
            safeReplyId in ownMessageIds
    }

    fun shortcodeForFileName(fileName: String): String? {
        val normalized = fileName.substringAfterLast('/').lowercase(Locale.ROOT)
        val extension = normalized.substringAfterLast('.', missingDelimiterValue = "")
        if (extension != "gif" && extension != "png") return null
        val baseName = normalized.substringBeforeLast('.')
        if (!reactionName.matches(baseName)) return null
        return ":$baseName:"
    }

    fun validatedReactionShortcode(
        shortcode: String?,
        fileName: String,
        mimeType: String
    ): String? {
        val expected = shortcodeForFileName(fileName) ?: return null
        val normalizedMime = mimeType.lowercase(Locale.ROOT)
        if (normalizedMime != "image/gif" && normalizedMime != "image/png") return null
        return expected.takeIf { it.equals(shortcode?.trim(), ignoreCase = true) }
    }

    fun exactReactionFileName(shortcut: String, availableFileNames: Collection<String>): String? {
        val normalized = shortcut.trim().lowercase(Locale.ROOT)
        return availableFileNames.firstOrNull { fileName ->
            shortcodeForFileName(fileName) == normalized
        }
    }
}

package com.abyssal.chat.domain.model

object AttachmentSavePolicy {
    private const val MAX_FILE_NAME_CODE_POINTS = 160
    private const val MAX_EXTENSION_CODE_POINTS = 32

    fun canSave(message: Message): Boolean =
        message.isMedia &&
            !message.oneTimeView &&
            message.saveAllowed &&
            !message.attachmentId.isNullOrBlank()

    fun sanitizedFileName(name: String?): String {
        val cleaned = buildString {
            (name ?: "").codePoints().forEach { codePoint ->
                if (isUnsafe(codePoint)) append('_') else appendCodePoint(codePoint)
            }
        }.trim { it == ' ' || it == '.' }

        if (cleaned.isBlank()) return "attachment"
        if (cleaned.codePointCount(0, cleaned.length) <= MAX_FILE_NAME_CODE_POINTS) return cleaned

        val extensionStart = cleaned.lastIndexOf('.')
        val extension = extensionStart.takeIf { it > 0 }?.let(cleaned::substring)
            .takeIf {
                it != null && it.codePointCount(0, it.length) in 2..MAX_EXTENSION_CODE_POINTS
            }
        if (extension == null) return cleaned.takeCodePoints(MAX_FILE_NAME_CODE_POINTS)

        val extensionPoints = extension.codePointCount(0, extension.length)
        return cleaned.substring(0, extensionStart)
            .takeCodePoints(MAX_FILE_NAME_CODE_POINTS - extensionPoints)
            .trimEnd { it == ' ' || it == '.' } + extension
    }

    private fun isUnsafe(codePoint: Int): Boolean =
        codePoint in 0x00..0x1f ||
            codePoint == 0x7f ||
            codePoint in 0x202a..0x202e ||
            codePoint in 0x2066..0x2069 ||
            codePoint.toChar() in "\\/:*?\"<>|"

    private fun String.takeCodePoints(maxCount: Int): String {
        if (maxCount <= 0) return ""
        var end = 0
        var count = 0
        while (end < length && count < maxCount) {
            end += Character.charCount(codePointAt(end))
            count += 1
        }
        return substring(0, end)
    }
}

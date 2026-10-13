package com.abyssal.chat.presentation.screens

import com.abyssal.chat.domain.model.ChatSession

/** Plain-language room rules matching the web dashboard, e.g. "Text, images · vanish 10s after reading". */
internal fun ChatSession.roomPolicySummary(): String? {
    if (!isForum) return null

    val media = buildList {
        if (allowImages) add("images")
        if (allowVideos) add("videos")
        if (allowFiles) add("files")
    }
    val content = if (media.isEmpty()) "Text only" else "Text, " + media.joinToString(", ")
    val read = if (selfDestructTimerSec > 0) "vanish ${durationLabel(selfDestructTimerSec)} after reading" else "stays until the session ends"
    val absolute = if (enforceTextAbsoluteExpiry && overallExpirySec > 0) " · deleted ${durationLabel(overallExpirySec)} after sending" else ""
    return "$content · $read$absolute"
}

internal fun ChatSession.retentionSecondsLabel(): String =
    retentionLabel(
        if (enforceTextAbsoluteExpiry && overallExpirySec > 0) overallExpirySec else selfDestructTimerSec
    )

private fun retentionLabel(seconds: Int): String = if (seconds > 0) "${seconds}s" else "Never"

/** Compact duration such as 30s, 5m, 2h or 1d; whole units only when exact. */
internal fun durationLabel(seconds: Int): String = when {
    seconds >= 86_400 && seconds % 86_400 == 0 -> "${seconds / 86_400}d"
    seconds >= 3_600 && seconds % 3_600 == 0 -> "${seconds / 3_600}h"
    seconds >= 60 && seconds % 60 == 0 -> "${seconds / 60}m"
    else -> "${seconds}s"
}

package com.abyssal.chat.presentation.screens

import com.abyssal.chat.domain.model.ChatSession

internal fun ChatSession.roomPolicySummary(): String? {
    if (!isForum) return null

    val media = buildList {
        if (allowImages) add("IMG")
        if (allowVideos) add("VID")
        if (allowFiles) add("FILE")
    }.ifEmpty { listOf("TEXT") }
    val absolute = if (enforceTextAbsoluteExpiry) retentionLabel(overallExpirySec) else "Never"
    val access = if (roomVisibility.name == "PUBLIC") "PUBLIC" else "PRIVATE"
    return "$access · ${media.joinToString(" · ")} · READ ${retentionLabel(selfDestructTimerSec)} · ABS $absolute"
}

internal fun ChatSession.retentionSecondsLabel(): String =
    retentionLabel(
        if (enforceTextAbsoluteExpiry && overallExpirySec > 0) overallExpirySec else selfDestructTimerSec
    )

private fun retentionLabel(seconds: Int): String = if (seconds > 0) "${seconds}s" else "Never"

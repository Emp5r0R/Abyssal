package com.abyssal.chat.domain.model

class UpdatePromptPolicy(
    private val regularCheckIntervalMs: Long = 24L * 60L * 60L * 1000L,
    private val retryIntervalMs: Long = 30L * 60L * 1000L,
    private val reminderIntervalMs: Long = 2L * 60L * 60L * 1000L
) {
    private var nextCheckAtMs = 0L
    private var cancelledForProcess = false

    fun shouldCheck(nowMs: Long): Boolean = !cancelledForProcess && nowMs >= nextCheckAtMs

    fun markChecked(nowMs: Long) {
        nextCheckAtMs = safeAdd(nowMs, regularCheckIntervalMs)
    }

    fun markFailed(nowMs: Long) {
        nextCheckAtMs = safeAdd(nowMs, retryIntervalMs)
    }

    fun remindLater(nowMs: Long) {
        nextCheckAtMs = safeAdd(nowMs, reminderIntervalMs)
    }

    fun cancelForProcess() {
        cancelledForProcess = true
    }

    private fun safeAdd(nowMs: Long, intervalMs: Long): Long {
        require(nowMs >= 0L && intervalMs > 0L)
        return if (Long.MAX_VALUE - nowMs < intervalMs) Long.MAX_VALUE else nowMs + intervalMs
    }
}

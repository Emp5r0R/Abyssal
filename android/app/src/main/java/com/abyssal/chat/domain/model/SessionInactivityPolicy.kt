package com.abyssal.chat.domain.model

class SessionInactivityPolicy(
    private val elapsedRealtimeMs: () -> Long = { System.nanoTime() / 1_000_000L }
) {
    private var lastActivityMs: Long? = null
    private var timeoutMs: Long = 0L

    @Synchronized
    fun start(timeoutMs: Long) {
        require(timeoutMs > 0L)
        this.timeoutMs = timeoutMs
        lastActivityMs = elapsedRealtimeMs()
    }

    @Synchronized
    fun touch(): Boolean {
        if (!isActive() || isExpired()) return false
        lastActivityMs = elapsedRealtimeMs()
        return true
    }

    @Synchronized
    fun isActive(): Boolean = lastActivityMs != null

    @Synchronized
    fun isExpired(): Boolean {
        val lastActivity = lastActivityMs ?: return false
        return elapsedRealtimeMs() - lastActivity >= timeoutMs
    }

    @Synchronized
    fun remainingMs(): Long {
        val lastActivity = lastActivityMs ?: return 0L
        return (timeoutMs - (elapsedRealtimeMs() - lastActivity)).coerceAtLeast(0L)
    }

    @Synchronized
    fun clear() {
        lastActivityMs = null
        timeoutMs = 0L
    }
}

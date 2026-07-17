package com.abyssal.chat.domain.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SessionInactivityPolicyTest {
    @Test
    fun sessionExpiresAtStrictBoundary() {
        var now = 1_000L
        val policy = SessionInactivityPolicy { now }

        policy.start(timeoutMs = 5_000L)
        now = 5_999L
        assertFalse(policy.isExpired())
        assertEquals(1L, policy.remainingMs())

        now = 6_000L
        assertTrue(policy.isExpired())
        assertEquals(0L, policy.remainingMs())
        assertFalse(policy.touch())
    }

    @Test
    fun userActivityMovesDeadlineForward() {
        var now = 100L
        val policy = SessionInactivityPolicy { now }

        policy.start(timeoutMs = 1_000L)
        now = 800L
        assertTrue(policy.touch())
        now = 1_799L
        assertFalse(policy.isExpired())
        now = 1_800L
        assertTrue(policy.isExpired())
    }

    @Test
    fun clearRemovesActiveDeadline() {
        val policy = SessionInactivityPolicy { 42L }
        policy.start(timeoutMs = 1_000L)

        policy.clear()

        assertFalse(policy.isActive())
        assertFalse(policy.isExpired())
        assertEquals(0L, policy.remainingMs())
    }

    @Test(expected = IllegalArgumentException::class)
    fun timeoutMustBePositive() {
        SessionInactivityPolicy { 0L }.start(timeoutMs = 0L)
    }
}

package com.abyssal.chat.domain.model

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UpdatePromptPolicyTest {
    @Test
    fun successfulCheckWaitsForRegularInterval() {
        val policy = UpdatePromptPolicy(
            regularCheckIntervalMs = 1000L,
            retryIntervalMs = 100L,
            reminderIntervalMs = 500L
        )

        assertTrue(policy.shouldCheck(0L))
        policy.markChecked(10L)
        assertFalse(policy.shouldCheck(1009L))
        assertTrue(policy.shouldCheck(1010L))
    }

    @Test
    fun remindLaterUsesShorterRamOnlyDelay() {
        val policy = UpdatePromptPolicy(
            regularCheckIntervalMs = 1000L,
            retryIntervalMs = 100L,
            reminderIntervalMs = 500L
        )

        policy.remindLater(25L)
        assertFalse(policy.shouldCheck(524L))
        assertTrue(policy.shouldCheck(525L))
    }

    @Test
    fun failureRetriesAndCancelLastsForProcess() {
        val policy = UpdatePromptPolicy(
            regularCheckIntervalMs = 1000L,
            retryIntervalMs = 100L,
            reminderIntervalMs = 500L
        )

        policy.markFailed(50L)
        assertFalse(policy.shouldCheck(149L))
        assertTrue(policy.shouldCheck(150L))
        policy.cancelForProcess()
        assertFalse(policy.shouldCheck(Long.MAX_VALUE))
    }
}

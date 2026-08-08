package com.abyssal.chat.data.repository

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidDisguiseManagerTest {
    @Test
    fun launcherTransitionEnablesTargetBeforeDisablingOpposite() {
        val events = mutableListOf<String>()

        val result = applyLauncherAliasTransition(
            enableTarget = { events += "enable" },
            disableOpposite = { events += "disable" },
            rollbackTarget = { events += "rollback" }
        )

        assertTrue(result)
        assertEquals(listOf("enable", "disable"), events)
    }

    @Test
    fun launcherTransitionRollsBackTargetWhenOppositeDisableFails() {
        val events = mutableListOf<String>()

        val result = applyLauncherAliasTransition(
            enableTarget = { events += "enable" },
            disableOpposite = {
                events += "disable"
                error("package manager failure")
            },
            rollbackTarget = { events += "rollback" }
        )

        assertFalse(result)
        assertEquals(listOf("enable", "disable", "rollback"), events)
    }
}

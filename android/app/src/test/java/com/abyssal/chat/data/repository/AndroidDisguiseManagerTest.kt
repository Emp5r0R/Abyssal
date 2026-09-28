package com.abyssal.chat.data.repository

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidDisguiseManagerTest {
    @Test
    fun launcherAliasChangesWaitForTheHostToLeaveTheForeground() {
        val applied = mutableListOf<Boolean>()
        val alias = DeferredLauncherAlias { applied += it; true }

        alias.request(disguised = true)
        assertTrue(alias.isPending)
        assertEquals(emptyList<Boolean>(), applied)

        assertTrue(alias.flush())
        assertEquals(listOf(true), applied)
        assertFalse(alias.isPending)
        assertTrue(alias.flush())
        assertEquals(listOf(true), applied)

        // Re-requesting the installed state, or toggling back before a flush,
        // must not touch PackageManager at all.
        alias.request(disguised = true)
        assertFalse(alias.isPending)
        alias.request(disguised = false)
        alias.request(disguised = true)
        assertTrue(alias.flush())
        assertEquals(listOf(true), applied)
    }

    @Test
    fun failedLauncherAliasChangeStaysPendingForTheNextBackground() {
        var succeed = false
        val alias = DeferredLauncherAlias { succeed }
        alias.request(disguised = true)
        assertFalse(alias.flush())
        assertTrue(alias.isPending)
        succeed = true
        assertTrue(alias.flush())
        assertFalse(alias.isPending)

        alias.request(disguised = false)
        alias.markInstalled(disguised = false)
        assertFalse(alias.isPending)
    }

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

    @Test
    fun camouflageVerifierAcceptsOnlyCalculatorSafePins() {
        assertTrue(isValidCamouflagePin("482613"))
        assertTrue(isValidCamouflagePin("12+345"))
        assertTrue(isValidCamouflagePin("(12)*345"))
        assertFalse(isValidCamouflagePin("4826"))
        assertFalse(isValidCamouflagePin("123"))
        assertFalse(isValidCamouflagePin("12 34"))
        assertFalse(isValidCamouflagePin("PIN4826"))
        assertFalse(isValidCamouflagePin("9".repeat(33)))
    }

    @Test
    fun duressPinMustNotEqualUnlockPin() {
        assertTrue(camouflagePinsAreDistinct("482613", ""))
        assertTrue(camouflagePinsAreDistinct("482613", "739102"))
        assertFalse(camouflagePinsAreDistinct("482613", "482613"))
    }

    @Test
    fun camouflageConfigurationRequiresVerifierBeforeEnable() {
        assertTrue(isValidCamouflageConfiguration(false, "", ""))
        assertTrue(isValidCamouflageConfiguration(true, "482613", "739102"))
        assertTrue(isValidCamouflageConfiguration(true, "482613", ""))
        assertFalse(isValidCamouflageConfiguration(true, "4826", "739102"))
        assertFalse(isValidCamouflageConfiguration(true, "482613", "482613"))
        assertFalse(isValidCamouflageConfiguration(true, "482613", "123"))
    }
}

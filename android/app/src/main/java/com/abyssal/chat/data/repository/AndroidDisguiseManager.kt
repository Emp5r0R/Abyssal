package com.abyssal.chat.data.repository

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import com.abyssal.chat.domain.repository.IDisguiseManager

internal fun applyLauncherAliasTransition(
    enableTarget: () -> Unit,
    disableOpposite: () -> Unit,
    rollbackTarget: () -> Unit
): Boolean {
    return try {
        enableTarget()
        try {
            disableOpposite()
        } catch (error: RuntimeException) {
            runCatching(rollbackTarget)
            throw error
        }
        true
    } catch (_: RuntimeException) {
        false
    }
}

class AndroidDisguiseManager(private val context: Context) : IDisguiseManager {

    // Secrets intentionally live only for the lifetime of the application process. If
    // Android recreates the process, the old calculator alias is stale and must not
    // fall back to a predictable unlock code.
    private var disguiseEnabled = false
    private var unlockPin = ""
    private var duressPin = ""

    init {
        resetStaleCamouflage()
    }

    override fun setDisguiseEnabled(enabled: Boolean) {
        if (applyLauncherIcon(enabled)) {
            disguiseEnabled = enabled
        }
    }

    override fun isDisguiseEnabled(): Boolean {
        return disguiseEnabled
    }

    override fun savePin(pin: String) {
        unlockPin = pin.trim()
    }

    override fun saveDuressPin(pin: String) {
        duressPin = pin
    }

    override fun verifyPin(pin: String): Boolean {
        return unlockPin.isNotEmpty() && pin == unlockPin
    }

    override fun verifyDuressPin(pin: String): Boolean {
        return duressPin.isNotBlank() && pin == duressPin
    }

    override fun getPin(): String {
        return unlockPin
    }

    override fun getDuressPin(): String {
        return duressPin
    }

    private fun applyLauncherIcon(enabled: Boolean): Boolean {
        val packageManager = context.packageManager
        val abyssal = ComponentName(context, "${context.packageName}.LauncherAbyssal")
        val calculator = ComponentName(context, "${context.packageName}.LauncherCalculator")
        val enable = PackageManager.COMPONENT_ENABLED_STATE_ENABLED
        val disable = PackageManager.COMPONENT_ENABLED_STATE_DISABLED
        val first = if (enabled) calculator else abyssal
        val second = if (enabled) abyssal else calculator
        return applyLauncherAliasTransition(
            enableTarget = {
                packageManager.setComponentEnabledSetting(first, enable, PackageManager.DONT_KILL_APP)
            },
            disableOpposite = {
                packageManager.setComponentEnabledSetting(second, disable, PackageManager.DONT_KILL_APP)
            },
            rollbackTarget = {
                packageManager.setComponentEnabledSetting(first, disable, PackageManager.DONT_KILL_APP)
            }
        )
    }

    private fun resetStaleCamouflage() {
        // Package-manager alias state survives process death, but the PIN does not.
        // Reset both aliases so a stale calculator cover can never accept a default PIN.
        applyLauncherIcon(enabled = false)
    }
}

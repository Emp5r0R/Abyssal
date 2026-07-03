package com.abyssal.chat.data.repository

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import com.abyssal.chat.domain.repository.IDisguiseManager

class AndroidDisguiseManager(private val context: Context) : IDisguiseManager {

    private var disguiseEnabled = false
    private var unlockPin = DEFAULT_PIN

    init {
        applyLauncherIcon(disguiseEnabled)
    }

    override fun setDisguiseEnabled(enabled: Boolean) {
        disguiseEnabled = enabled
        applyLauncherIcon(enabled)
    }

    override fun isDisguiseEnabled(): Boolean {
        return disguiseEnabled
    }

    override fun savePin(pin: String) {
        unlockPin = pin.ifBlank { DEFAULT_PIN }
    }

    override fun verifyPin(pin: String): Boolean {
        return pin == unlockPin
    }

    override fun getPin(): String {
        return unlockPin
    }

    private companion object {
        const val DEFAULT_PIN = "2026"
    }

    private fun applyLauncherIcon(enabled: Boolean) {
        val packageManager = context.packageManager
        val abyssal = ComponentName(context, "${context.packageName}.LauncherAbyssal")
        val calculator = ComponentName(context, "${context.packageName}.LauncherCalculator")
        packageManager.setComponentEnabledSetting(
            abyssal,
            if (enabled) {
                PackageManager.COMPONENT_ENABLED_STATE_DISABLED
            } else {
                PackageManager.COMPONENT_ENABLED_STATE_ENABLED
            },
            PackageManager.DONT_KILL_APP
        )
        packageManager.setComponentEnabledSetting(
            calculator,
            if (enabled) {
                PackageManager.COMPONENT_ENABLED_STATE_ENABLED
            } else {
                PackageManager.COMPONENT_ENABLED_STATE_DISABLED
            },
            PackageManager.DONT_KILL_APP
        )
    }
}

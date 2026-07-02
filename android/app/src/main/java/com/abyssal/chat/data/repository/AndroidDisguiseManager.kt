package com.abyssal.chat.data.repository

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import com.abyssal.chat.domain.repository.IDisguiseManager

class AndroidDisguiseManager(private val context: Context) : IDisguiseManager {
    
    private val sharedPrefs = context.getSharedPreferences("mirage_settings", Context.MODE_PRIVATE)

    override fun setDisguiseEnabled(enabled: Boolean) {
        sharedPrefs.edit().putBoolean("disguise_active", enabled).apply()
        
        val pm = context.packageManager
        // Map ComponentName values to the package aliases in our AndroidManifest
        val abyssalComponent = ComponentName(context, "com.abyssal.chat.LauncherAbyssal")
        val calculatorComponent = ComponentName(context, "com.abyssal.chat.LauncherCalculator")
        
        try {
            if (enabled) {
                // Enable Calculator launcher interface
                pm.setComponentEnabledSetting(
                    calculatorComponent,
                    PackageManager.COMPONENT_ENABLED_STATE_ENABLED,
                    PackageManager.DONT_KILL_APP
                )
                // Disable default Abyssal launcher entry
                pm.setComponentEnabledSetting(
                    abyssalComponent,
                    PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                    PackageManager.DONT_KILL_APP
                )
            } else {
                // Enable default Abyssal launcher entry
                pm.setComponentEnabledSetting(
                    abyssalComponent,
                    PackageManager.COMPONENT_ENABLED_STATE_ENABLED,
                    PackageManager.DONT_KILL_APP
                )
                // Disable Calculator launcher interface
                pm.setComponentEnabledSetting(
                    calculatorComponent,
                    PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                    PackageManager.DONT_KILL_APP
                )
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    override fun isDisguiseEnabled(): Boolean {
        return sharedPrefs.getBoolean("disguise_active", false)
    }

    override fun savePin(pin: String) {
        sharedPrefs.edit().putString("unlock_pin", pin).apply()
    }

    override fun verifyPin(pin: String): Boolean {
        val saved = sharedPrefs.getString("unlock_pin", "2026") ?: "2026"
        return pin == saved
    }

    override fun getPin(): String {
        return sharedPrefs.getString("unlock_pin", "2026") ?: "2026"
    }
}

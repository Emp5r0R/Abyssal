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
    private var credentialVerifier = InMemoryCamouflageVerifier()

    init {
        resetStaleCamouflage()
    }

    override fun configure(enabled: Boolean, unlockPin: String, duressPin: String): Boolean {
        if (!enabled) {
            // Keep the verifier material intact if PackageManager cannot complete the
            // alias transition. This avoids turning a failed disable into a partial wipe.
            if (!applyLauncherIcon(enabled = false)) return false
            credentialVerifier.destroy()
            credentialVerifier = InMemoryCamouflageVerifier()
            disguiseEnabled = false
            return true
        }

        // Prepare a complete verifier before exposing the calculator alias. A failed
        // alias transition destroys the candidate and leaves the active verifier intact.
        val candidate = InMemoryCamouflageVerifier()
        if (!candidate.configure(unlockPin, duressPin)) return false
        // Updating verifier material while already disguised does not require a
        // package-manager transition and avoids disturbing an active alias.
        if (!disguiseEnabled && !applyLauncherIcon(enabled = true)) {
            candidate.destroy()
            return false
        }
        credentialVerifier.destroy()
        credentialVerifier = candidate
        disguiseEnabled = true
        return true
    }

    override fun isDisguiseEnabled(): Boolean {
        return disguiseEnabled
    }

    override fun clear() {
        // Teardown prioritizes removing verifier material even if PackageManager is
        // unavailable. A fresh process resets stale aliases during initialization.
        credentialVerifier.destroy()
        credentialVerifier = InMemoryCamouflageVerifier()
        disguiseEnabled = false
        runCatching { applyLauncherIcon(enabled = false) }
    }

    override fun verifyPin(pin: String): Boolean = credentialVerifier.verifyUnlock(pin)

    override fun verifyDuressPin(pin: String): Boolean = credentialVerifier.verifyDuress(pin)

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

internal fun isValidCamouflagePin(value: String): Boolean =
    // A four-digit PIN has only 10,000 guesses if the process heap is copied.
    // PBKDF2 slows that search but cannot create entropy, so require six chars.
    value.length in 6..32 && value.all { it in "0123456789.+-*/()" }

internal fun camouflagePinsAreDistinct(unlockPin: String, duressPin: String): Boolean =
    duressPin.isBlank() || unlockPin != duressPin

internal fun isValidCamouflageConfiguration(
    enabled: Boolean,
    unlockPin: String,
    duressPin: String
): Boolean = !enabled || (
    isValidCamouflagePin(unlockPin) &&
        (duressPin.isBlank() ||
            (isValidCamouflagePin(duressPin) && camouflagePinsAreDistinct(unlockPin, duressPin)))
    )

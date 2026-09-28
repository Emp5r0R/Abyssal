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

/**
 * Tracks the requested launcher alias separately from the installed one.
 *
 * Disabling the alias that hosts the running task makes Android close that task
 * even with DONT_KILL_APP, which would drop the user to the home screen right
 * after choosing a PIN. Requests are therefore applied only by [flush], which the
 * host calls once the app has left the foreground.
 */
internal class DeferredLauncherAlias(private val apply: (disguised: Boolean) -> Boolean) {
    private var installed = false
    private var pending: Boolean? = null

    val isPending: Boolean get() = pending != null

    fun request(disguised: Boolean) {
        pending = disguised.takeIf { it != installed }
    }

    /** Applies a pending request; keeps it pending for a later retry on failure. */
    fun flush(): Boolean {
        val target = pending ?: return true
        if (!apply(target)) return false
        installed = target
        pending = null
        return true
    }

    /** Records an alias state installed out of band (startup reset or teardown). */
    fun markInstalled(disguised: Boolean) {
        installed = disguised
        pending = null
    }
}

class AndroidDisguiseManager(private val context: Context) : IDisguiseManager {

    // Secrets intentionally live only for the lifetime of the application process. If
    // Android recreates the process, the old calculator alias is stale and must not
    // fall back to a predictable unlock code.
    private var disguiseEnabled = false
    private var credentialVerifier = InMemoryCamouflageVerifier()
    private val launcherAlias = DeferredLauncherAlias(::applyLauncherIcon)

    init {
        resetStaleCamouflage()
    }

    override fun configure(enabled: Boolean, unlockPin: String, duressPin: String): Boolean {
        if (!enabled) {
            credentialVerifier.destroy()
            credentialVerifier = InMemoryCamouflageVerifier()
            disguiseEnabled = false
            launcherAlias.request(disguised = false)
            return true
        }

        // Prepare a complete verifier before requesting the calculator alias. The
        // alias itself switches when the app is backgrounded (see DeferredLauncherAlias).
        val candidate = InMemoryCamouflageVerifier()
        if (!candidate.configure(unlockPin, duressPin)) return false
        credentialVerifier.destroy()
        credentialVerifier = candidate
        disguiseEnabled = true
        launcherAlias.request(disguised = true)
        return true
    }

    override fun applyPendingLauncherAlias() {
        launcherAlias.flush()
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
        launcherAlias.markInstalled(disguised = false)
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

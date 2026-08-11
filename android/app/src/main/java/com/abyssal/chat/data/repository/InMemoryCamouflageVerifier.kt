package com.abyssal.chat.data.repository

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

internal data class CamouflageVerifierState(
    val hasUnlockVerifier: Boolean,
    val hasDuressVerifier: Boolean,
    val unlockSaltBytes: Int,
    val unlockDigestBytes: Int,
    val duressSaltBytes: Int,
    val duressDigestBytes: Int,
    val failedUnlockAttempts: Int,
    val blockedUntilNanos: Long
)

/** RAM-only credential verifier. Every public operation is serialized on [lock]. */
internal class InMemoryCamouflageVerifier(
    private val nanoTime: () -> Long = System::nanoTime,
    private val fillRandom: (ByteArray) -> Unit = SecureRandom()::nextBytes,
    private val keyDeriver: (CharArray, ByteArray) -> ByteArray? = ::derivePbkdf2,
    private val baseBackoffNanos: Long = BASE_UNLOCK_BACKOFF_NANOS,
    private val maxUnlockFailures: Int = MAX_UNLOCK_FAILURES,
    private val maxBackoffSteps: Int = MAX_BACKOFF_STEPS
) {
    private val lock = Any()
    private var unlockDigest: ByteArray? = null
    private var unlockSalt: ByteArray? = null
    private var duressDigest: ByteArray? = null
    private var duressSalt: ByteArray? = null
    private var failedUnlockAttempts = 0
    private var blockedUntilNanos = 0L

    fun configure(unlockPin: String, duressPin: String): Boolean = synchronized(lock) {
        val normalizedUnlock = unlockPin.trim()
        val normalizedDuress = duressPin.trim()
        if (!isValidCamouflageConfiguration(true, normalizedUnlock, normalizedDuress)) return false

        val nextUnlockSalt = ByteArray(SALT_BYTES).also(fillRandom)
        val nextUnlockDigest = derive(normalizedUnlock, nextUnlockSalt) ?: run {
            nextUnlockSalt.fill(0)
            return false
        }
        val nextDuressSalt = normalizedDuress.takeIf(String::isNotBlank)?.let {
            ByteArray(SALT_BYTES).also(fillRandom)
        }
        val nextDuressDigest = if (nextDuressSalt == null) {
            null
        } else {
            derive(normalizedDuress, nextDuressSalt) ?: run {
                nextUnlockSalt.fill(0)
                nextUnlockDigest.fill(0)
                nextDuressSalt.fill(0)
                return false
            }
        }

        clearLocked()
        unlockSalt = nextUnlockSalt
        unlockDigest = nextUnlockDigest
        duressSalt = nextDuressSalt
        duressDigest = nextDuressDigest
        true
    }

    fun verifyUnlock(pin: String): Boolean = synchronized(lock) {
        val expected = unlockDigest ?: return false
        val salt = unlockSalt ?: return false
        val now = nanoTime()
        if (now < blockedUntilNanos) return false
        val candidate = pin.trim()
        if (!isValidCamouflagePin(candidate)) {
            registerFailureLocked(now)
            return false
        }
        val actual = derive(candidate, salt) ?: return false
        val matched = MessageDigest.isEqual(expected, actual)
        actual.fill(0)
        if (matched) resetThrottleLocked() else registerFailureLocked(now)
        matched
    }

    fun verifyDuress(pin: String): Boolean = synchronized(lock) {
        val expected = duressDigest ?: return false
        val salt = duressSalt ?: return false
        val now = nanoTime()
        if (now < blockedUntilNanos) return false
        val candidate = pin.trim()
        if (!isValidCamouflagePin(candidate)) {
            registerFailureLocked(now)
            return false
        }
        val actual = derive(candidate, salt) ?: run {
            registerFailureLocked(now)
            return false
        }
        val matched = MessageDigest.isEqual(expected, actual)
        actual.fill(0)
        if (matched) resetThrottleLocked() else registerFailureLocked(now)
        matched
    }

    fun destroy() = synchronized(lock) {
        clearLocked()
    }

    internal fun stateSnapshot(): CamouflageVerifierState = synchronized(lock) {
        CamouflageVerifierState(
            hasUnlockVerifier = unlockDigest != null,
            hasDuressVerifier = duressDigest != null,
            unlockSaltBytes = unlockSalt?.size ?: 0,
            unlockDigestBytes = unlockDigest?.size ?: 0,
            duressSaltBytes = duressSalt?.size ?: 0,
            duressDigestBytes = duressDigest?.size ?: 0,
            failedUnlockAttempts = failedUnlockAttempts,
            blockedUntilNanos = blockedUntilNanos
        )
    }

    private fun derive(value: String, salt: ByteArray): ByteArray? {
        if (salt.size != SALT_BYTES) return null
        val password = value.toCharArray()
        return try {
            keyDeriver(password, salt)
        } catch (_: Exception) {
            null
        } finally {
            password.fill('\u0000')
        }
    }

    private fun registerFailureLocked(nowNanos: Long) {
        failedUnlockAttempts = (failedUnlockAttempts + 1)
            .coerceAtMost(maxUnlockFailures + maxBackoffSteps)
        if (failedUnlockAttempts >= maxUnlockFailures) {
            val exponent = (failedUnlockAttempts - maxUnlockFailures).coerceIn(0, maxBackoffSteps)
            blockedUntilNanos = nowNanos + (baseBackoffNanos shl exponent)
        }
    }

    private fun resetThrottleLocked() {
        failedUnlockAttempts = 0
        blockedUntilNanos = 0L
    }

    private fun clearLocked() {
        unlockDigest?.fill(0)
        unlockSalt?.fill(0)
        duressDigest?.fill(0)
        duressSalt?.fill(0)
        unlockDigest = null
        unlockSalt = null
        duressDigest = null
        duressSalt = null
        resetThrottleLocked()
    }

    private companion object {
        const val MAX_UNLOCK_FAILURES = 5
        const val MAX_BACKOFF_STEPS = 4
        const val BASE_UNLOCK_BACKOFF_NANOS = 30_000_000_000L
        const val SALT_BYTES = 16
        const val VERIFIER_BITS = 256
        const val PBKDF2_ITERATIONS = 120_000
        const val PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256"

        fun derivePbkdf2(password: CharArray, salt: ByteArray): ByteArray? {
            val spec = PBEKeySpec(password, salt, PBKDF2_ITERATIONS, VERIFIER_BITS)
            return try {
                SecretKeyFactory.getInstance(PBKDF2_ALGORITHM)
                    .generateSecret(spec)
                    .encoded
            } catch (_: Exception) {
                null
            } finally {
                spec.clearPassword()
            }
        }
    }
}

package com.abyssal.chat.data.repository

import java.security.MessageDigest
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class InMemoryCamouflageVerifierTest {
    @Test
    fun productionPbkdf2VerifierMatchesConfiguredPins() {
        val verifier = InMemoryCamouflageVerifier()

        assertTrue(verifier.configure("482613", "739102"))
        assertTrue(verifier.verifyUnlock("482613"))
        assertTrue(verifier.verifyDuress("739102"))
        assertFalse(verifier.verifyUnlock("111111"))
        verifier.destroy()
    }

    @Test
    fun configurationKeepsOnlySaltedVerifierMaterialAndClearsTransientPasswords() {
        val passwordBuffers = Collections.synchronizedList(mutableListOf<CharArray>())
        val verifier = testVerifier(
            keyDeriver = { password, salt ->
                passwordBuffers += password
                fastDigest(password, salt)
            }
        )

        assertTrue(verifier.configure("482613", "739102"))

        val state = verifier.stateSnapshot()
        assertTrue(state.hasUnlockVerifier)
        assertTrue(state.hasDuressVerifier)
        assertEquals(16, state.unlockSaltBytes)
        assertEquals(32, state.unlockDigestBytes)
        assertEquals(16, state.duressSaltBytes)
        assertEquals(32, state.duressDigestBytes)
        assertTrue(passwordBuffers.all { password -> password.all { it == '\u0000' } })
        assertTrue(verifier.verifyUnlock("482613"))
        assertTrue(verifier.verifyDuress("739102"))
        assertFalse(verifier.verifyUnlock("739102"))
    }

    @Test
    fun invalidOrIdenticalPinsCannotReplaceAnExistingVerifier() {
        val verifier = testVerifier()
        assertTrue(verifier.configure("482613", "739102"))

        assertFalse(verifier.configure("1234", "739102"))
        assertFalse(verifier.configure("482613", "482613"))

        assertTrue(verifier.verifyUnlock("482613"))
        assertTrue(verifier.verifyDuress("739102"))
    }

    @Test
    fun unlockAndDuressShareExponentialBackoffWithoutDoubleCounting() {
        var now = 0L
        val verifier = testVerifier(
            nanoTime = { now },
            baseBackoffNanos = 100L,
            maxUnlockFailures = 2,
            maxBackoffSteps = 2
        )
        assertTrue(verifier.configure("482613", "739102"))

        assertFalse(verifier.verifyDuress("111111"))
        assertFalse(verifier.verifyUnlock("111111"))
        assertEquals(1, verifier.stateSnapshot().failedUnlockAttempts)

        assertFalse(verifier.verifyDuress("111111"))
        assertFalse(verifier.verifyUnlock("111111"))
        assertEquals(2, verifier.stateSnapshot().failedUnlockAttempts)
        assertEquals(100L, verifier.stateSnapshot().blockedUntilNanos)

        now = 50L
        assertFalse(verifier.verifyDuress("739102"))
        assertFalse(verifier.verifyUnlock("482613"))
        assertEquals(2, verifier.stateSnapshot().failedUnlockAttempts)

        now = 100L
        assertFalse(verifier.verifyDuress("111111"))
        assertFalse(verifier.verifyUnlock("111111"))
        assertEquals(3, verifier.stateSnapshot().failedUnlockAttempts)
        assertEquals(300L, verifier.stateSnapshot().blockedUntilNanos)
    }

    @Test
    fun successfulUnlockResetsFailureAndBackoffState() {
        var now = 0L
        val verifier = testVerifier(
            nanoTime = { now },
            baseBackoffNanos = 100L,
            maxUnlockFailures = 2
        )
        assertTrue(verifier.configure("482613", ""))
        assertFalse(verifier.verifyUnlock("111111"))
        assertEquals(1, verifier.stateSnapshot().failedUnlockAttempts)

        now = 1L
        assertTrue(verifier.verifyUnlock("482613"))
        assertEquals(0, verifier.stateSnapshot().failedUnlockAttempts)
        assertEquals(0L, verifier.stateSnapshot().blockedUntilNanos)
    }

    @Test
    fun destroyZeroizesSaltAndDigestBuffersAndDisablesVerification() {
        val retainedMaterial = Collections.synchronizedList(mutableListOf<ByteArray>())
        val verifier = testVerifier(
            fillRandom = { salt ->
                salt.fill(7)
                retainedMaterial += salt
            },
            keyDeriver = { password, salt ->
                fastDigest(password, salt).also { retainedMaterial += it }
            }
        )
        assertTrue(verifier.configure("482613", "739102"))
        assertTrue(retainedMaterial.any { material -> material.any { it != 0.toByte() } })

        verifier.destroy()

        assertTrue(retainedMaterial.all { material -> material.all { it == 0.toByte() } })
        assertEquals(
            CamouflageVerifierState(false, false, 0, 0, 0, 0, 0, 0L),
            verifier.stateSnapshot()
        )
        assertFalse(verifier.verifyUnlock("482613"))
        assertFalse(verifier.verifyDuress("739102"))
    }

    @Test
    fun concurrentVerificationAttemptsAreSerialized() {
        val activeDerivations = AtomicInteger(0)
        val maxConcurrentDerivations = AtomicInteger(0)
        val verifier = testVerifier(
            maxUnlockFailures = 100,
            keyDeriver = { password, salt ->
                val active = activeDerivations.incrementAndGet()
                maxConcurrentDerivations.accumulateAndGet(active, ::maxOf)
                try {
                    Thread.sleep(5)
                    fastDigest(password, salt)
                } finally {
                    activeDerivations.decrementAndGet()
                }
            }
        )
        assertTrue(verifier.configure("482613", ""))
        maxConcurrentDerivations.set(0)

        val workers = 8
        val ready = CountDownLatch(workers)
        val start = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(workers)
        try {
            val futures = (0 until workers).map {
                pool.submit<Boolean> {
                    ready.countDown()
                    start.await()
                    verifier.verifyUnlock("111111")
                }
            }
            assertTrue(ready.await(2, TimeUnit.SECONDS))
            start.countDown()
            futures.forEach { assertFalse(it.get(2, TimeUnit.SECONDS)) }
        } finally {
            pool.shutdownNow()
        }

        assertEquals(1, maxConcurrentDerivations.get())
        assertEquals(workers, verifier.stateSnapshot().failedUnlockAttempts)
    }

    private fun testVerifier(
        nanoTime: () -> Long = { 0L },
        fillRandom: (ByteArray) -> Unit = { bytes -> bytes.indices.forEach { bytes[it] = (it + 1).toByte() } },
        keyDeriver: (CharArray, ByteArray) -> ByteArray? = ::fastDigest,
        baseBackoffNanos: Long = 100L,
        maxUnlockFailures: Int = 5,
        maxBackoffSteps: Int = 4
    ): InMemoryCamouflageVerifier = InMemoryCamouflageVerifier(
        nanoTime = nanoTime,
        fillRandom = fillRandom,
        keyDeriver = keyDeriver,
        baseBackoffNanos = baseBackoffNanos,
        maxUnlockFailures = maxUnlockFailures,
        maxBackoffSteps = maxBackoffSteps
    )

    private companion object {
        fun fastDigest(password: CharArray, salt: ByteArray): ByteArray {
            val digest = MessageDigest.getInstance("SHA-256")
            password.forEach { char ->
                digest.update((char.code ushr 8).toByte())
                digest.update(char.code.toByte())
            }
            digest.update(salt)
            return digest.digest()
        }
    }
}

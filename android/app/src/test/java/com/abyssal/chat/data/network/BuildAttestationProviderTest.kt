package com.abyssal.chat.data.network

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

class BuildAttestationProviderTest {
    @Test
    fun acceptsOnlyNativeVerifiedBakedIdentity() {
        var verifiedBuildId: String? = null
        var verifiedSource: String? = null
        var verifiedSignature: ByteArray? = null
        val result = buildAttestationFromConfig(
            configured = true,
            buildIdValue = "android@2.3.0",
            signatureValue = "A".repeat(86),
            sourceCommitValue = "a".repeat(40),
            expectedVersion = "2.3.0",
            verifier = BuildSignatureVerifier { buildId, sourceCommit, signature ->
                verifiedBuildId = buildId
                verifiedSource = sourceCommit
                verifiedSignature = signature.copyOf()
                true
            }
        )

        assertEquals(
            BuildAttestation("android", "2.3.0", "A".repeat(86), "a".repeat(40)),
            result
        )
        assertEquals("android@2.3.0", verifiedBuildId)
        assertEquals("a".repeat(40), verifiedSource)
        assertArrayEquals(ByteArray(64), verifiedSignature)
    }

    @Test
    fun rejectsMalformedOrUntrustedIdentityBeforeAdmission() {
        var calls = 0
        val verifier = BuildSignatureVerifier { _, _, _ ->
            calls += 1
            true
        }

        assertNull(buildAttestationFromConfig(
            configured = false,
            buildIdValue = "android@2.3.0",
            signatureValue = "A".repeat(86),
            sourceCommitValue = "a".repeat(40),
            expectedVersion = "2.3.0",
            verifier = verifier
        ))
        assertNull(buildAttestationFromConfig(
            configured = true,
            buildIdValue = "android@2.3.0",
            signatureValue = "A".repeat(85) + "=",
            sourceCommitValue = "a".repeat(40),
            expectedVersion = "2.3.0",
            verifier = verifier
        ))
        assertNull(buildAttestationFromConfig(
            configured = true,
            buildIdValue = "android@2.3.0",
            signatureValue = "A".repeat(86),
            sourceCommitValue = "A".repeat(40),
            expectedVersion = "2.3.0",
            verifier = verifier
        ))
        assertNull(buildAttestationFromConfig(
            configured = true,
            buildIdValue = "android@2.3.1",
            signatureValue = "A".repeat(86),
            sourceCommitValue = "a".repeat(40),
            expectedVersion = "2.3.0",
            verifier = verifier
        ))
        assertEquals(0, calls)
    }

    @Test
    fun rejectsAWellFormedIdentityWhenNativeSignatureCheckFails() {
        val result = buildAttestationFromConfig(
            configured = true,
            buildIdValue = "android@2.3.0",
            signatureValue = "A".repeat(86),
            sourceCommitValue = "a".repeat(40),
            expectedVersion = "2.3.0",
            verifier = BuildSignatureVerifier { _, _, _ -> false }
        )

        assertNull(result)
    }

    @Test
    fun nativeTrustRootRejectsAnInvalidSignature() {
        assertFalse(
            NativeBuildSignatureVerifier.verify(
                "android@2.3.0",
                "a".repeat(40),
                ByteArray(64)
            )
        )
    }
}

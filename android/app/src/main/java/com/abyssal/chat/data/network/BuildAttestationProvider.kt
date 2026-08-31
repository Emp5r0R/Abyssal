package com.abyssal.chat.data.network

import com.abyssal.chat.BuildConfig
import java.util.Base64
import org.json.JSONObject
import uniffi.abyssal_core.releaseTrustAnchorConfigured
import uniffi.abyssal_core.verifyReleaseBuildSignature

private const val SIGNATURE_BYTES = 64
private val BUILD_ID_PATTERN = Regex(
    "^android@((?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*))$"
)
private val SIGNATURE_PATTERN = Regex("^[A-Za-z0-9_-]{86}$")
private val SOURCE_COMMIT_PATTERN = Regex("^[0-9a-f]{40}$")

internal data class BuildAttestation(
    val platform: String,
    val version: String,
    val signatureBase64Url: String,
    val sourceCommit: String
) {
    fun toJson(): String = JSONObject()
        .put("platform", platform)
        .put("version", version)
        .put("build_signature_b64", signatureBase64Url)
        .toString()
}

internal fun interface BuildAttestationProvider {
    fun current(): BuildAttestation?
}

internal fun interface BuildSignatureVerifier {
    fun verify(buildId: String, sourceCommit: String, signature: ByteArray): Boolean
}

internal object NativeBuildSignatureVerifier : BuildSignatureVerifier {
    override fun verify(buildId: String, sourceCommit: String, signature: ByteArray): Boolean {
        return runCatching {
            if (!releaseTrustAnchorConfigured()) return@runCatching false
            verifyReleaseBuildSignature(buildId, sourceCommit, signature)
            true
        }.getOrDefault(false)
    }
}

internal fun buildAttestationFromConfig(
    configured: Boolean,
    buildIdValue: String,
    signatureValue: String,
    sourceCommitValue: String,
    expectedVersion: String,
    verifier: BuildSignatureVerifier = NativeBuildSignatureVerifier
): BuildAttestation? {
    if (!configured) return null
    val version = BUILD_ID_PATTERN.matchEntire(buildIdValue)?.groupValues?.get(1)
        ?.takeIf { it == expectedVersion }
        ?: return null
    if (!SIGNATURE_PATTERN.matches(signatureValue)) return null
    if (!SOURCE_COMMIT_PATTERN.matches(sourceCommitValue)) return null
    val decoded = runCatching { Base64.getUrlDecoder().decode(signatureValue) }.getOrNull()
        ?.takeIf { it.size == SIGNATURE_BYTES }
        ?: return null
    if (Base64.getUrlEncoder().withoutPadding().encodeToString(decoded) != signatureValue) {
        decoded.fill(0)
        return null
    }
    return try {
        if (!verifier.verify(buildIdValue, sourceCommitValue, decoded)) return null
        BuildAttestation(
            platform = "android",
            version = version,
            signatureBase64Url = signatureValue,
            sourceCommit = sourceCommitValue
        )
    } finally {
        decoded.fill(0)
    }
}

internal object AndroidBuildAttestationProvider : BuildAttestationProvider {
    override fun current(): BuildAttestation? {
        return buildAttestationFromConfig(
            configured = BuildConfig.RELEASE_BUILD_CONFIGURED,
            buildIdValue = BuildConfig.RELEASE_BUILD_ID,
            signatureValue = BuildConfig.RELEASE_BUILD_SIGNATURE_B64,
            sourceCommitValue = BuildConfig.RELEASE_SOURCE_COMMIT,
            expectedVersion = BuildConfig.VERSION_NAME
        )
    }
}

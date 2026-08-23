package com.abyssal.chat.data.network

import com.abyssal.chat.BuildConfig
import org.json.JSONObject

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

internal object AndroidBuildAttestationProvider : BuildAttestationProvider {
    private val buildId = Regex(
        "^android@((?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*))$"
    )
    private val signature = Regex("^[A-Za-z0-9_-]{86}$")
    private val sourceCommit = Regex("^[0-9a-f]{40}$")

    override fun current(): BuildAttestation? {
        if (!BuildConfig.RELEASE_BUILD_CONFIGURED) return null
        val version = buildId.matchEntire(BuildConfig.RELEASE_BUILD_ID)?.groupValues?.get(1)
            ?: return null
        if (!signature.matches(BuildConfig.RELEASE_BUILD_SIGNATURE_B64)) return null
        if (!sourceCommit.matches(BuildConfig.RELEASE_SOURCE_COMMIT)) return null
        return BuildAttestation(
            platform = "android",
            version = version,
            signatureBase64Url = BuildConfig.RELEASE_BUILD_SIGNATURE_B64,
            sourceCommit = BuildConfig.RELEASE_SOURCE_COMMIT
        )
    }
}

package com.abyssal.chat.data.network

import org.json.JSONObject
import uniffi.abyssal_core.inspectReleaseManifest
import uniffi.abyssal_core.releaseTrustAnchorConfigured

internal data class VerifiedAndroidRelease(
    val apkSha256Hex: String,
    val apkSizeBytes: Long,
    val sourceCommit: String
)

internal data class AndroidReleaseExpectation(
    val version: String,
    val apkName: String,
    val buildSignatureBase64Url: String? = null,
    val sourceCommit: String? = null
)

internal fun interface ReleaseManifestInspector {
    fun inspect(
        manifestBytes: ByteArray,
        signatureBytes: ByteArray,
        nowMs: Long,
        expectation: AndroidReleaseExpectation
    ): VerifiedAndroidRelease?
}

internal object NativeReleaseManifestInspector : ReleaseManifestInspector {
    private val decimal = Regex("^(?:0|[1-9][0-9]*)$")
    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val sourceCommit = Regex("^[0-9a-f]{40}$")

    override fun inspect(
        manifestBytes: ByteArray,
        signatureBytes: ByteArray,
        nowMs: Long,
        expectation: AndroidReleaseExpectation
    ): VerifiedAndroidRelease? {
        if (nowMs < 0L || !releaseTrustAnchorConfigured()) return null
        val canonical = runCatching {
            inspectReleaseManifest(manifestBytes, signatureBytes)
        }.getOrNull() ?: return null
        return runCatching {
            val document = JSONObject(canonical)
            val notBefore = document.canonicalLong("not_before_ms") ?: return null
            val expiresAt = document.canonicalLong("expires_at_ms") ?: return null
            if (nowMs < notBefore || nowMs >= expiresAt) return null
            val buildId = "android@${expectation.version}"
            val revoked = document.optJSONArray("revoked_build_ids") ?: return null
            for (index in 0 until revoked.length()) {
                if (revoked.optString(index) == buildId) return null
            }
            val builds = document.optJSONArray("builds") ?: return null
            var matching: JSONObject? = null
            for (index in 0 until builds.length()) {
                val build = builds.optJSONObject(index) ?: return null
                if (build.optString("build_id") != buildId) continue
                if (matching != null) return null
                matching = build
            }
            val build = matching ?: return null
            val commit = build.optString("source_commit").takeIf(sourceCommit::matches) ?: return null
            if (expectation.sourceCommit != null && expectation.sourceCommit != commit) return null
            if (expectation.buildSignatureBase64Url != null &&
                expectation.buildSignatureBase64Url != build.optString("build_signature_b64")) return null
            val assets = build.optJSONArray("assets") ?: return null
            var apk: JSONObject? = null
            for (index in 0 until assets.length()) {
                val asset = assets.optJSONObject(index) ?: return null
                if (asset.optString("name") != expectation.apkName) continue
                if (apk != null) return null
                apk = asset
            }
            val asset = apk ?: return null
            val digest = asset.optString("sha256_hex").takeIf(sha256::matches) ?: return null
            val size = asset.canonicalLong("size")?.takeIf { it > 0L } ?: return null
            VerifiedAndroidRelease(digest, size, commit)
        }.getOrNull()
    }

    private fun JSONObject.canonicalLong(name: String): Long? {
        val value = opt(name) as? String ?: return null
        if (!decimal.matches(value)) return null
        return value.toLongOrNull()
    }
}

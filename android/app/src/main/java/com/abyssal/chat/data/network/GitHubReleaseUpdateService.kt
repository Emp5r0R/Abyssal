package com.abyssal.chat.data.network

import com.abyssal.chat.domain.model.AvailableAppUpdate
import com.abyssal.chat.domain.model.AppUpdateCheckResult
import com.abyssal.chat.domain.model.ReleaseVerificationStatus
import com.abyssal.chat.domain.repository.IAppUpdateService
import java.nio.charset.StandardCharsets
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.CacheControl
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.ResponseBody
import org.json.JSONObject

internal fun interface ReleaseAssetLoader {
    suspend fun load(url: HttpUrl, maximumBytes: Long): ByteArray
}

class GitHubReleaseUpdateService internal constructor(
    private val client: OkHttpClient,
    currentVersionName: String,
    apiUrl: String,
    private val repository: String = OFFICIAL_REPOSITORY,
    expectedApiHost: String = OFFICIAL_API_HOST,
    private val allowInsecureApiForTests: Boolean = false,
    private val assetLoader: ReleaseAssetLoader? = null,
    private val manifestInspector: ReleaseManifestInspector = NativeReleaseManifestInspector,
    private val currentBuildAttestation: BuildAttestation? = AndroidBuildAttestationProvider.current()
) : IAppUpdateService {
    private val currentVersion = StableVersion.parse(currentVersionName)
        ?: throw IllegalArgumentException("Invalid current version")
    private val releaseAssets = OfficialReleaseAssetClient(
        client,
        "Abyssal-Android/${currentVersion.display}"
    )
    private val apiEndpoint = apiUrl.toHttpUrlOrNull()
        ?.takeIf { endpoint ->
            endpoint.host == expectedApiHost &&
                endpoint.encodedPath == "/repos/$repository/releases/latest" &&
                endpoint.query == null &&
                endpoint.fragment == null &&
                endpoint.username.isEmpty() &&
                endpoint.password.isEmpty() &&
                (endpoint.isHttps || allowInsecureApiForTests)
        }
        ?: throw IllegalArgumentException("Invalid update endpoint")

    override suspend fun checkCurrentRelease(): AppUpdateCheckResult = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url(apiEndpoint)
            .cacheControl(CacheControl.FORCE_NETWORK)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "Abyssal-Android/${currentVersion.display}")
            .get()
            .build()

        val candidate = awaitHttpResponse(client.newCall(request)) { response ->
            check(response.request.url == apiEndpoint && response.isSuccessful)
            val body = requireNotNull(response.body)
            val reportedLength = body.contentLength()
            check(reportedLength < 0L || reportedLength <= MAX_RESPONSE_BYTES)
            val raw = readBounded(body, MAX_RESPONSE_BYTES)
            try {
                parseReleaseDescriptor(JSONObject(String(raw, StandardCharsets.UTF_8)))
            } finally {
                raw.fill(0)
            }
        } ?: return@withContext rejected()
        if (candidate.version < currentVersion) return@withContext rejected()

        val currentIdentity = if (candidate.version == currentVersion) {
            currentBuildAttestation?.takeIf { attestation ->
                attestation.platform == "android" && attestation.version == currentVersion.display
            } ?: return@withContext rejected()
        } else {
            null
        }

        val manifestBytes = loadAsset(candidate.manifestUrl, MAX_MANIFEST_BYTES)
        val signatureBytes = loadAsset(candidate.signatureUrl, SIGNATURE_BYTES)
        try {
            if (signatureBytes.size != SIGNATURE_BYTES.toInt()) return@withContext rejected()
            val verified = manifestInspector.inspect(
                manifestBytes,
                signatureBytes,
                System.currentTimeMillis(),
                AndroidReleaseExpectation(
                    version = candidate.version.display,
                    apkName = candidate.apkName,
                    buildSignatureBase64Url = currentIdentity?.signatureBase64Url,
                    sourceCommit = currentIdentity?.sourceCommit
                )
            ) ?: return@withContext rejected()
            if (verified.apkSizeBytes != candidate.apkSizeBytes) return@withContext rejected()
            val update = if (candidate.version > currentVersion) {
                AvailableAppUpdate(
                    versionName = candidate.version.display,
                    apkDownloadUrl = candidate.apkUrl.toString(),
                    releasePageUrl = candidate.releasePageUrl.toString(),
                    apkSha256Hex = verified.apkSha256Hex,
                    apkSizeBytes = verified.apkSizeBytes,
                    sourceCommit = verified.sourceCommit
                )
            } else {
                null
            }
            AppUpdateCheckResult(ReleaseVerificationStatus.VERIFIED, update)
        } finally {
            manifestBytes.fill(0)
            signatureBytes.fill(0)
        }
    }

    private fun rejected() = AppUpdateCheckResult(ReleaseVerificationStatus.REJECTED)

    internal fun parseReleaseCandidate(release: JSONObject): ReleaseCandidate? {
        return parseReleaseDescriptor(release)?.takeIf { it.version > currentVersion }
    }

    private fun parseReleaseDescriptor(release: JSONObject): ReleaseCandidate? {
        if (release.optBoolean("draft", false) || release.optBoolean("prerelease", false)) return null
        val tagName = release.optString("tag_name")
        val availableVersion = StableVersion.parse(tagName) ?: return null
        if (tagName != "v${availableVersion.display}") return null

        val versionName = availableVersion.display
        val apkName = "abyssal-android-$versionName-universal-release.apk"
        val expectedNames = setOf(apkName, MANIFEST_ASSET_NAME, SIGNATURE_ASSET_NAME)
        val assets = release.optJSONArray("assets") ?: return null
        if (assets.length() > MAX_RELEASE_ASSETS) return null
        val matches = LinkedHashMap<String, Pair<HttpUrl, Long>>()
        for (index in 0 until assets.length()) {
            val asset = assets.optJSONObject(index) ?: continue
            val name = asset.optString("name")
            if (name !in expectedNames) continue
            if (matches.containsKey(name)) return null
            val size = asset.optLong("size", -1L)
            val bounds = when (name) {
                apkName -> MIN_APK_BYTES..MAX_APK_BYTES
                MANIFEST_ASSET_NAME -> 1L..MAX_MANIFEST_BYTES
                else -> SIGNATURE_BYTES..SIGNATURE_BYTES
            }
            if (size !in bounds) return null
            val contentType = asset.optString("content_type")
            if (name == apkName && contentType.isNotBlank() && contentType != APK_CONTENT_TYPE) {
                return null
            }
            val expectedPath = "/$repository/releases/download/$tagName/$name"
            val url = officialGitHubUrl(asset.optString("browser_download_url"), expectedPath)
                ?: return null
            matches[name] = url to size
        }
        if (matches.keys != expectedNames) return null
        val releasePage = officialGitHubUrl(
            release.optString("html_url"),
            "/$repository/releases/tag/$tagName"
        ) ?: return null
        return ReleaseCandidate(
            version = availableVersion,
            apkName = apkName,
            apkUrl = requireNotNull(matches[apkName]).first,
            apkSizeBytes = requireNotNull(matches[apkName]).second,
            manifestUrl = requireNotNull(matches[MANIFEST_ASSET_NAME]).first,
            signatureUrl = requireNotNull(matches[SIGNATURE_ASSET_NAME]).first,
            releasePageUrl = releasePage
        )
    }

    private suspend fun loadAsset(url: HttpUrl, maximumBytes: Long): ByteArray {
        return assetLoader?.load(url, maximumBytes) ?: releaseAssets.loadBytes(url, maximumBytes)
    }

    private fun readBounded(body: ResponseBody, maximumBytes: Long): ByteArray {
        return BoundedInputReader.read(body.byteStream(), maximumBytes)
            ?: error("Update metadata exceeds the safety limit")
    }

    private fun officialGitHubUrl(raw: String, expectedPath: String): HttpUrl? {
        return raw.toHttpUrlOrNull()?.takeIf { url ->
            url.isHttps && url.host == OFFICIAL_DOWNLOAD_HOST && url.port == 443 &&
                url.encodedPath == expectedPath && url.query == null && url.fragment == null &&
                url.username.isEmpty() && url.password.isEmpty()
        }
    }

    internal data class ReleaseCandidate(
        val version: StableVersion,
        val apkName: String,
        val apkUrl: HttpUrl,
        val apkSizeBytes: Long,
        val manifestUrl: HttpUrl,
        val signatureUrl: HttpUrl,
        val releasePageUrl: HttpUrl
    )

    internal data class StableVersion(
        val major: Int,
        val minor: Int,
        val patch: Int
    ) : Comparable<StableVersion> {
        val display: String = "$major.$minor.$patch"

        override fun compareTo(other: StableVersion): Int =
            compareValuesBy(this, other, StableVersion::major, StableVersion::minor, StableVersion::patch)

        companion object {
            private val PATTERN = Regex("^v?(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$")

            fun parse(raw: String): StableVersion? {
                val match = PATTERN.matchEntire(raw.trim()) ?: return null
                val parts = match.groupValues.drop(1).map { value ->
                    value.toIntOrNull()?.takeIf { it <= MAX_VERSION_PART } ?: return null
                }
                return StableVersion(parts[0], parts[1], parts[2])
            }
        }
    }

    private companion object {
        const val OFFICIAL_REPOSITORY = "Emp5r0R/Abyssal"
        const val OFFICIAL_API_HOST = "api.github.com"
        const val OFFICIAL_DOWNLOAD_HOST = "github.com"
        const val MANIFEST_ASSET_NAME = "release-manifest-v1.json"
        const val SIGNATURE_ASSET_NAME = "release-manifest-v1.sig"
        const val APK_CONTENT_TYPE = "application/vnd.android.package-archive"
        const val MAX_VERSION_PART = 1_000_000
        const val MAX_RESPONSE_BYTES = 512L * 1024L
        const val MAX_MANIFEST_BYTES = 256L * 1024L
        const val SIGNATURE_BYTES = 64L
        const val MIN_APK_BYTES = 1024L * 1024L
        const val MAX_APK_BYTES = 256L * 1024L * 1024L
        const val MAX_RELEASE_ASSETS = 128
    }
}

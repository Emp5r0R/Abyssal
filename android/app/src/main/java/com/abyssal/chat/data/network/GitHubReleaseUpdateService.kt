package com.abyssal.chat.data.network

import com.abyssal.chat.domain.model.AvailableAppUpdate
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

class GitHubReleaseUpdateService(
    private val client: OkHttpClient,
    currentVersionName: String,
    apiUrl: String,
    private val repository: String = OFFICIAL_REPOSITORY,
    expectedApiHost: String = OFFICIAL_API_HOST,
    allowInsecureApiForTests: Boolean = false
) : IAppUpdateService {
    private val currentVersion = StableVersion.parse(currentVersionName)
        ?: throw IllegalArgumentException("Invalid current version")
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

    override suspend fun findAvailableUpdate(): AvailableAppUpdate? = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url(apiEndpoint)
            .cacheControl(CacheControl.FORCE_NETWORK)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "Abyssal-Android/${currentVersion.display}")
            .get()
            .build()

        client.newCall(request).execute().use { response ->
            check(response.request.url == apiEndpoint && response.isSuccessful)
            val body = requireNotNull(response.body)
            val reportedLength = body.contentLength()
            check(reportedLength < 0L || reportedLength <= MAX_RESPONSE_BYTES)
            val raw = readBounded(body)
            try {
                parseRelease(JSONObject(String(raw, StandardCharsets.UTF_8)))
            } finally {
                raw.fill(0)
            }
        }
    }

    private fun readBounded(body: ResponseBody): ByteArray {
        return BoundedInputReader.read(body.byteStream(), MAX_RESPONSE_BYTES)
            ?: error("Update metadata exceeds the safety limit")
    }

    internal fun parseRelease(release: JSONObject): AvailableAppUpdate? {
        if (release.optBoolean("draft", false) || release.optBoolean("prerelease", false)) return null
        val tagName = release.optString("tag_name")
        val availableVersion = StableVersion.parse(tagName) ?: return null
        if (availableVersion <= currentVersion) return null

        val versionName = availableVersion.display
        val expectedAssetName = "abyssal-android-$versionName-universal-release.apk"
        val expectedAssetPath = "/$repository/releases/download/$tagName/$expectedAssetName"
        val assets = release.optJSONArray("assets") ?: return null
        var apkUrl: HttpUrl? = null
        for (index in 0 until assets.length()) {
            val asset = assets.optJSONObject(index) ?: continue
            if (asset.optString("name") != expectedAssetName) continue
            if (asset.optLong("size", -1L) !in MIN_APK_BYTES..MAX_APK_BYTES) return null
            val contentType = asset.optString("content_type")
            if (contentType.isNotBlank() && contentType != APK_CONTENT_TYPE) return null
            apkUrl = officialGitHubUrl(asset.optString("browser_download_url"), expectedAssetPath)
                ?: return null
            break
        }
        val downloadUrl = apkUrl ?: return null
        val releasePage = officialGitHubUrl(
            release.optString("html_url"),
            "/$repository/releases/tag/$tagName"
        ) ?: return null

        return AvailableAppUpdate(
            versionName = versionName,
            apkDownloadUrl = downloadUrl.toString(),
            releasePageUrl = releasePage.toString()
        )
    }

    private fun officialGitHubUrl(raw: String, expectedPath: String): HttpUrl? {
        return raw.toHttpUrlOrNull()?.takeIf { url ->
            url.isHttps &&
                url.host == OFFICIAL_DOWNLOAD_HOST &&
                url.encodedPath == expectedPath &&
                url.query == null &&
                url.fragment == null &&
                url.username.isEmpty() &&
                url.password.isEmpty()
        }
    }

    private data class StableVersion(
        val major: Int,
        val minor: Int,
        val patch: Int
    ) : Comparable<StableVersion> {
        val display: String = "$major.$minor.$patch"

        override fun compareTo(other: StableVersion): Int {
            return compareValuesBy(this, other, StableVersion::major, StableVersion::minor, StableVersion::patch)
        }

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
        const val APK_CONTENT_TYPE = "application/vnd.android.package-archive"
        const val MAX_VERSION_PART = 1_000_000
        const val MAX_RESPONSE_BYTES = 512L * 1024L
        const val MIN_APK_BYTES = 1024L * 1024L
        const val MAX_APK_BYTES = 256L * 1024L * 1024L
    }
}

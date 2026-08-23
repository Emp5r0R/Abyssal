package com.abyssal.chat.data.network

import kotlinx.coroutines.runBlocking
import com.abyssal.chat.domain.model.ReleaseVerificationStatus
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class GitHubReleaseUpdateServiceTest {
    @Test
    fun fetchesOnlyNewerOfficialStableApk() = runBlocking {
        val server = MockWebServer()
        server.enqueue(MockResponse().setBody(releaseJson("v1.8.1").toString()))
        server.start()
        try {
            val service = GitHubReleaseUpdateService(
                client = OkHttpClient.Builder().followRedirects(false).build(),
                currentVersionName = "1.8.0",
                apiUrl = server.url("/repos/Emp5r0R/Abyssal/releases/latest").toString(),
                expectedApiHost = server.hostName,
                allowInsecureApiForTests = true,
                assetLoader = ReleaseAssetLoader { url, maximum ->
                    when (url.encodedPath.substringAfterLast('/')) {
                        "release-manifest-v1.json" -> "manifest".toByteArray()
                        "release-manifest-v1.sig" -> ByteArray(64)
                        else -> error("unexpected asset")
                    }.also { require(it.size.toLong() <= maximum) }
                },
                manifestInspector = ReleaseManifestInspector { _, _, _, expectation ->
                    assertEquals("1.8.1", expectation.version)
                    assertEquals(
                        "abyssal-android-1.8.1-universal-release.apk",
                        expectation.apkName
                    )
                    VerifiedAndroidRelease("a".repeat(64), 16L * 1024L * 1024L, "1".repeat(40))
                }
            )

            val result = service.checkCurrentRelease()
            val update = result.update
            val request = server.takeRequest()

            assertEquals(ReleaseVerificationStatus.VERIFIED, result.verificationStatus)
            assertEquals("1.8.1", update?.versionName)
            assertEquals(
                "https://github.com/Emp5r0R/Abyssal/releases/download/v1.8.1/" +
                    "abyssal-android-1.8.1-universal-release.apk",
                update?.apkDownloadUrl
            )
            assertEquals("a".repeat(64), update?.apkSha256Hex)
            assertEquals(16L * 1024L * 1024L, update?.apkSizeBytes)
            assertEquals("1".repeat(40), update?.sourceCommit)
            assertEquals("no-cache", request.getHeader("Cache-Control"))
            assertEquals("application/vnd.github+json", request.getHeader("Accept"))
            assertTrue(request.getHeader("User-Agent")?.startsWith("Abyssal-Android/") == true)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun ignoresCurrentOlderDraftPrereleaseAndNonStableVersions() {
        val service = parserService("1.8.0")

        assertNull(service.parseReleaseCandidate(releaseJson("v1.8.0")))
        assertNull(service.parseReleaseCandidate(releaseJson("v1.7.9")))
        assertNull(service.parseReleaseCandidate(releaseJson("v1.8.1").put("draft", true)))
        assertNull(service.parseReleaseCandidate(releaseJson("v1.8.1").put("prerelease", true)))
        assertNull(service.parseReleaseCandidate(releaseJson("v1.8.1-beta.1")))
    }

    @Test
    fun rejectsUntrustedOrMalformedDownloadMetadata() {
        val service = parserService("1.8.0")
        val wrongHost = releaseJson("v1.8.1").also { release ->
            release.getJSONArray("assets").getJSONObject(0).put(
                "browser_download_url",
                "https://example.com/abyssal-android-1.8.1-universal-release.apk"
            )
        }
        val insecure = releaseJson("v1.8.1").also { release ->
            release.getJSONArray("assets").getJSONObject(0).put(
                "browser_download_url",
                "http://github.com/Emp5r0R/Abyssal/releases/download/v1.8.1/" +
                    "abyssal-android-1.8.1-universal-release.apk"
            )
        }
        val wrongName = releaseJson("v1.8.1").also { release ->
            release.getJSONArray("assets").getJSONObject(0).put("name", "untrusted.apk")
        }
        val oversized = releaseJson("v1.8.1").also { release ->
            release.getJSONArray("assets").getJSONObject(0).put("size", 300L * 1024L * 1024L)
        }

        assertNull(service.parseReleaseCandidate(wrongHost))
        assertNull(service.parseReleaseCandidate(insecure))
        assertNull(service.parseReleaseCandidate(wrongName))
        assertNull(service.parseReleaseCandidate(oversized))
    }

    @Test
    fun rejectsInsecureProductionApiEndpoint() {
        assertThrows(IllegalArgumentException::class.java) {
            GitHubReleaseUpdateService(
                client = OkHttpClient(),
                currentVersionName = "1.8.0",
                apiUrl = "http://api.github.com/repos/Emp5r0R/Abyssal/releases/latest"
            )
        }
    }

    @Test
    fun rejectsOversizedChunkedReleaseMetadata() = runBlocking {
        val server = MockWebServer()
        server.enqueue(
            MockResponse().setChunkedBody("x".repeat(512 * 1024 + 1), 8192)
        )
        server.start()
        try {
            val service = GitHubReleaseUpdateService(
                client = OkHttpClient(),
                currentVersionName = "1.8.0",
                apiUrl = server.url("/repos/Emp5r0R/Abyssal/releases/latest").toString(),
                expectedApiHost = server.hostName,
                allowInsecureApiForTests = true
            )

            assertTrue(runCatching { service.checkCurrentRelease() }.isFailure)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun rejectsReleaseWhenSignedManifestDoesNotAuthorizeApk() = runBlocking {
        val server = MockWebServer()
        server.enqueue(MockResponse().setBody(releaseJson("v1.8.1").toString()))
        server.start()
        try {
            val service = GitHubReleaseUpdateService(
                client = OkHttpClient(),
                currentVersionName = "1.8.0",
                apiUrl = server.url("/repos/Emp5r0R/Abyssal/releases/latest").toString(),
                expectedApiHost = server.hostName,
                allowInsecureApiForTests = true,
                assetLoader = ReleaseAssetLoader { url, _ ->
                    if (url.encodedPath.endsWith(".sig")) ByteArray(64) else byteArrayOf(1)
                },
                manifestInspector = ReleaseManifestInspector { _, _, _, _ -> null }
            )

            val result = service.checkCurrentRelease()
            assertEquals(ReleaseVerificationStatus.REJECTED, result.verificationStatus)
            assertNull(result.update)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun verifiesTheBakedCurrentBuildIdentityWithoutOfferingAnUpdate() = runBlocking {
        val server = MockWebServer()
        server.enqueue(MockResponse().setBody(releaseJson("v1.8.0").toString()))
        server.start()
        try {
            val service = GitHubReleaseUpdateService(
                client = OkHttpClient.Builder().followRedirects(false).build(),
                currentVersionName = "1.8.0",
                apiUrl = server.url("/repos/Emp5r0R/Abyssal/releases/latest").toString(),
                expectedApiHost = server.hostName,
                allowInsecureApiForTests = true,
                assetLoader = ReleaseAssetLoader { url, _ ->
                    if (url.encodedPath.endsWith(".sig")) ByteArray(64) else byteArrayOf(1)
                },
                manifestInspector = ReleaseManifestInspector { _, _, _, expectation ->
                    assertEquals("A".repeat(86), expectation.buildSignatureBase64Url)
                    assertEquals("1".repeat(40), expectation.sourceCommit)
                    VerifiedAndroidRelease("a".repeat(64), 16L * 1024L * 1024L, "1".repeat(40))
                },
                currentBuildAttestation = BuildAttestation(
                    "android",
                    "1.8.0",
                    "A".repeat(86),
                    "1".repeat(40)
                )
            )

            val result = service.checkCurrentRelease()

            assertEquals(ReleaseVerificationStatus.VERIFIED, result.verificationStatus)
            assertNull(result.update)
        } finally {
            server.shutdown()
        }
    }

    private fun parserService(currentVersion: String): GitHubReleaseUpdateService {
        return GitHubReleaseUpdateService(
            client = OkHttpClient(),
            currentVersionName = currentVersion,
            apiUrl = "https://api.github.com/repos/Emp5r0R/Abyssal/releases/latest"
        )
    }

    private fun releaseJson(tag: String): JSONObject {
        val version = tag.removePrefix("v")
        val fileName = "abyssal-android-$version-universal-release.apk"
        return JSONObject()
            .put("tag_name", tag)
            .put("draft", false)
            .put("prerelease", false)
            .put("html_url", "https://github.com/Emp5r0R/Abyssal/releases/tag/$tag")
            .put(
                "assets",
                JSONArray()
                    .put(releaseAsset(tag, fileName, 16L * 1024L * 1024L).put(
                        "content_type",
                        "application/vnd.android.package-archive"
                    ))
                    .put(releaseAsset(tag, "release-manifest-v1.json", 4096L))
                    .put(releaseAsset(tag, "release-manifest-v1.sig", 64L))
            )
    }

    private fun releaseAsset(tag: String, name: String, size: Long): JSONObject =
        JSONObject()
            .put("name", name)
            .put("size", size)
            .put(
                "browser_download_url",
                "https://github.com/Emp5r0R/Abyssal/releases/download/$tag/$name"
            )
}

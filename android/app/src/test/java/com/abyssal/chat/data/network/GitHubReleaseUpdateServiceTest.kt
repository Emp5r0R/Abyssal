package com.abyssal.chat.data.network

import kotlinx.coroutines.runBlocking
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
                allowInsecureApiForTests = true
            )

            val update = service.findAvailableUpdate()
            val request = server.takeRequest()

            assertEquals("1.8.1", update?.versionName)
            assertEquals(
                "https://github.com/Emp5r0R/Abyssal/releases/download/v1.8.1/" +
                    "abyssal-android-1.8.1-universal-release.apk",
                update?.apkDownloadUrl
            )
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

        assertNull(service.parseRelease(releaseJson("v1.8.0")))
        assertNull(service.parseRelease(releaseJson("v1.7.9")))
        assertNull(service.parseRelease(releaseJson("v1.8.1").put("draft", true)))
        assertNull(service.parseRelease(releaseJson("v1.8.1").put("prerelease", true)))
        assertNull(service.parseRelease(releaseJson("v1.8.1-beta.1")))
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

        assertNull(service.parseRelease(wrongHost))
        assertNull(service.parseRelease(insecure))
        assertNull(service.parseRelease(wrongName))
        assertNull(service.parseRelease(oversized))
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

            assertTrue(runCatching { service.findAvailableUpdate() }.isFailure)
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
                JSONArray().put(
                    JSONObject()
                        .put("name", fileName)
                        .put("size", 16L * 1024L * 1024L)
                        .put("content_type", "application/vnd.android.package-archive")
                        .put(
                            "browser_download_url",
                            "https://github.com/Emp5r0R/Abyssal/releases/download/$tag/$fileName"
                        )
                )
            )
    }
}

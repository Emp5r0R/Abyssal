package com.abyssal.chat.data.network

import java.io.File
import okhttp3.CacheControl
import okhttp3.HttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request

/** Fetches only bounded GitHub release assets through an explicit host-pinned redirect chain. */
internal class OfficialReleaseAssetClient(
    private val client: OkHttpClient,
    private val userAgent: String
) {
    suspend fun loadBytes(initialUrl: HttpUrl, maximumBytes: Long): ByteArray =
        follow(initialUrl, maximumBytes) { body ->
            BoundedInputReader.read(body.byteStream(), maximumBytes)
                ?: error("Release asset exceeds its safety limit")
        }

    suspend fun downloadVerified(
        initialUrl: HttpUrl,
        expectedSize: Long,
        expectedSha256Hex: String,
        output: File
    ): Boolean = follow(initialUrl, expectedSize) { body ->
        val reportedLength = body.contentLength()
        if (reportedLength >= 0L && reportedLength != expectedSize) return@follow false
        VerifiedApkFileWriter.write(
            input = body.byteStream(),
            output = output,
            expectedSize = expectedSize,
            expectedSha256Hex = expectedSha256Hex
        )
    }

    private suspend fun <T> follow(
        initialUrl: HttpUrl,
        maximumBytes: Long,
        consume: (okhttp3.ResponseBody) -> T
    ): T {
        require(maximumBytes > 0L)
        var url = initialUrl
        repeat(MAX_REDIRECTS + 1) { redirectCount ->
            val request = Request.Builder()
                .url(url)
                .cacheControl(CacheControl.FORCE_NETWORK)
                .header("Accept", "application/octet-stream")
                .header("User-Agent", userAgent)
                .get()
                .build()
            val result = awaitHttpResponse(client.newCall(request)) { response ->
                when {
                    response.isRedirect -> {
                        if (redirectCount >= MAX_REDIRECTS) error("Too many release redirects")
                        val destination = response.header("Location")
                            ?.let(url::resolve)
                            ?.takeIf(::isTrustedReleaseUrl)
                            ?: error("Untrusted release redirect")
                        Fetch.Redirect(destination)
                    }
                    response.isSuccessful -> {
                        check(isTrustedReleaseUrl(response.request.url))
                        val body = requireNotNull(response.body)
                        val length = body.contentLength()
                        check(length < 0L || length <= maximumBytes)
                        Fetch.Body(consume(body))
                    }
                    else -> error("Release asset unavailable")
                }
            }
            when (result) {
                is Fetch.Redirect -> url = result.url
                is Fetch.Body<*> -> {
                    @Suppress("UNCHECKED_CAST")
                    return result.value as T
                }
            }
        }
        error("Release asset unavailable")
    }

    private sealed interface Fetch {
        data class Redirect(val url: HttpUrl) : Fetch
        data class Body<T>(val value: T) : Fetch
    }

    companion object {
        private const val MAX_REDIRECTS = 3
        private val trustedHosts = setOf(
            "github.com",
            "release-assets.githubusercontent.com",
            "objects.githubusercontent.com"
        )

        internal fun isTrustedReleaseUrl(url: HttpUrl): Boolean =
            url.isHttps && url.host in trustedHosts && url.port == 443 &&
                url.username.isEmpty() && url.password.isEmpty() && url.fragment == null
    }
}

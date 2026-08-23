package com.abyssal.chat.data.network

import android.content.Context
import android.net.Uri
import androidx.core.content.FileProvider
import com.abyssal.chat.domain.model.AvailableAppUpdate
import com.abyssal.chat.domain.repository.IAppUpdateInstaller
import java.io.File
import java.net.Proxy
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Dns
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient

class VerifiedAppUpdateInstaller(
    private val context: Context,
    client: OkHttpClient = updateClient()
) : IAppUpdateInstaller {
    private val assetClient = OfficialReleaseAssetClient(client, "Abyssal-Android-Updater/1")
    private val updateDirectory = File(context.cacheDir, UPDATE_DIRECTORY)

    init {
        clearDirectory()
    }

    override suspend fun prepare(update: AvailableAppUpdate): Uri? = withContext(Dispatchers.IO) {
        val downloadUrl = validateDownload(update) ?: return@withContext null
        try {
            clearDirectory()
            check(updateDirectory.mkdirs() || updateDirectory.isDirectory)
            val partial = File(updateDirectory, "$APK_FILE_NAME.part")
            val complete = File(updateDirectory, APK_FILE_NAME)
            var moved = false
            try {
                check(
                    assetClient.downloadVerified(
                        initialUrl = downloadUrl,
                        expectedSize = update.apkSizeBytes,
                        expectedSha256Hex = update.apkSha256Hex,
                        output = partial
                    )
                )
                Files.move(partial.toPath(), complete.toPath())
                moved = true
            } finally {
                if (!moved) partial.delete()
            }
            FileProvider.getUriForFile(context, "${context.packageName}.updates", complete)
        } catch (cancelled: CancellationException) {
            clearDirectory()
            throw cancelled
        } catch (_: Exception) {
            clearDirectory()
            null
        }
    }

    override fun discard() {
        clearDirectory()
    }

    private fun clearDirectory() {
        updateDirectory.listFiles()?.forEach(File::delete)
    }

    internal fun validateDownload(update: AvailableAppUpdate): HttpUrl? {
        if (!VERSION.matches(update.versionName) || update.apkSizeBytes !in MIN_APK_BYTES..MAX_APK_BYTES ||
            !SHA256.matches(update.apkSha256Hex)) return null
        val name = "abyssal-android-${update.versionName}-universal-release.apk"
        val expectedPath = "/$OFFICIAL_REPOSITORY/releases/download/v${update.versionName}/$name"
        return update.apkDownloadUrl.toHttpUrlOrNull()?.takeIf { url ->
            OfficialReleaseAssetClient.isTrustedReleaseUrl(url) && url.host == "github.com" &&
                url.encodedPath == expectedPath && url.query == null
        }
    }

    private companion object {
        const val OFFICIAL_REPOSITORY = "Emp5r0R/Abyssal"
        const val UPDATE_DIRECTORY = "verified-updates"
        const val APK_FILE_NAME = "abyssal-update.apk"
        const val MIN_APK_BYTES = 1024L * 1024L
        const val MAX_APK_BYTES = 256L * 1024L * 1024L
        val VERSION = Regex("^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$")
        val SHA256 = Regex("^[0-9a-f]{64}$")

        fun updateClient(): OkHttpClient = OkHttpClient.Builder()
            .dns(Dns.SYSTEM)
            .proxy(Proxy.NO_PROXY)
            .callTimeout(5, TimeUnit.MINUTES)
            .connectTimeout(8, TimeUnit.SECONDS)
            .readTimeout(2, TimeUnit.MINUTES)
            .writeTimeout(10, TimeUnit.SECONDS)
            .followRedirects(false)
            .followSslRedirects(false)
            .retryOnConnectionFailure(false)
            .cache(null)
            .build()
    }
}

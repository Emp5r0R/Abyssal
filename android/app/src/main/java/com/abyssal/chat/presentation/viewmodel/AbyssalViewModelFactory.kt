package com.abyssal.chat.presentation.viewmodel

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import com.abyssal.chat.BuildConfig
import com.abyssal.chat.data.network.CloudflareFallbackDns
import com.abyssal.chat.data.network.EncryptedAttachmentService
import com.abyssal.chat.data.network.GitHubReleaseUpdateService
import com.abyssal.chat.data.network.InMemoryNodeConfigService
import com.abyssal.chat.data.network.InMemoryPayloadCipher
import com.abyssal.chat.data.network.NetworkIdentityService
import com.abyssal.chat.data.network.RealChatTransport
import com.abyssal.chat.data.repository.AndroidDisguiseManager
import com.abyssal.chat.data.repository.InMemoryMessageRepository
import java.util.concurrent.TimeUnit
import okhttp3.OkHttpClient

class AbyssalViewModelFactory(
    private val appContext: Context
) : ViewModelProvider.Factory {
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        if (!modelClass.isAssignableFrom(ChatViewModel::class.java)) {
            error("Unsupported ViewModel: ${modelClass.name}")
        }

        val httpClient = OkHttpClient.Builder()
            .dns(CloudflareFallbackDns())
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(0, TimeUnit.SECONDS)
            .writeTimeout(120, TimeUnit.SECONDS)
            .build()
        val nodeConfigService = InMemoryNodeConfigService()
        val payloadCipher = InMemoryPayloadCipher()
        val identityService = NetworkIdentityService(httpClient, payloadCipher)
        val messageRepository = InMemoryMessageRepository()
        val chatTransport = RealChatTransport(nodeConfigService, httpClient)
        val attachmentService = EncryptedAttachmentService(appContext, nodeConfigService, httpClient)
        val disguiseManager = AndroidDisguiseManager(appContext)
        val appUpdateService = GitHubReleaseUpdateService(
            client = httpClient.newBuilder()
                .callTimeout(12, TimeUnit.SECONDS)
                .connectTimeout(8, TimeUnit.SECONDS)
                .readTimeout(10, TimeUnit.SECONDS)
                .writeTimeout(10, TimeUnit.SECONDS)
                .followRedirects(false)
                .followSslRedirects(false)
                .cache(null)
                .build(),
            currentVersionName = BuildConfig.VERSION_NAME,
            apiUrl = BuildConfig.UPDATE_API_URL
        )

        @Suppress("UNCHECKED_CAST")
        return ChatViewModel(
            identityService = identityService,
            nodeConfigService = nodeConfigService,
            messageRepository = messageRepository,
            messageSender = messageRepository,
            chatTransport = chatTransport,
            attachmentService = attachmentService,
            disguiseManager = disguiseManager,
            appUpdateService = appUpdateService,
            payloadCipher = payloadCipher
        ) as T
    }
}

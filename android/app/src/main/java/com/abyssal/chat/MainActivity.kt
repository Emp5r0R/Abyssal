package com.abyssal.chat

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import com.abyssal.chat.data.network.CloudflareFallbackDns
import com.abyssal.chat.data.network.EncryptedAttachmentService
import com.abyssal.chat.data.network.InMemoryNodeConfigService
import com.abyssal.chat.data.network.NetworkIdentityService
import com.abyssal.chat.data.network.RealChatTransport
import com.abyssal.chat.data.repository.InMemoryMessageRepository
import com.abyssal.chat.data.repository.AndroidDisguiseManager
import com.abyssal.chat.presentation.screens.ChatScreen
import com.abyssal.chat.presentation.screens.DashboardScreen
import com.abyssal.chat.presentation.screens.EntranceScreen
import com.abyssal.chat.presentation.screens.CalculatorScreen
import com.abyssal.chat.presentation.viewmodel.ChatViewModel
import com.abyssal.chat.presentation.viewmodel.Screen
import com.abyssal.chat.theme.AbyssalTheme
import com.abyssal.chat.theme.DeepBlack
import java.util.concurrent.TimeUnit
import okhttp3.OkHttpClient

class MainActivity : ComponentActivity() {
    private lateinit var viewModel: ChatViewModel

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Block screenshots, screen recording, and cached window overlays
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        // Singletons injected adhering to DIP
        val httpClient = OkHttpClient.Builder()
            .dns(CloudflareFallbackDns())
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(0, TimeUnit.SECONDS)
            .writeTimeout(10, TimeUnit.SECONDS)
            .build()
        val nodeConfigService = InMemoryNodeConfigService()
        val identityService = NetworkIdentityService(httpClient)
        val messageRepository = InMemoryMessageRepository()
        val chatTransport = RealChatTransport(nodeConfigService, httpClient)
        val attachmentService = EncryptedAttachmentService(applicationContext, nodeConfigService, httpClient)
        val disguiseManager = AndroidDisguiseManager(this)
        
        viewModel = ChatViewModel(
            identityService = identityService,
            nodeConfigService = nodeConfigService,
            messageRepository = messageRepository,
            messageSender = messageRepository,
            chatTransport = chatTransport,
            attachmentService = attachmentService,
            disguiseManager = disguiseManager
        )

        setContent {
            AbyssalTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = DeepBlack
                ) {
                    val currentScreen by viewModel.currentScreen.collectAsState()
                    val isLocked by viewModel.isLocked.collectAsState()

                    // If disguised, intercept routing to display Calculator Cover
                    if (isLocked) {
                        CalculatorScreen(viewModel)
                    } else {
                        AnimatedContent(
                            targetState = currentScreen,
                            transitionSpec = {
                                fadeIn(animationSpec = tween(400)) togetherWith fadeOut(animationSpec = tween(400))
                            },
                            label = "screen_routing"
                        ) { screen ->
                            when (screen) {
                                is Screen.Entrance -> EntranceScreen(viewModel)
                                is Screen.Dashboard -> DashboardScreen(viewModel)
                                is Screen.Chat -> ChatScreen(viewModel, screen.sessionId)
                            }
                        }
                    }
                }
            }
        }
    }

    override fun onPause() {
        viewModel.logoutForLifecycleExit()
        super.onPause()
    }

    override fun onStop() {
        viewModel.logoutForLifecycleExit()
        super.onStop()
    }
}

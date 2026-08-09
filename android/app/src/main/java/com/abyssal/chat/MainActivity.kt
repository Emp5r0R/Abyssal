package com.abyssal.chat

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.MotionEvent
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
import androidx.lifecycle.ViewModelProvider
import com.abyssal.chat.presentation.screens.ChatScreen
import com.abyssal.chat.presentation.screens.DashboardScreen
import com.abyssal.chat.presentation.screens.EntranceScreen
import com.abyssal.chat.presentation.screens.CalculatorScreen
import com.abyssal.chat.presentation.screens.UpdateAvailableDialog
import com.abyssal.chat.presentation.viewmodel.ChatViewModel
import com.abyssal.chat.presentation.viewmodel.Screen
import com.abyssal.chat.theme.AbyssalTheme
import com.abyssal.chat.theme.DeepBlack

class MainActivity : ComponentActivity() {
    private lateinit var viewModel: ChatViewModel

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Block screenshots, screen recording, and cached window overlays
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            window.setHideOverlayWindows(true)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            setRecentsScreenshotEnabled(false)
        }

        val abyssalApplication = application as AbyssalApplication
        viewModel = ViewModelProvider(
            abyssalApplication,
            abyssalApplication.viewModelFactory
        )[ChatViewModel::class.java]

        setContent {
            AbyssalTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = DeepBlack
                ) {
                    val currentScreen by viewModel.currentScreen.collectAsState()
                    val isLocked by viewModel.isLocked.collectAsState()
                    val availableUpdate by viewModel.availableUpdate.collectAsState()

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

                    if (!isLocked) {
                        availableUpdate?.let { update ->
                            UpdateAvailableDialog(
                                update = update,
                                currentVersionName = BuildConfig.VERSION_NAME,
                                onUpdate = {
                                    val intent = Intent(
                                        Intent.ACTION_VIEW,
                                        Uri.parse(update.apkDownloadUrl)
                                    ).addCategory(Intent.CATEGORY_BROWSABLE)
                                    runCatching {
                                        startActivity(intent)
                                        viewModel.acceptAvailableUpdate()
                                    }
                                },
                                onRemindLater = viewModel::remindAvailableUpdateLater,
                                onCancel = viewModel::cancelAvailableUpdate
                            )
                        }
                    }
                }
            }
        }
    }

    override fun onPause() {
        if (::viewModel.isInitialized && !isChangingConfigurations) {
            viewModel.lockForLifecycleExit()
        }
        super.onPause()
    }

    override fun onStop() {
        if (::viewModel.isInitialized && !isChangingConfigurations) {
            viewModel.lockForLifecycleExit()
        }
        super.onStop()
    }

    override fun onResume() {
        super.onResume()
        if (::viewModel.isInitialized) viewModel.onHostResumed()
    }

    override fun onTrimMemory(level: Int) {
        if (::viewModel.isInitialized) viewModel.onHostTrimMemory(level)
        super.onTrimMemory(level)
    }

    override fun dispatchTouchEvent(event: MotionEvent): Boolean {
        if (::viewModel.isInitialized && event.actionMasked == MotionEvent.ACTION_DOWN) {
            viewModel.recordUserActivity()
        }
        return super.dispatchTouchEvent(event)
    }
}

package com.abyssal.chat

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
        if (!isChangingConfigurations) viewModel.lockForLifecycleExit()
        super.onPause()
    }

    override fun onStop() {
        if (!isChangingConfigurations) viewModel.lockForLifecycleExit()
        super.onStop()
    }

    override fun onResume() {
        super.onResume()
        viewModel.onHostResumed()
    }

    override fun dispatchTouchEvent(event: MotionEvent): Boolean {
        if (event.actionMasked == MotionEvent.ACTION_DOWN) {
            viewModel.recordUserActivity()
        }
        return super.dispatchTouchEvent(event)
    }
}

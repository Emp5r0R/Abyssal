package com.abyssal.chat

import android.content.Intent
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
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import com.abyssal.chat.presentation.screens.ChatScreen
import com.abyssal.chat.presentation.screens.DashboardScreen
import com.abyssal.chat.presentation.screens.EntranceScreen
import com.abyssal.chat.presentation.screens.CalculatorScreen
import com.abyssal.chat.presentation.screens.UpdateAvailableDialog
import com.abyssal.chat.presentation.screens.SecurityVerificationDialog
import com.abyssal.chat.presentation.viewmodel.ChatViewModel
import com.abyssal.chat.presentation.viewmodel.Screen
import com.abyssal.chat.domain.model.ReleaseVerificationStatus
import com.abyssal.chat.theme.AbyssalTheme
import com.abyssal.chat.theme.DeepBlack
import kotlinx.coroutines.launch

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
        val appUpdateInstaller = abyssalApplication.appUpdateInstaller
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
                    val serverStatus by viewModel.serverStatus.collectAsState()
                    val releaseStatus by viewModel.releaseVerificationStatus.collectAsState()
                    var updatePreparing by remember { mutableStateOf(false) }
                    var updateFailure by remember { mutableStateOf<String?>(null) }

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
                        if (releaseStatus != ReleaseVerificationStatus.VERIFIED) {
                            val unavailable = releaseStatus == ReleaseVerificationStatus.UNAVAILABLE
                            SecurityVerificationDialog(
                                title = when (releaseStatus) {
                                    ReleaseVerificationStatus.CHECKING -> "Verifying signed build"
                                    ReleaseVerificationStatus.UNAVAILABLE -> "Verification unavailable"
                                    else -> "Build verification failed"
                                },
                                message = if (unavailable) {
                                    "The signed release record could not be verified."
                                } else {
                                    "The current build does not match the signed release record."
                                },
                                isChecking = releaseStatus == ReleaseVerificationStatus.CHECKING,
                                onRetry = viewModel::retryReleaseVerification,
                                onEndSession = viewModel::endSession
                            )
                        } else if (serverStatus.state == "SECURITY_REJECTED") {
                            SecurityVerificationDialog(
                                onRetry = viewModel::onHostResumed,
                                onEndSession = viewModel::endSession
                            )
                        } else availableUpdate?.let { update ->
                            UpdateAvailableDialog(
                                update = update,
                                currentVersionName = BuildConfig.VERSION_NAME,
                                isPreparing = updatePreparing,
                                failureMessage = updateFailure,
                                onUpdate = {
                                    if (!updatePreparing) {
                                        updatePreparing = true
                                        updateFailure = null
                                        lifecycleScope.launch {
                                            val packageUri = appUpdateInstaller.prepare(update)
                                            updatePreparing = false
                                            if (packageUri == null) {
                                                updateFailure = "Unable to continue."
                                                return@launch
                                            }
                                            val intent = Intent(Intent.ACTION_VIEW)
                                                .setDataAndType(
                                                    packageUri,
                                                    "application/vnd.android.package-archive"
                                                )
                                                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                                            runCatching { startActivity(intent) }
                                                .onSuccess { viewModel.acceptAvailableUpdate() }
                                                .onFailure {
                                                    appUpdateInstaller.discard()
                                                    updateFailure = "Unable to continue."
                                                }
                                        }
                                    }
                                },
                                onRemindLater = {
                                    appUpdateInstaller.discard()
                                    updateFailure = null
                                    viewModel.remindAvailableUpdateLater()
                                },
                                onCancel = {
                                    appUpdateInstaller.discard()
                                    updateFailure = null
                                    viewModel.cancelAvailableUpdate()
                                }
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

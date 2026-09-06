package com.abyssal.chat.presentation.screens

import android.Manifest
import android.content.pm.PackageManager
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.util.Size
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.view.CameraController
import androidx.camera.view.LifecycleCameraController
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import com.abyssal.chat.BuildConfig
import com.abyssal.chat.data.qr.InviteQrDecoder
import com.abyssal.chat.theme.PureWhite
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.delay

@Composable
internal fun InviteQrScanner(onScanned: (String) -> Unit, onDismiss: () -> Unit) {
    val context = LocalContext.current
    var granted by remember { mutableStateOf(ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) }
    var requested by remember { mutableStateOf(false) }
    val permission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
        granted = it
        requested = true
    }
    LaunchedEffect(Unit) {
        if (!granted) permission.launch(Manifest.permission.CAMERA)
    }
    val dismiss by rememberUpdatedState(onDismiss)
    LaunchedEffect(Unit) { delay(60_000); dismiss() }
    Dialog(onDismissRequest = onDismiss, properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn)) {
        GlassSurface {
            Column(Modifier.padding(16.dp)) {
                Text("Scan Abyssal invite", color = PureWhite)
                if (granted) {
                    InviteCameraPreview(onScanned, onDismiss)
                } else {
                    Text(if (requested) "Camera unavailable. You can paste or open a QR image." else "Waiting for camera permission.", color = PureWhite)
                }
                TextButton(onClick = onDismiss) { Text("Close camera") }
            }
        }
    }
}

@Composable
private fun InviteCameraPreview(onScanned: (String) -> Unit, onDismiss: () -> Unit) {
    val context = LocalContext.current
    val lifecycle = LocalLifecycleOwner.current
    val scanned by rememberUpdatedState(onScanned)
    val dismiss by rememberUpdatedState(onDismiss)
    val preview = remember(context) { PreviewView(context).apply { implementationMode = PreviewView.ImplementationMode.COMPATIBLE } }
    var status by remember { mutableStateOf("Camera active.") }
    DisposableEffect(context, lifecycle, preview) {
        val active = AtomicBoolean(true)
        val delivered = AtomicBoolean(false)
        val handler = Handler(Looper.getMainLooper())
        val executor = Executors.newSingleThreadExecutor()
        var lastFrame = 0L
        var controller: LifecycleCameraController? = null
        fun stop() {
            if (!active.getAndSet(false)) return
            controller?.clearImageAnalysisAnalyzer()
            controller?.unbind()
            preview.controller = null
            handler.removeCallbacksAndMessages(null)
            executor.shutdownNow()
        }
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_PAUSE || event == Lifecycle.Event.ON_STOP) { stop(); dismiss() }
        }
        lifecycle.lifecycle.addObserver(observer)
        try {
            controller = LifecycleCameraController(context)
            controller.apply {
                setEnabledUseCases(CameraController.IMAGE_ANALYSIS)
                cameraSelector = CameraSelector.DEFAULT_BACK_CAMERA
                imageAnalysisTargetSize = CameraController.OutputSize(Size(960, 720))
                imageAnalysisBackpressureStrategy = ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST
                setImageAnalysisAnalyzer(executor) { frame ->
                    var bytes: ByteArray? = null
                    try {
                        val now = SystemClock.elapsedRealtime()
                        if (!active.get() || delivered.get() || now - lastFrame < 250) return@setImageAnalysisAnalyzer
                        lastFrame = now
                        val plane = frame.planes.firstOrNull() ?: return@setImageAnalysisAnalyzer
                        bytes = InviteQrDecoder.copyPlane(plane.buffer, frame.width, frame.height, plane.rowStride, plane.pixelStride)
                        val value = InviteQrDecoder.decodeLuminance(requireNotNull(bytes), frame.width, frame.height)
                            ?: return@setImageAnalysisAnalyzer
                        val valid = InviteQrDecoder.isVerifiedInvite(value, BuildConfig.DEBUG)
                        handler.post {
                            if (active.get()) {
                                if (valid && delivered.compareAndSet(false, true)) { stop(); scanned(value) }
                                else status = "QR code not accepted."
                            }
                        }
                    } catch (_: Exception) {
                        handler.post { if (active.get()) status = "QR code not accepted." }
                    } finally {
                        bytes?.fill(0)
                        frame.close()
                    }
                }
                preview.controller = this
                bindToLifecycle(lifecycle)
            }
        } catch (_: Exception) {
            stop()
            status = "Camera unavailable. You can open a QR image."
        }
        onDispose { lifecycle.lifecycle.removeObserver(observer); stop() }
    }
    AndroidView(factory = { preview }, modifier = Modifier.fillMaxWidth().aspectRatio(4f / 3f).padding(vertical = 12.dp))
    Text(status, color = PureWhite)
}

package com.abyssal.chat.presentation.screens

import android.Manifest
import android.content.pm.PackageManager
import android.media.MediaPlayer
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.abyssal.chat.domain.model.Message
import com.abyssal.chat.domain.model.VoiceNotes
import com.abyssal.chat.theme.Accent
import com.abyssal.chat.theme.AccentSoft
import com.abyssal.chat.theme.Danger
import com.abyssal.chat.theme.OnAccent
import com.abyssal.chat.theme.SurfaceHigh
import com.abyssal.chat.theme.TextMuted
import com.abyssal.chat.theme.TextPrimary
import com.abyssal.chat.theme.TextSubtle
import kotlinx.coroutines.delay

/** A voice message inside a bubble: its length and a play button that opens the in-memory player. */
@Composable
internal fun VoiceMessageContent(message: Message, onPlay: () -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(vertical = 2.dp)) {
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier
                .size(40.dp)
                .clip(CircleShape)
                .background(Accent)
                .clickable(role = Role.Button, onClick = onPlay)
                .semantics { contentDescription = "Play voice message" }
        ) {
            AppIcon(AppIcons.Play, tint = OnAccent, size = 18.dp)
        }
        Column(Modifier.padding(start = 10.dp)) {
            Text("Voice message", color = TextPrimary, fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
            Text(
                VoiceNotes.format(message.voiceDurationMs ?: 0L) + if (message.oneTimeView) " · listen once" else "",
                color = TextMuted,
                fontSize = 12.sp
            )
        }
    }
}

/**
 * Microphone button for the composer. It asks for the microphone permission
 * the first time, marking the system dialog as external UI so the app does not
 * lock behind it, then starts recording.
 */
@Composable
internal fun VoiceRecordButton(
    enabled: Boolean,
    onStart: () -> Unit,
    onExternalSystemUiStart: () -> Long,
    onExternalSystemUiEnd: (Long) -> Boolean
) {
    val context = LocalContext.current
    var permissionToken by remember { mutableStateOf<Long?>(null) }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        val token = permissionToken
        permissionToken = null
        val current = token != null && onExternalSystemUiEnd(token)
        if (granted && current) onStart()
    }
    Box(
        contentAlignment = Alignment.Center,
        modifier = Modifier
            .size(44.dp)
            .clip(CircleShape)
            .background(if (enabled) AccentSoft else SurfaceHigh)
            .semantics { contentDescription = "Record voice message" }
            .clickable(enabled = enabled, role = Role.Button) {
                if (ContextCompat.checkSelfPermission(context, Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED) {
                    onStart()
                } else {
                    val token = onExternalSystemUiStart()
                    permissionToken = token
                    runCatching { launcher.launch(Manifest.permission.RECORD_AUDIO) }
                        .onFailure { onExternalSystemUiEnd(token); permissionToken = null }
                }
            }
    ) {
        AppIcon(AppIcons.Mic, tint = if (enabled) Accent else TextSubtle, size = 20.dp)
    }
}

/** Replaces the composer while recording: elapsed time, discard and send. */
@Composable
internal fun VoiceRecordingBar(startedAtMs: Long, onDiscard: () -> Unit, onSend: () -> Unit) {
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(startedAtMs) {
        while (true) {
            now = System.currentTimeMillis()
            delay(250)
        }
    }
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        modifier = Modifier
            .fillMaxWidth()
            .navigationBarsPadding()
            .imePadding()
            .padding(start = 16.dp, end = 10.dp, top = 8.dp, bottom = 8.dp)
    ) {
        Box(Modifier.size(10.dp).clip(CircleShape).background(Danger))
        Text(
            VoiceNotes.format(now - startedAtMs),
            color = TextPrimary,
            fontSize = 16.sp,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.semantics { contentDescription = "Recording, ${VoiceNotes.format(now - startedAtMs)}" }
        )
        Text("/ ${VoiceNotes.format(VoiceNotes.MAX_DURATION_MS)}", color = TextSubtle, fontSize = 13.sp, modifier = Modifier.weight(1f))
        IconAction(AppIcons.Trash, "Discard recording", onDiscard, tint = Danger)
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier
                .size(44.dp)
                .clip(CircleShape)
                .background(Accent)
                .clickable(role = Role.Button, onClick = onSend)
                .semantics { contentDescription = "Send voice message" }
        ) {
            AppIcon(AppIcons.Send, tint = OnAccent, size = 20.dp)
        }
    }
}

/** Plays decrypted audio straight from memory; the bytes never reach a file. */
@Composable
internal fun RamAudioPreview(bytes: ByteArray) {
    var playing by remember { mutableStateOf(false) }
    var ready by remember { mutableStateOf(false) }
    var failed by remember { mutableStateOf(false) }
    var progress by remember { mutableFloatStateOf(0f) }
    val player = remember(bytes) {
        runCatching {
            MediaPlayer().apply {
                setDataSource(ByteArrayMediaDataSource(bytes))
                setOnPreparedListener { ready = true; start(); playing = true }
                setOnCompletionListener { playing = false; progress = 1f }
                setOnErrorListener { _, _, _ -> failed = true; playing = false; true }
                prepareAsync()
            }
        }.getOrNull()
    }
    DisposableEffect(player) {
        onDispose { runCatching { player?.stop() }; player?.release() }
    }
    LaunchedEffect(player, playing) {
        while (playing && player != null) {
            val duration = runCatching { player.duration }.getOrDefault(0)
            if (duration > 0) progress = runCatching { player.currentPosition }.getOrDefault(0).toFloat() / duration
            delay(200)
        }
    }
    Column(Modifier.fillMaxWidth().padding(vertical = 12.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        if (player == null || failed) {
            Text("This audio could not be played.", color = Danger, fontSize = 14.sp)
            return@Column
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .size(52.dp)
                    .clip(CircleShape)
                    .background(if (ready) Accent else SurfaceHigh)
                    .clickable(enabled = ready, role = Role.Button) {
                        if (playing) { player.pause(); playing = false } else { player.start(); playing = true }
                    }
                    .semantics { contentDescription = if (playing) "Pause" else "Play" }
            ) {
                AppIcon(if (playing) AppIcons.Pause else AppIcons.Play, tint = OnAccent, size = 22.dp)
            }
            Spacer(Modifier.width(14.dp))
            LinearProgressIndicator(
                progress = { progress },
                color = Accent,
                trackColor = SurfaceHigh,
                modifier = Modifier.weight(1f)
            )
        }
    }
}

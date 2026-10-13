package com.abyssal.chat.presentation.screens

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.selection.toggleable
import androidx.compose.ui.draw.clip
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.RadioButton
import androidx.compose.material3.RadioButtonDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.abyssal.chat.domain.model.BackgroundAction
import com.abyssal.chat.domain.model.NotificationLevel
import com.abyssal.chat.domain.model.WorkspacePreferences
import com.abyssal.chat.theme.Outline
import com.abyssal.chat.theme.AccentBorder
import com.abyssal.chat.theme.AccentSoft
import com.abyssal.chat.theme.SurfaceRaised
import com.abyssal.chat.theme.TextSubtle
import com.abyssal.chat.theme.Accent
import com.abyssal.chat.theme.TextPrimary
import com.abyssal.chat.theme.TextMuted

/** Preference state and actions for Settings, matching the web client's Settings dialog. */
internal data class WorkspacePreferenceControls(
    val preferences: WorkspacePreferences = WorkspacePreferences(),
    val notificationsAllowed: Boolean = false,
    val onBlurChange: (Boolean) -> Unit = {},
    val onBackgroundActionChange: (BackgroundAction) -> Unit = {},
    val onNotificationLevelChange: (NotificationLevel) -> Unit = {},
    val onNotificationPermissionResult: () -> Unit = {},
    val onExternalSystemUiStart: () -> Long = { 0L },
    val onExternalSystemUiEnd: (Long) -> Boolean = { false }
)

private data class Choice<T>(val value: T, val label: String, val detail: String)

private val BACKGROUND_CHOICES = listOf(
    Choice(BackgroundAction.LOCK, "Lock behind the calculator", "Your session stays open. Enter your PIN on the calculator to return."),
    Choice(BackgroundAction.SIGN_OUT, "Sign out", "End the session. You sign in again with your invite and password."),
    Choice(BackgroundAction.STAY, "Stay signed in", "Nothing happens. The idle timer still signs you out.")
)

private val NOTIFICATION_CHOICES = listOf(
    Choice(NotificationLevel.OFF, "Off", "No notifications."),
    Choice(NotificationLevel.PRIVATE, "Private", "Only “New message”. No name or text."),
    Choice(NotificationLevel.SENDER, "Sender", "Who wrote, and in which room. No message text."),
    Choice(NotificationLevel.PREVIEW, "Sender and preview", "Who wrote and the start of the message. Hidden on the lock screen.")
)

/** Blur and leave-the-app choices; sits inside a Settings card. */
@Composable
internal fun PrivacyPreferences(controls: WorkspacePreferenceControls, disguised: Boolean) {
    val preferences = controls.preferences
    PreferenceSwitch(
        label = "Blur names and messages",
        detail = "Tap blurred text to show it for a few seconds.",
        checked = preferences.blurEnabled,
        onCheckedChange = controls.onBlurChange
    )
    Text(
        text = "When you leave Abyssal",
        color = TextPrimary,
        fontSize = 14.sp,
        fontWeight = FontWeight.SemiBold,
        modifier = Modifier.padding(top = 18.dp, bottom = 8.dp)
    )
    BACKGROUND_CHOICES.forEach { choice ->
        val unavailable = choice.value == BackgroundAction.LOCK && !disguised
        PreferenceChoice(
            label = choice.label,
            detail = if (unavailable) "Turn on the calculator cover to use this." else choice.detail,
            selected = preferences.backgroundAction == choice.value && !(unavailable && choice.value == BackgroundAction.LOCK),
            enabled = !unavailable,
            onSelect = { controls.onBackgroundActionChange(choice.value) }
        )
    }
}

@Composable
internal fun NotificationPreferences(controls: WorkspacePreferenceControls) {
    val context = LocalContext.current
    var pending by remember { mutableStateOf<NotificationLevel?>(null) }
    var systemUiToken by remember { mutableStateOf<Long?>(null) }
    var blocked by remember { mutableStateOf(false) }
    val permission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        systemUiToken?.let(controls.onExternalSystemUiEnd)
        systemUiToken = null
        controls.onNotificationPermissionResult()
        blocked = !granted
        if (granted) pending?.let(controls.onNotificationLevelChange)
        pending = null
    }
    val choose: (NotificationLevel) -> Unit = choose@{ level ->
        if (level == NotificationLevel.OFF || controls.notificationsAllowed) {
            blocked = false
            controls.onNotificationLevelChange(level)
            return@choose
        }
        val askable = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        if (askable) {
            pending = level
            systemUiToken = controls.onExternalSystemUiStart()
            permission.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            blocked = true
        }
    }

    NOTIFICATION_CHOICES.forEach { choice ->
        PreferenceChoice(
            label = choice.label,
            detail = choice.detail,
            selected = controls.preferences.notificationLevel == choice.value,
            enabled = true,
            onSelect = { choose(choice.value) }
        )
    }
    Text(
        text = notificationHint(controls, blocked),
        color = TextSubtle,
        fontSize = 12.sp,
        lineHeight = 17.sp,
        modifier = Modifier.padding(top = 4.dp)
    )
    if (blocked) {
        TextButton(onClick = {
            val intent = Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                .putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            // Leaving for system settings is an ordinary background transition.
            runCatching { context.startActivity(intent) }
        }) { Text("Open notification settings", color = Accent, fontWeight = FontWeight.SemiBold) }
    }
}

private fun notificationHint(controls: WorkspacePreferenceControls, blocked: Boolean): String = when {
    blocked -> "Notifications are turned off for Abyssal in system settings. Allow them there, then choose a level."
    controls.preferences.notificationLevel == NotificationLevel.OFF -> "Choosing a level asks Android for permission."
    controls.preferences.backgroundAction == BackgroundAction.SIGN_OUT ->
        "You are signed out when you leave Abyssal, so notifications only arrive while it is open on another conversation."
    else -> "Nothing is shown while Abyssal is locked behind the calculator. Android may still stop the app in the background."
}

@Composable
internal fun PreferenceSwitch(label: String, detail: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .toggleable(value = checked, role = Role.Switch, onValueChange = onCheckedChange)
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f).padding(end = 12.dp)) {
            Text(label, color = TextPrimary, fontSize = 15.sp, fontWeight = FontWeight.SemiBold)
            Text(detail, color = TextMuted, fontSize = 13.sp, lineHeight = 18.sp, modifier = Modifier.padding(top = 2.dp))
        }
        Switch(checked = checked, onCheckedChange = null, colors = appSwitchColors())
    }
}

@Composable
private fun PreferenceChoice(label: String, detail: String, selected: Boolean, enabled: Boolean, onSelect: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(bottom = 8.dp)
            .clip(RoundedCornerShape(12.dp))
            .background(if (selected) AccentSoft else SurfaceRaised)
            .border(1.dp, if (selected) AccentBorder else Outline, RoundedCornerShape(12.dp))
            .selectable(selected = selected, enabled = enabled, role = Role.RadioButton, onClick = onSelect)
            .padding(horizontal = 6.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        RadioButton(
            selected = selected,
            onClick = null,
            enabled = enabled,
            colors = RadioButtonDefaults.colors(selectedColor = Accent, unselectedColor = TextMuted)
        )
        Column(modifier = Modifier.weight(1f).padding(start = 4.dp, end = 8.dp)) {
            Text(label, color = if (enabled) TextPrimary else TextSubtle, fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
            Text(detail, color = if (enabled) TextMuted else TextSubtle, fontSize = 13.sp, lineHeight = 18.sp)
        }
    }
}

package com.abyssal.chat.presentation.screens

import android.os.Build
import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Switch
import com.abyssal.chat.BuildConfig
import com.abyssal.chat.data.repository.isValidCamouflageConfiguration
import com.abyssal.chat.domain.model.DisguiseSettings
import com.abyssal.chat.domain.model.SessionSecurityState
import com.abyssal.chat.domain.model.User
import com.abyssal.chat.domain.model.shortAccountId
import com.abyssal.chat.theme.Background
import com.abyssal.chat.theme.Danger
import com.abyssal.chat.theme.Outline
import com.abyssal.chat.theme.TextMuted
import com.abyssal.chat.theme.TextPrimary
import com.abyssal.chat.theme.TextSubtle

/** Full-screen Settings, grouped into the same sections as the web Settings dialog. */
@Composable
internal fun SettingsScreen(
    currentUser: User?,
    disguiseSettings: DisguiseSettings,
    sessionSecurity: SessionSecurityState,
    directoryCheckpoint: String?,
    preferenceControls: WorkspacePreferenceControls,
    onDismiss: () -> Unit,
    onSaveDisguise: (Boolean, String, String) -> Unit,
    onLock: () -> Unit,
    onEndSession: () -> Unit,
    onWipe: () -> Unit
) {
    var showWipe by remember { mutableStateOf(false) }
    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false, decorFitsSystemWindows = false)
    ) {
        Surface(color = Background, modifier = Modifier.fillMaxSize()) {
            Column(modifier = Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding().imePadding()) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    IconAction(AppIcons.ArrowLeft, "Close settings", onDismiss, tint = TextPrimary)
                    Text("Settings", color = TextPrimary, fontSize = 20.sp, fontWeight = FontWeight.SemiBold)
                }
                HorizontalDivider(color = Outline)
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .verticalScroll(rememberScrollState())
                        .padding(16.dp)
                        .widthIn(max = 640.dp),
                    verticalArrangement = Arrangement.spacedBy(14.dp)
                ) {
                    AccountCard(currentUser, sessionSecurity, disguiseSettings.isDisguised, onLock, onEndSession)
                    SectionCard(title = "Privacy", icon = AppIcons.Eye) {
                        Column(Modifier.padding(16.dp)) {
                            PrivacyPreferences(preferenceControls, disguised = disguiseSettings.isDisguised)
                        }
                    }
                    SectionCard(title = "Notifications", icon = AppIcons.Bell) {
                        Column(Modifier.padding(16.dp)) { NotificationPreferences(preferenceControls) }
                    }
                    CalculatorCoverCard(disguiseSettings, onSaveDisguise)
                    if (!directoryCheckpoint.isNullOrBlank()) {
                        SecurityCard(directoryCheckpoint)
                    }
                    SectionCard(title = "About", icon = AppIcons.Info) {
                        Column(Modifier.padding(16.dp)) {
                            Text("Abyssal ${BuildConfig.VERSION_NAME}", color = TextPrimary, fontSize = 15.sp, fontWeight = FontWeight.SemiBold)
                            Text(
                                "Ephemeral encrypted chat. Messages, keys and sessions live only in memory and are gone when the app or relay restarts.",
                                color = TextMuted,
                                fontSize = 13.sp,
                                lineHeight = 18.sp,
                                modifier = Modifier.padding(top = 4.dp)
                            )
                        }
                    }
                    SectionCard(title = "Danger zone", icon = AppIcons.Alert, titleColor = Danger, borderColor = Danger.copy(alpha = 0.35f)) {
                        Column(Modifier.padding(16.dp)) {
                            Text(
                                "Wiping the relay clears every account, invite, room, queued message and attachment on it, then asks connected apps to clear their memory.",
                                color = TextMuted,
                                fontSize = 13.sp,
                                lineHeight = 18.sp
                            )
                            MirageSecondaryButton(
                                text = "Wipe relay",
                                onClick = { showWipe = true },
                                danger = true,
                                icon = AppIcons.Trash,
                                modifier = Modifier.fillMaxWidth().padding(top = 12.dp)
                            )
                        }
                    }
                    Spacer(Modifier.height(8.dp))
                }
            }
        }
        if (showWipe) {
            ConfirmDialog(
                title = "Wipe relay memory?",
                message = "This clears relay accounts, invites, rooms, queued messages and attachments, then asks connected clients to clear local memory. Modified clients cannot be forced to delete.",
                confirmLabel = "Wipe relay",
                onConfirm = { showWipe = false; onWipe() },
                onDismiss = { showWipe = false }
            )
        }
    }
}

@Composable
private fun AccountCard(
    currentUser: User?,
    sessionSecurity: SessionSecurityState,
    disguised: Boolean,
    onLock: () -> Unit,
    onEndSession: () -> Unit
) {
    SectionCard {
        Column(Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Avatar(currentUser?.displayName ?: currentUser?.username.orEmpty(), size = 48.dp)
                Column(Modifier.weight(1f).padding(start = 12.dp)) {
                    PrivacyBlurred {
                        Text(
                            currentUser?.displayName ?: currentUser?.username?.let(::shortAccountId) ?: "Signed out",
                            color = TextPrimary,
                            fontSize = 16.sp,
                            fontWeight = FontWeight.SemiBold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                    currentUser?.username?.let { username ->
                        CopyableLine(value = username, label = "account ID", display = shortAccountId(username))
                    }
                }
            }
            Text(
                text = (if (sessionSecurity.retainedInBackground) "Kept in memory while hidden" else "Ends when you leave the app") +
                    " · signs out after ${formatDuration(sessionSecurity.remainingSec)} idle",
                color = TextMuted,
                fontSize = 13.sp,
                modifier = Modifier.padding(top = 12.dp)
            )
            Row(Modifier.fillMaxWidth().padding(top = 12.dp), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                if (disguised) {
                    MirageSecondaryButton("Lock now", onLock, icon = AppIcons.Lock, modifier = Modifier.weight(1f))
                }
                MirageSecondaryButton("Sign out", onEndSession, icon = AppIcons.LogOut, danger = true, modifier = Modifier.weight(1f))
            }
        }
    }
}

@Composable
private fun CalculatorCoverCard(disguiseSettings: DisguiseSettings, onSave: (Boolean, String, String) -> Unit) {
    var enabled by remember(disguiseSettings) { mutableStateOf(disguiseSettings.isDisguised) }
    var pin by remember(disguiseSettings) { mutableStateOf("") }
    var duressPin by remember(disguiseSettings) { mutableStateOf("") }
    val changed = enabled != disguiseSettings.isDisguised || pin.isNotEmpty() || duressPin.isNotEmpty()
    val valid = isValidCamouflageConfiguration(enabled = enabled, unlockPin = pin.trim(), duressPin = duressPin.trim())
    SectionCard(title = "Calculator cover", icon = AppIcons.Calculator) {
        Column(Modifier.padding(16.dp)) {
            PreferenceSwitch(
                label = "Hide behind a calculator",
                detail = "When Abyssal locks, a working calculator is shown. Type your PIN and tap = to return.",
                checked = enabled,
                onCheckedChange = { enabled = it }
            )
            if (enabled) {
                Spacer(Modifier.height(12.dp))
                CamouflagePinFields(pin, { pin = it }, duressPin, { duressPin = it })
            }
            if (changed) {
                MiragePrimaryButton(
                    text = if (enabled) "Save calculator cover" else "Turn off calculator cover",
                    onClick = { onSave(enabled, pin.trim(), duressPin.trim()) },
                    enabled = valid,
                    modifier = Modifier.fillMaxWidth().padding(top = 14.dp)
                )
            }
        }
    }
}

@Composable
private fun SecurityCard(directoryCheckpoint: String) {
    SectionCard(title = "Security", icon = AppIcons.ShieldCheck) {
        Column(Modifier.padding(16.dp)) {
            Text("Directory checkpoint", color = TextPrimary, fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
            Text(
                "Compare with someone on the same relay: matching checkpoints mean you both see the same signed member list.",
                color = TextMuted,
                fontSize = 13.sp,
                lineHeight = 18.sp,
                modifier = Modifier.padding(top = 2.dp, bottom = 8.dp)
            )
            CopyableLine(value = directoryCheckpoint, label = "directory checkpoint", display = directoryCheckpoint.chunked(4).joinToString(" "), multiline = true)
        }
    }
}

/** Monospace value with a copy button, like the web `CopyableValue`. */
@Composable
internal fun CopyableLine(value: String, label: String, display: String = value, multiline: Boolean = false) {
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    var copied by remember(value) { mutableStateOf(false) }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(
            display,
            color = TextSubtle,
            fontSize = 12.sp,
            lineHeight = 17.sp,
            fontFamily = FontFamily.Monospace,
            maxLines = if (multiline) 4 else 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(1f, fill = false)
        )
        Spacer(Modifier.width(4.dp))
        IconAction(
            icon = if (copied) AppIcons.Check else AppIcons.Copy,
            contentDescription = "Copy $label",
            onClick = {
                clipboard.setText(AnnotatedString(value))
                copied = true
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
                    Toast.makeText(context, "Copied", Toast.LENGTH_SHORT).show()
                }
            },
            size = 36.dp,
            iconSize = 16.dp
        )
    }
}

internal fun formatDuration(totalSeconds: Int): String {
    val safeSeconds = totalSeconds.coerceAtLeast(0)
    return "%d:%02d".format(safeSeconds / 60, safeSeconds % 60)
}

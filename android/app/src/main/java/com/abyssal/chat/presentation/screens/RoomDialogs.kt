package com.abyssal.chat.presentation.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.abyssal.chat.domain.model.MlsRoomVisibility
import com.abyssal.chat.theme.Accent
import com.abyssal.chat.theme.Danger
import com.abyssal.chat.theme.OnAccent
import com.abyssal.chat.theme.Outline
import com.abyssal.chat.theme.SurfaceRaised
import com.abyssal.chat.theme.TextMuted
import com.abyssal.chat.theme.TextPrimary
import com.abyssal.chat.theme.TextSubtle

private val ROOM_ID = Regex("^[A-Za-z0-9_-]{1,128}$")

@Composable
internal fun JoinRoomDialog(onDismiss: () -> Unit, onJoin: (String) -> Unit) {
    var roomId by remember { mutableStateOf("") }
    val valid = ROOM_ID.matches(roomId)
    MirageDialog(
        title = "Join a private room",
        onDismiss = onDismiss,
        icon = { Avatar("", size = 40.dp, icon = AppIcons.LogIn) }
    ) {
        Text(
            "Ask the room owner for its ID. They approve your request while they are online.",
            color = TextMuted,
            fontSize = 14.sp,
            lineHeight = 20.sp
        )
        Spacer(Modifier.height(14.dp))
        AppTextField(
            value = roomId,
            onValueChange = { roomId = it.trim().take(128) },
            label = "Room ID",
            placeholder = "forum_…",
            isError = roomId.isNotEmpty() && !valid,
            supportingText = if (roomId.isNotEmpty() && !valid) "Letters, digits, - and _ only." else null
        )
        DialogButtons("Cancel", "Request to join", onDismiss, { onJoin(roomId) }, valid)
    }
}

@Composable
internal fun CamouflagePinSetupDialog(onSave: (String, String) -> Unit) {
    var pinCode by remember { mutableStateOf("") }
    var duressPin by remember { mutableStateOf("") }
    val canSave = com.abyssal.chat.data.repository.isValidCamouflageConfiguration(
        enabled = true,
        unlockPin = pinCode.trim(),
        duressPin = duressPin.trim()
    )

    MirageDialog(
        title = "Set a calculator PIN",
        onDismiss = {},
        icon = { Avatar("", size = 40.dp, icon = AppIcons.Calculator) }
    ) {
        Text(
            "Abyssal hides behind a calculator when you leave. Type this PIN and tap = to come back. It is kept in memory only.",
            color = TextMuted,
            fontSize = 14.sp,
            lineHeight = 20.sp
        )
        Spacer(Modifier.height(14.dp))
        CamouflagePinFields(pinCode, { pinCode = it }, duressPin, { duressPin = it })
        MiragePrimaryButton(
            text = "Save and continue",
            onClick = { onSave(pinCode, duressPin) },
            enabled = canSave,
            modifier = Modifier.fillMaxWidth().padding(top = 20.dp)
        )
    }
}

@Composable
internal fun CamouflagePinFields(
    pin: String,
    onPinChange: (String) -> Unit,
    duressPin: String,
    onDuressPinChange: (String) -> Unit
) {
    AppTextField(
        value = pin,
        onValueChange = { onPinChange(it.filter(::isCamouflageInput).take(32)) },
        label = "Unlock PIN or expression",
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii),
        supportingText = "Digits and + - * / ( ) . are allowed."
    )
    Spacer(Modifier.height(8.dp))
    AppTextField(
        value = duressPin,
        onValueChange = { onDuressPinChange(it.filter(::isCamouflageInput).take(32)) },
        label = "Duress PIN (optional)",
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii)
    )
    Text(
        "Entering the duress PIN on the calculator silently wipes this device's memory and tries to wipe the relay.",
        color = Danger,
        fontSize = 12.sp,
        lineHeight = 17.sp,
        modifier = Modifier.padding(top = 6.dp)
    )
}

internal fun isCamouflageInput(value: Char): Boolean = value in "0123456789.+-*/()"

/** Values chosen in the create-room dialog. Timers are seconds; 0 means never. */
internal data class RoomDraft(
    val name: String = "",
    val visibility: MlsRoomVisibility = MlsRoomVisibility.PRIVATE,
    val readSec: String = "5",
    val absoluteSec: String = "0",
    val enforceTextAbsolute: Boolean = false,
    val images: MediaRuleDraft = MediaRuleDraft(),
    val videos: MediaRuleDraft = MediaRuleDraft(),
    val files: MediaRuleDraft = MediaRuleDraft()
)

internal data class MediaRuleDraft(
    val allowed: Boolean = true,
    val readSec: String = "5",
    val absoluteSec: String = "0",
    val enforceAbsolute: Boolean = false
)

private fun String.readSeconds(): Int = toIntOrNull()?.coerceIn(0, 86_400) ?: 5
private fun String.absoluteSeconds(): Int = toIntOrNull()?.coerceAtLeast(0) ?: 0

@Composable
internal fun CreateForumDialog(
    onDismiss: () -> Unit,
    onCreate: (String, Int, Int, Boolean, Boolean, Boolean, Boolean, Int, Int, Boolean, Int, Int, Boolean, Int, Int, Boolean, MlsRoomVisibility) -> Unit
) {
    var draft by remember { mutableStateOf(RoomDraft()) }
    var advanced by remember { mutableStateOf(false) }

    MirageDialog(
        title = "Create a room",
        onDismiss = onDismiss,
        icon = { Avatar("", size = 40.dp, icon = AppIcons.Hash) }
    ) {
        AppTextField(
            value = draft.name,
            onValueChange = { draft = draft.copy(name = it.take(36)) },
            label = "Room name",
            placeholder = "e.g. Operations"
        )
        Text("Who can join", color = TextMuted, fontSize = 13.sp, modifier = Modifier.padding(top = 16.dp, bottom = 8.dp))
        SegmentedControl(
            options = listOf("Private", "Public"),
            selectedIndex = if (draft.visibility == MlsRoomVisibility.PUBLIC) 1 else 0,
            onSelect = {
                draft = draft.copy(visibility = if (it == 1) MlsRoomVisibility.PUBLIC else MlsRoomVisibility.PRIVATE)
            },
            modifier = Modifier.fillMaxWidth()
        )
        Text(
            text = if (draft.visibility == MlsRoomVisibility.PUBLIC) {
                "Listed for everyone on this relay. Anyone can join while you are online."
            } else {
                "Not listed. Share the room ID and approve each request to join."
            },
            color = TextSubtle,
            fontSize = 12.sp,
            lineHeight = 17.sp,
            modifier = Modifier.padding(top = 6.dp)
        )
        AppTextField(
            value = draft.readSec,
            onValueChange = { draft = draft.copy(readSec = it.filter(Char::isDigit).take(5)) },
            label = "Messages disappear after reading (seconds)",
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            supportingText = "0 keeps messages until the room or session ends.",
            modifier = Modifier.padding(top = 14.dp)
        )

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 12.dp)
                .clip(ControlShape)
                .clickable(role = Role.Button) { advanced = !advanced }
                .padding(vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                "Advanced: attachments and message lifetime",
                color = Accent,
                fontSize = 14.sp,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.weight(1f)
            )
            AppIcon(AppIcons.ChevronDown, tint = Accent, size = 18.dp, modifier = Modifier.rotate(if (advanced) 180f else 0f))
        }
        AnimatedVisibility(visible = advanced) {
            Column {
                SecondsField(
                    label = "Delete text after sending (seconds)",
                    value = draft.absoluteSec,
                    onValueChange = { draft = draft.copy(absoluteSec = it) }
                )
                LabeledCheckbox("Enforce for every text message", draft.enforceTextAbsolute) {
                    draft = draft.copy(enforceTextAbsolute = it)
                }
                SectionLabel("Allowed attachments", modifier = Modifier.padding(top = 14.dp, bottom = 4.dp))
                MediaRuleEditor("Images and GIFs", draft.images) { draft = draft.copy(images = it) }
                MediaRuleEditor("Videos", draft.videos) { draft = draft.copy(videos = it) }
                MediaRuleEditor("Files up to 200 MB", draft.files) { draft = draft.copy(files = it) }
            }
        }

        DialogButtons(
            cancel = "Cancel",
            confirm = "Create room",
            confirmEnabled = draft.name.isNotBlank(),
            onCancel = onDismiss,
            onConfirm = {
                onCreate(
                    draft.name.trim(),
                    draft.readSec.readSeconds(),
                    draft.absoluteSec.absoluteSeconds(),
                    draft.enforceTextAbsolute,
                    draft.images.allowed,
                    draft.videos.allowed,
                    draft.files.allowed,
                    draft.images.readSec.readSeconds(),
                    draft.images.absoluteSec.absoluteSeconds(),
                    draft.images.enforceAbsolute,
                    draft.videos.readSec.readSeconds(),
                    draft.videos.absoluteSec.absoluteSeconds(),
                    draft.videos.enforceAbsolute,
                    draft.files.readSec.readSeconds(),
                    draft.files.absoluteSec.absoluteSeconds(),
                    draft.files.enforceAbsolute,
                    draft.visibility
                )
            }
        )
    }
}

@Composable
private fun SecondsField(label: String, value: String, onValueChange: (String) -> Unit, enabled: Boolean = true, modifier: Modifier = Modifier) {
    AppTextField(
        value = value,
        onValueChange = { onValueChange(it.filter(Char::isDigit).take(5)) },
        label = label,
        enabled = enabled,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        modifier = modifier
    )
}

@Composable
private fun MediaRuleEditor(label: String, rule: MediaRuleDraft, onChange: (MediaRuleDraft) -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 8.dp)
            .clip(ControlShape)
            .background(SurfaceRaised)
            .border(1.dp, Outline, ControlShape)
            .padding(horizontal = 12.dp, vertical = 8.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(label, color = TextPrimary, fontSize = 14.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
            Switch(checked = rule.allowed, onCheckedChange = { onChange(rule.copy(allowed = it)) }, colors = appSwitchColors())
        }
        AnimatedVisibility(visible = rule.allowed) {
            Column {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(top = 4.dp)) {
                    SecondsField("After reading (s)", rule.readSec, { onChange(rule.copy(readSec = it)) }, modifier = Modifier.weight(1f))
                    SecondsField("After sending (s)", rule.absoluteSec, { onChange(rule.copy(absoluteSec = it)) }, modifier = Modifier.weight(1f))
                }
                LabeledCheckbox("Enforce the after-sending limit", rule.enforceAbsolute) {
                    onChange(rule.copy(enforceAbsolute = it))
                }
            }
        }
    }
}

@Composable
private fun LabeledCheckbox(label: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .clip(ControlShape)
            .clickable(role = Role.Checkbox) { onCheckedChange(!checked) }
    ) {
        Checkbox(
            checked = checked,
            onCheckedChange = onCheckedChange,
            colors = CheckboxDefaults.colors(checkedColor = Accent, uncheckedColor = TextMuted, checkmarkColor = OnAccent)
        )
        Spacer(Modifier.width(2.dp))
        Text(label, color = TextPrimary, fontSize = 14.sp)
    }
}

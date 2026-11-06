package com.abyssal.chat.presentation.screens

import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.abyssal.chat.data.repository.isValidCamouflageConfiguration
import com.abyssal.chat.data.repository.isValidCamouflagePin
import com.abyssal.chat.theme.Danger
import com.abyssal.chat.theme.TextMuted

/** Longest calculator PIN the setup fields accept. */
internal const val COVER_PIN_MAX_LENGTH = 12

/**
 * The calculator PIN being typed during setup. PINs are digits only so every
 * character has a key on the calculator, and the PIN is typed twice so a typo
 * cannot lock the user out of a session that has no recovery.
 */
internal data class CoverPinDraft(val pin: String = "", val confirm: String = "", val duress: String = "") {
    val isReady: Boolean
        get() = problem() == null && isValidCamouflageConfiguration(enabled = true, unlockPin = pin, duressPin = duress)

    /** What still needs fixing, or null when the PIN can be saved. */
    fun problem(): String? = when {
        !isValidCamouflagePin(pin) -> "Use 6 to $COVER_PIN_MAX_LENGTH digits."
        confirm != pin -> if (confirm.isEmpty()) "Type the PIN again to confirm it." else "The PINs do not match."
        duress.isNotEmpty() && !isValidCamouflagePin(duress) -> "The duress PIN also needs 6 to $COVER_PIN_MAX_LENGTH digits."
        duress.isNotEmpty() && duress == pin -> "The duress PIN must differ from your PIN."
        else -> null
    }

    companion object {
        /** Keeps only digits, up to the maximum length. */
        fun clean(value: String): String = value.filter { it in '0'..'9' }.take(COVER_PIN_MAX_LENGTH)
    }
}

/** First-sign-in prompt to set up the calculator cover. It can be skipped and turned on later in Settings. */
@Composable
internal fun CamouflagePinSetupDialog(onSave: (String, String) -> Unit, onSkip: () -> Unit) {
    var draft by remember { mutableStateOf(CoverPinDraft()) }
    MirageDialog(
        title = "Hide Abyssal behind a calculator?",
        onDismiss = {},
        icon = { Avatar("", size = 40.dp, icon = AppIcons.Calculator) }
    ) {
        Text(
            "When you leave the app, a working calculator is shown instead. Type your PIN and tap = to come back. " +
                "The PIN is kept in memory only, so you set it again after the app restarts.",
            color = TextMuted,
            fontSize = 14.sp,
            lineHeight = 20.sp
        )
        Spacer(Modifier.height(14.dp))
        CamouflagePinFields(draft) { draft = it }
        MiragePrimaryButton(
            text = "Turn on calculator cover",
            onClick = { onSave(draft.pin, draft.duress) },
            enabled = draft.isReady,
            modifier = Modifier.fillMaxWidth().padding(top = 18.dp)
        )
        MirageTextButton(
            text = "Not now",
            onClick = onSkip,
            modifier = Modifier.fillMaxWidth().padding(top = 4.dp)
        )
    }
}

/** PIN, confirmation and optional duress PIN, with one line saying what is still wrong. */
@Composable
internal fun CamouflagePinFields(draft: CoverPinDraft, onChange: (CoverPinDraft) -> Unit) {
    val keyboard = KeyboardOptions(keyboardType = KeyboardType.NumberPassword)
    val problem = draft.problem()
    AppTextField(
        value = draft.pin,
        onValueChange = { onChange(draft.copy(pin = CoverPinDraft.clean(it))) },
        label = "PIN (6 to $COVER_PIN_MAX_LENGTH digits)",
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = keyboard
    )
    Spacer(Modifier.height(8.dp))
    AppTextField(
        value = draft.confirm,
        onValueChange = { onChange(draft.copy(confirm = CoverPinDraft.clean(it))) },
        label = "Confirm PIN",
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = keyboard,
        isError = draft.confirm.isNotEmpty() && draft.confirm != draft.pin
    )
    Spacer(Modifier.height(8.dp))
    AppTextField(
        value = draft.duress,
        onValueChange = { onChange(draft.copy(duress = CoverPinDraft.clean(it))) },
        label = "Duress PIN (optional)",
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = keyboard,
        supportingText = "Typing this one instead wipes this device's memory and tries to wipe the relay."
    )
    val started = draft.pin.isNotEmpty() || draft.confirm.isNotEmpty() || draft.duress.isNotEmpty()
    Text(
        text = if (problem == null) "Ready." else if (started) problem else "Use 6 to $COVER_PIN_MAX_LENGTH digits.",
        color = if (problem != null && started && draft.confirm.isNotEmpty()) Danger else TextMuted,
        fontSize = 12.sp,
        lineHeight = 17.sp,
        modifier = Modifier.padding(top = 6.dp)
    )
}

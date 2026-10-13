package com.abyssal.chat.presentation.screens

import com.abyssal.chat.theme.TextSubtle
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.material3.Text
import com.abyssal.chat.domain.model.AvailableAppUpdate
import com.abyssal.chat.theme.Success
import com.abyssal.chat.theme.TextPrimary
import com.abyssal.chat.theme.TextMuted

@Composable
fun UpdateAvailableDialog(
    update: AvailableAppUpdate,
    currentVersionName: String,
    isPreparing: Boolean,
    failureMessage: String?,
    onUpdate: () -> Unit,
    onRemindLater: () -> Unit,
    onCancel: () -> Unit
) {
    MirageDialog(
        title = "Update available",
        onDismiss = onRemindLater,
        accent = Success,
        icon = { Avatar("", size = 40.dp, tone = Tone.Success, icon = AppIcons.Download) },
        modifier = Modifier.widthIn(max = 440.dp)
    ) {
        Text(
            text = "A signed Abyssal release is ready on the official GitHub repository.",
            color = TextPrimary,
            fontSize = 14.sp,
            lineHeight = 20.sp
        )

        Spacer(modifier = Modifier.height(18.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            VersionLabel(label = "Installed", version = currentVersionName, color = TextMuted)
            VersionLabel(label = "New", version = update.versionName, color = Success)
        }

        Text(
            text = "Abyssal verifies the complete package against the signed release digest before Android opens it.",
            color = TextMuted,
            fontSize = 12.sp,
            lineHeight = 17.sp,
            modifier = Modifier.padding(top = 18.dp)
        )

        if (isPreparing) {
            AbyssalMarkLoader(
                size = AbyssalMarkLoaderSize.Small,
                description = "Verifying update package",
                modifier = Modifier.padding(top = 18.dp)
            )
        }

        MiragePrimaryButton(
            text = if (isPreparing) "Verifying…" else "Update now",
            onClick = onUpdate,
            enabled = !isPreparing,
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 18.dp)
        )

        if (failureMessage != null) {
            Text(
                text = failureMessage,
                color = com.abyssal.chat.theme.Danger,
                fontSize = 13.sp,
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp)
            )
        }

        Row(
            modifier = Modifier.fillMaxWidth().padding(top = 10.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            MirageSecondaryButton(
                text = "Skip",
                onClick = onCancel,
                modifier = Modifier.weight(1f)
            )
            MirageSecondaryButton(
                text = "Remind later",
                onClick = onRemindLater,
                modifier = Modifier.weight(1f)
            )
        }
    }
}

@Composable
private fun VersionLabel(label: String, version: String, color: Color) {
    Column(horizontalAlignment = Alignment.Start) {
        Text(
            text = label,
            color = TextSubtle,
            fontSize = 12.sp,
            fontWeight = FontWeight.Medium
        )
        Text(
            text = "v$version",
            color = color,
            fontSize = 17.sp,
            fontWeight = FontWeight.Bold
        )
    }
}

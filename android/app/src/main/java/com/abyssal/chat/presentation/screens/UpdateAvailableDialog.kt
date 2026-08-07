package com.abyssal.chat.presentation.screens

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
import com.abyssal.chat.theme.NeonGreen
import com.abyssal.chat.theme.PureWhite
import com.abyssal.chat.theme.SteelMuted

@Composable
fun UpdateAvailableDialog(
    update: AvailableAppUpdate,
    currentVersionName: String,
    onUpdate: () -> Unit,
    onRemindLater: () -> Unit,
    onCancel: () -> Unit
) {
    MirageDialog(
        title = "Update available",
        onDismiss = onRemindLater,
        accent = NeonGreen,
        modifier = Modifier.widthIn(max = 440.dp)
    ) {
        Text(
            text = "A signed Abyssal release is ready on the official GitHub repository.",
            color = PureWhite,
            fontSize = 14.sp,
            lineHeight = 20.sp,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(22.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            VersionLabel(label = "CURRENT", version = currentVersionName, color = SteelMuted)
            VersionLabel(label = "AVAILABLE", version = update.versionName, color = NeonGreen)
        }

        Text(
            text = "Android verifies the signing key before replacing this installation.",
            color = SteelMuted,
            fontSize = 12.sp,
            lineHeight = 17.sp,
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(top = 22.dp)
        )

        MiragePrimaryButton(
            text = "UPDATE",
            onClick = onUpdate,
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 22.dp)
        )

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            MirageSecondaryButton(
                text = "Cancel",
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
            color = SteelMuted,
            fontSize = 10.sp,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Bold
        )
        Text(
            text = "v$version",
            color = color,
            fontSize = 17.sp,
            fontWeight = FontWeight.Bold
        )
    }
}

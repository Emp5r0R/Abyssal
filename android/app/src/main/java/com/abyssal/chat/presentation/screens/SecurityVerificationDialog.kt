package com.abyssal.chat.presentation.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.abyssal.chat.theme.PureWhite
import com.abyssal.chat.theme.SelfDestructAmber
import com.abyssal.chat.theme.SteelMuted

@Composable
fun SecurityVerificationDialog(
    title: String = "Build rejected by node",
    message: String = "The current signed build is not accepted by this node.",
    isChecking: Boolean = false,
    onRetry: () -> Unit,
    onEndSession: () -> Unit
) {
    MirageDialog(
        title = title,
        onDismiss = {},
        accent = SelfDestructAmber,
        icon = {
            AbyssalMarkLoader(
                size = AbyssalMarkLoaderSize.Medium,
                description = title,
                animated = isChecking
            )
        },
        modifier = Modifier.widthIn(max = 440.dp)
    ) {
        Text(
            text = message,
            color = PureWhite,
            fontSize = 14.sp,
            lineHeight = 20.sp,
            textAlign = TextAlign.Center
        )
        Text(
            text = "Account traffic remains blocked.",
            color = SteelMuted,
            fontSize = 12.sp,
            lineHeight = 17.sp,
            textAlign = TextAlign.Center
        )
        Spacer(modifier = Modifier.height(12.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            MirageSecondaryButton(
                text = "End session",
                onClick = onEndSession,
                modifier = Modifier.weight(1f)
            )
            MiragePrimaryButton(
                text = if (isChecking) "CHECKING..." else "Check again",
                onClick = onRetry,
                enabled = !isChecking,
                modifier = Modifier.weight(1f)
            )
        }
    }
}

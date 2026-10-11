package com.abyssal.chat.presentation.screens

import android.os.Build
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay

/** Whether names and message text are hidden until tapped. Off unless Settings turns it on. */
val LocalPrivacyBlur = staticCompositionLocalOf { false }

internal const val PRIVACY_REVEAL_MS = 5_000L

/**
 * Hides sensitive content while the blur preference is on. A tap reveals it for a
 * few seconds, the touch equivalent of hovering on the web client. Inside a row that
 * already opens something on tap, pass `revealOnTap = false`: opening it reveals.
 */
@Composable
internal fun PrivacyBlurred(
    modifier: Modifier = Modifier,
    revealOnTap: Boolean = true,
    content: @Composable () -> Unit
) {
    if (!LocalPrivacyBlur.current) {
        Box(modifier) { content() }
        return
    }
    var revealed by remember { mutableStateOf(false) }
    LaunchedEffect(revealed) {
        if (revealed) {
            delay(PRIVACY_REVEAL_MS)
            revealed = false
        }
    }
    val hidden = if (revealed) {
        Modifier
    } else {
        Modifier
            .clearAndSetSemantics {
                contentDescription = if (revealOnTap) "Hidden. Double tap to reveal." else "Hidden."
            }
            .obscured()
    }
    val reveal = if (revealOnTap) {
        Modifier.clickable(role = Role.Button, onClickLabel = if (revealed) "Hide" else "Reveal") { revealed = !revealed }
    } else {
        Modifier
    }
    Box(modifier.then(reveal).then(hidden)) { content() }
}

/** A real blur where the platform supports it; a solid block on older Android versions. */
private fun Modifier.obscured(): Modifier =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        blur(8.dp)
    } else {
        drawWithContent {
            drawRoundRect(Color(0xFF2A313D), cornerRadius = CornerRadius(4.dp.toPx()))
        }
    }

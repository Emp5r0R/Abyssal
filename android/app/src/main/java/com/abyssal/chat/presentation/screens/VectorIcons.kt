package com.abyssal.chat.presentation.screens

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.graphics.drawscope.scale
import androidx.compose.ui.unit.dp
import com.abyssal.chat.theme.Accent
import com.abyssal.chat.theme.Success
import com.abyssal.chat.theme.TextPrimary
import com.abyssal.chat.theme.Danger
import com.abyssal.chat.theme.Background
import com.abyssal.chat.theme.TextMuted

@Composable
fun MirageLogo(
    modifier: Modifier = Modifier,
    animated: Boolean = true
) {
    if (animated) {
        val infiniteTransition = rememberInfiniteTransition(label = "mirageLogoTransition")
        val rotationOuter by infiniteTransition.animateFloat(
            initialValue = 0f,
            targetValue = 360f,
            animationSpec = infiniteRepeatable(
                animation = tween(durationMillis = 15000, easing = LinearEasing),
                repeatMode = RepeatMode.Restart
            ),
            label = "rotationOuter"
        )
        val rotationInner by infiniteTransition.animateFloat(
            initialValue = 360f,
            targetValue = 0f,
            animationSpec = infiniteRepeatable(
                animation = tween(durationMillis = 10000, easing = LinearEasing),
                repeatMode = RepeatMode.Restart
            ),
            label = "rotationInner"
        )
        val pulseScale by infiniteTransition.animateFloat(
            initialValue = 0.95f,
            targetValue = 1.05f,
            animationSpec = infiniteRepeatable(
                animation = tween(durationMillis = 2000, easing = LinearEasing),
                repeatMode = RepeatMode.Reverse
            ),
            label = "pulseScale"
        )
        val wormholeProgress by infiniteTransition.animateFloat(
            initialValue = 0f,
            targetValue = 1f,
            animationSpec = infiniteRepeatable(
                animation = tween(durationMillis = 4000, easing = LinearEasing),
                repeatMode = RepeatMode.Restart
            ),
            label = "wormholeProgress"
        )
        MirageLogoCanvas(
            modifier = modifier,
            rotationOuter = rotationOuter,
            rotationInner = rotationInner,
            pulseScale = pulseScale,
            wormholeProgress = wormholeProgress
        )
    } else {
        MirageLogoCanvas(
            modifier = modifier,
            rotationOuter = 0f,
            rotationInner = 0f,
            pulseScale = 1f,
            wormholeProgress = 0f
        )
    }
}

@Composable
private fun MirageLogoCanvas(
    modifier: Modifier,
    rotationOuter: Float,
    rotationInner: Float,
    pulseScale: Float,
    wormholeProgress: Float
) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height

        // Background wormhole rings (3 concentric cyan diamonds expanding and fading)
        val baseOuterPath = Path().apply {
            moveTo(w / 2, 0f)
            lineTo(w, h * 0.35f)
            lineTo(w / 2, h)
            lineTo(0f, h * 0.35f)
            close()
        }

        for (i in 0 until 3) {
            val t = (wormholeProgress + i / 3f) % 1f
            val scaleVal = 0.3f + t * 1.5f
            val alpha = if (t < 0.2f) {
                t / 0.2f
            } else {
                (1f - t) / 0.8f
            }
            val strokeColor = Accent.copy(alpha = alpha * 0.18f)

            scale(scale = scaleVal, pivot = center) {
                rotate(degrees = rotationOuter + i * 20f, pivot = center) {
                    drawPath(
                        path = baseOuterPath,
                        color = strokeColor,
                        style = Stroke(width = 1.dp.toPx())
                    )
                }
            }
        }

        // Outer cyan diamond
        rotate(degrees = rotationOuter, pivot = center) {
            drawPath(
                path = baseOuterPath,
                color = Accent,
                style = Stroke(width = 2.dp.toPx())
            )
        }

        // Inner delta chevron
        val baseInnerPath = Path().apply {
            moveTo(w / 2, h * 0.25f)
            lineTo(w * 0.72f, h * 0.45f)
            lineTo(w / 2, h * 0.75f)
            lineTo(w * 0.28f, h * 0.45f)
            close()
        }
        scale(scale = pulseScale, pivot = center) {
            rotate(degrees = rotationInner, pivot = center) {
                drawPath(
                    path = baseInnerPath,
                    color = Success,
                    style = Stroke(width = 1.5.dp.toPx())
                )
            }
        }

        // Central core glow dot
        drawCircle(
            color = Success,
            radius = 3.dp.toPx() * pulseScale,
            center = Offset(w / 2, h * 0.47f)
        )
    }
}

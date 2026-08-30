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
import com.abyssal.chat.theme.NeonCyan
import com.abyssal.chat.theme.NeonGreen
import com.abyssal.chat.theme.PureWhite
import com.abyssal.chat.theme.SelfDestructAmber
import com.abyssal.chat.theme.DeepBlack
import com.abyssal.chat.theme.SteelMuted

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
            val strokeColor = NeonCyan.copy(alpha = alpha * 0.18f)

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
                color = NeonCyan,
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
                    color = NeonGreen,
                    style = Stroke(width = 1.5.dp.toPx())
                )
            }
        }

        // Central core glow dot
        drawCircle(
            color = NeonGreen,
            radius = 3.dp.toPx() * pulseScale,
            center = Offset(w / 2, h * 0.47f)
        )
    }
}

@Composable
fun BiometricScannerIcon(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        val center = Offset(w / 2, h / 2)
        val radius = size.minDimension / 2
        
        drawArc(
            color = NeonGreen.copy(alpha = 0.8f),
            startAngle = 45f,
            sweepAngle = 90f,
            useCenter = false,
            style = Stroke(width = 2.dp.toPx()),
            topLeft = Offset(center.x - radius * 0.7f, center.y - radius * 0.7f),
            size = Size(radius * 1.4f, radius * 1.4f)
        )
        
        drawArc(
            color = NeonGreen.copy(alpha = 0.6f),
            startAngle = 180f,
            sweepAngle = 140f,
            useCenter = false,
            style = Stroke(width = 2.dp.toPx()),
            topLeft = Offset(center.x - radius * 0.5f, center.y - radius * 0.5f),
            size = Size(radius * 1.0f, radius * 1.0f)
        )

        drawArc(
            color = NeonGreen,
            startAngle = -45f,
            sweepAngle = 180f,
            useCenter = false,
            style = Stroke(width = 2.dp.toPx()),
            topLeft = Offset(center.x - radius * 0.3f, center.y - radius * 0.3f),
            size = Size(radius * 0.6f, radius * 0.6f)
        )
    }
}

@Composable
fun LockIcon(modifier: Modifier = Modifier, color: Color = NeonGreen) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        
        drawRoundRect(
            color = color,
            topLeft = Offset(0f, h * 0.42f),
            size = Size(w, h * 0.58f),
            cornerRadius = CornerRadius(2.dp.toPx()),
            style = Stroke(width = 1.5.dp.toPx())
        )
        
        drawArc(
            color = color,
            startAngle = 180f,
            sweepAngle = 180f,
            useCenter = false,
            style = Stroke(width = 1.5.dp.toPx()),
            topLeft = Offset(w * 0.18f, h * 0.08f),
            size = Size(w * 0.64f, h * 0.68f)
        )
    }
}

@Composable
fun TimerIcon(modifier: Modifier = Modifier, color: Color = SelfDestructAmber) {
    Canvas(modifier = modifier) {
        val r = size.minDimension / 2
        val center = Offset(size.width / 2, size.height / 2)
        
        drawCircle(color = color, radius = r * 0.9f, style = Stroke(width = 1.5.dp.toPx()))
        
        drawLine(color = color, start = center, end = Offset(center.x, center.y - r * 0.5f), strokeWidth = 1.5.dp.toPx())
        drawLine(color = color, start = center, end = Offset(center.x + r * 0.35f, center.y), strokeWidth = 1.5.dp.toPx())
        
        drawLine(color = color, start = Offset(center.x - r * 0.25f, center.y - r), end = Offset(center.x + r * 0.25f, center.y - r), strokeWidth = 2.dp.toPx())
    }
}

@Composable
fun HazardIcon(modifier: Modifier = Modifier, color: Color = PureWhite) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        
        val path = Path().apply {
            moveTo(w / 2, 0f)
            lineTo(w, h)
            lineTo(0f, h)
            close()
        }
        drawPath(path = path, color = color, style = Stroke(width = 2.dp.toPx()))
        
        drawLine(color = color, start = Offset(w / 2, h * 0.35f), end = Offset(w / 2, h * 0.68f), strokeWidth = 2.dp.toPx())
        drawCircle(color = color, radius = 1.5.dp.toPx(), center = Offset(w / 2, h * 0.82f))
    }
}

@Composable
fun ArrowBackIcon(modifier: Modifier = Modifier, color: Color = NeonCyan) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        
        drawLine(color = color, start = Offset(w * 0.8f, h * 0.5f), end = Offset(w * 0.2f, h * 0.5f), strokeWidth = 2.dp.toPx())
        drawLine(color = color, start = Offset(w * 0.5f, h * 0.2f), end = Offset(w * 0.2f, h * 0.5f), strokeWidth = 2.dp.toPx())
        drawLine(color = color, start = Offset(w * 0.5f, h * 0.8f), end = Offset(w * 0.2f, h * 0.5f), strokeWidth = 2.dp.toPx())
    }
}

@Composable
fun SendIcon(modifier: Modifier = Modifier, color: Color = DeepBlack) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        
        val path = Path().apply {
            moveTo(0f, 0f)
            lineTo(w, h / 2)
            lineTo(0f, h)
            lineTo(w * 0.35f, h / 2)
            close()
        }
        drawPath(path = path, color = color)
    }
}

@Composable
fun ReplyIcon(modifier: Modifier = Modifier, color: Color = SteelMuted) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        val path = Path().apply {
            moveTo(w * 0.42f, h * 0.18f)
            lineTo(w * 0.10f, h * 0.48f)
            lineTo(w * 0.42f, h * 0.78f)
            moveTo(w * 0.12f, h * 0.48f)
            cubicTo(w * 0.52f, h * 0.42f, w * 0.78f, h * 0.55f, w * 0.90f, h * 0.84f)
        }
        drawPath(
            path = path,
            color = color,
            style = Stroke(width = 1.8.dp.toPx())
        )
    }
}

@Composable
fun CloseIcon(modifier: Modifier = Modifier, color: Color = SteelMuted) {
    Canvas(modifier = modifier) {
        drawLine(
            color = color,
            start = Offset(size.width * 0.18f, size.height * 0.18f),
            end = Offset(size.width * 0.82f, size.height * 0.82f),
            strokeWidth = 1.8.dp.toPx()
        )
        drawLine(
            color = color,
            start = Offset(size.width * 0.82f, size.height * 0.18f),
            end = Offset(size.width * 0.18f, size.height * 0.82f),
            strokeWidth = 1.8.dp.toPx()
        )
    }
}

@Composable
fun EyeIcon(
    modifier: Modifier = Modifier,
    color: Color = SteelMuted,
    crossedOut: Boolean = false
) {
    Canvas(modifier = modifier) {
        val eye = Path().apply {
            moveTo(size.width * 0.08f, size.height * 0.5f)
            cubicTo(
                size.width * 0.28f,
                size.height * 0.16f,
                size.width * 0.72f,
                size.height * 0.16f,
                size.width * 0.92f,
                size.height * 0.5f
            )
            cubicTo(
                size.width * 0.72f,
                size.height * 0.84f,
                size.width * 0.28f,
                size.height * 0.84f,
                size.width * 0.08f,
                size.height * 0.5f
            )
            close()
        }
        drawPath(eye, color = color, style = Stroke(width = 1.7.dp.toPx()))
        drawCircle(
            color = color,
            radius = size.minDimension * 0.14f,
            center = Offset(size.width / 2f, size.height / 2f),
            style = Stroke(width = 1.7.dp.toPx())
        )
        if (crossedOut) {
            drawLine(
                color = color,
                start = Offset(size.width * 0.12f, size.height * 0.12f),
                end = Offset(size.width * 0.88f, size.height * 0.88f),
                strokeWidth = 1.9.dp.toPx()
            )
        }
    }
}

@Composable
fun PlusIcon(modifier: Modifier = Modifier, color: Color = DeepBlack) {
    Canvas(modifier = modifier) {
        drawLine(
            color = color,
            start = Offset(size.width / 2f, size.height * 0.18f),
            end = Offset(size.width / 2f, size.height * 0.82f),
            strokeWidth = 2.dp.toPx()
        )
        drawLine(
            color = color,
            start = Offset(size.width * 0.18f, size.height / 2f),
            end = Offset(size.width * 0.82f, size.height / 2f),
            strokeWidth = 2.dp.toPx()
        )
    }
}

@Composable
fun DeleteIcon(modifier: Modifier = Modifier, color: Color = SelfDestructAmber) {
    Canvas(modifier = modifier) {
        val stroke = 1.7.dp.toPx()
        drawRoundRect(
            color = color,
            topLeft = Offset(size.width * 0.24f, size.height * 0.30f),
            size = Size(size.width * 0.52f, size.height * 0.58f),
            cornerRadius = CornerRadius(2.dp.toPx()),
            style = Stroke(width = stroke)
        )
        drawLine(
            color = color,
            start = Offset(size.width * 0.16f, size.height * 0.24f),
            end = Offset(size.width * 0.84f, size.height * 0.24f),
            strokeWidth = stroke
        )
        drawLine(
            color = color,
            start = Offset(size.width * 0.38f, size.height * 0.12f),
            end = Offset(size.width * 0.62f, size.height * 0.12f),
            strokeWidth = stroke
        )
        drawLine(
            color = color,
            start = Offset(size.width * 0.42f, size.height * 0.40f),
            end = Offset(size.width * 0.42f, size.height * 0.76f),
            strokeWidth = stroke
        )
        drawLine(
            color = color,
            start = Offset(size.width * 0.58f, size.height * 0.40f),
            end = Offset(size.width * 0.58f, size.height * 0.76f),
            strokeWidth = stroke
        )
    }
}

@Composable
fun SettingsIcon(modifier: Modifier = Modifier, color: Color = SteelMuted) {
    Canvas(modifier = modifier) {
        val r = size.minDimension / 2
        val center = Offset(size.width / 2, size.height / 2)
        
        drawCircle(color = color, radius = r * 0.62f, style = Stroke(width = 2.dp.toPx()))
        drawCircle(color = color, radius = r * 0.22f, style = Stroke(width = 1.5.dp.toPx()))
        
        for (i in 0..7) {
            val angle = i * (Math.PI / 4)
            val start = Offset(
                (center.x + Math.cos(angle) * r * 0.58f).toFloat(),
                (center.y + Math.sin(angle) * r * 0.58f).toFloat()
            )
            val end = Offset(
                (center.x + Math.cos(angle) * r * 0.90f).toFloat(),
                (center.y + Math.sin(angle) * r * 0.90f).toFloat()
            )
            drawLine(color = color, start = start, end = end, strokeWidth = 3.dp.toPx())
        }
    }
}

@Composable
fun PaperclipIcon(modifier: Modifier = Modifier, color: Color = SteelMuted) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        
        val path = Path().apply {
            moveTo(w * 0.70f, h * 0.25f)
            lineTo(w * 0.70f, h * 0.65f)
            // Bottom loop
            quadraticBezierTo(w * 0.70f, h * 0.88f, w * 0.50f, h * 0.88f)
            quadraticBezierTo(w * 0.30f, h * 0.88f, w * 0.30f, h * 0.65f)
            lineTo(w * 0.30f, h * 0.35f)
            // Top loop
            quadraticBezierTo(w * 0.30f, h * 0.12f, w * 0.50f, h * 0.12f)
            quadraticBezierTo(w * 0.70f, h * 0.12f, w * 0.70f, h * 0.35f)
            // Inner line
            lineTo(w * 0.70f, h * 0.55f)
        }
        drawPath(path = path, color = color, style = Stroke(width = 1.5.dp.toPx()))
    }
}

@Composable
fun MediaFileIcon(modifier: Modifier = Modifier, color: Color = NeonGreen) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        
        val path = Path().apply {
            moveTo(0f, 0f)
            lineTo(w * 0.68f, 0f)
            lineTo(w, h * 0.32f)
            lineTo(w, h)
            lineTo(0f, h)
            close()
        }
        drawPath(path = path, color = color, style = Stroke(width = 1.5.dp.toPx()))
        
        drawLine(color = color, start = Offset(w * 0.68f, 0f), end = Offset(w * 0.68f, h * 0.32f), strokeWidth = 1.5.dp.toPx())
        drawLine(color = color, start = Offset(w * 0.68f, h * 0.32f), end = Offset(w, h * 0.32f), strokeWidth = 1.5.dp.toPx())
    }
}

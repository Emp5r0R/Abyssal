package com.abyssal.chat.theme

import android.app.Activity
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.remember
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.unit.dp
import androidx.core.view.WindowCompat

private fun colorSchemeFor(p: AppPalette): ColorScheme =
    if (p.isLight) {
        lightColorScheme(
            primary = p.accent, onPrimary = p.onAccent, primaryContainer = p.accentSoft, onPrimaryContainer = p.accent,
            secondary = p.success, onSecondary = p.background, tertiary = p.warning,
            background = p.background, onBackground = p.textPrimary, surface = p.surfaceBase, onSurface = p.textPrimary,
            surfaceVariant = p.surfaceRaised, onSurfaceVariant = p.textMuted, surfaceContainer = p.surfaceBase,
            surfaceContainerHigh = p.surfaceRaised, surfaceContainerHighest = p.surfaceHigh, surfaceContainerLow = p.surfaceBase,
            outline = p.outlineStrong, outlineVariant = p.outline, error = p.danger, onError = p.surfaceBase
        )
    } else {
        darkColorScheme(
            primary = p.accent, onPrimary = p.onAccent, primaryContainer = p.accentSoft, onPrimaryContainer = p.accent,
            secondary = p.success, onSecondary = p.background, tertiary = p.warning,
            background = p.background, onBackground = p.textPrimary, surface = p.surfaceBase, onSurface = p.textPrimary,
            surfaceVariant = p.surfaceRaised, onSurfaceVariant = p.textMuted, surfaceContainer = p.surfaceBase,
            surfaceContainerHigh = p.surfaceRaised, surfaceContainerHighest = p.surfaceHigh, surfaceContainerLow = p.surfaceBase,
            outline = p.outlineStrong, outlineVariant = p.outline, error = p.danger, onError = p.background
        )
    }

private val AppShapes = Shapes(
    extraSmall = RoundedCornerShape(6.dp),
    small = RoundedCornerShape(8.dp),
    medium = RoundedCornerShape(12.dp),
    large = RoundedCornerShape(16.dp),
    extraLarge = RoundedCornerShape(24.dp)
)

/** Colour scheme choice: follow the device, or force light or dark. Kept in memory only. */
enum class AppearanceChoice { SYSTEM, LIGHT, DARK }

@Composable
fun AbyssalTheme(appearance: AppearanceChoice = AppearanceChoice.SYSTEM, content: @Composable () -> Unit) {
    val light = when (appearance) {
        AppearanceChoice.SYSTEM -> !isSystemInDarkTheme()
        AppearanceChoice.LIGHT -> true
        AppearanceChoice.DARK -> false
    }
    val palette = if (light) LightPalette else DarkPalette
    val colorScheme = remember(palette) { colorSchemeFor(palette) }
    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = palette.background.toArgb()
            window.navigationBarColor = palette.background.toArgb()
            val controller = WindowCompat.getInsetsController(window, view)
            controller.isAppearanceLightStatusBars = palette.isLight
            controller.isAppearanceLightNavigationBars = palette.isLight
        }
    }

    CompositionLocalProvider(LocalAppPalette provides palette) {
        MaterialTheme(
            colorScheme = colorScheme,
            typography = Typography,
            shapes = AppShapes,
            content = content
        )
    }
}

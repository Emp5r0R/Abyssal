package com.abyssal.chat.theme

import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color

/**
 * The app's colour tokens. They mirror the web client's design tokens
 * (apps/web/src/styles.css) in both the dark and light themes.
 */
@Immutable
data class AppPalette(
    val isLight: Boolean,
    val background: Color,
    val surfaceBase: Color,
    val surfaceRaised: Color,
    val surfaceHigh: Color,
    val outline: Color,
    val outlineStrong: Color,
    val textPrimary: Color,
    val textSecondary: Color,
    val textMuted: Color,
    val textSubtle: Color,
    val accent: Color,
    val accentPressed: Color,
    val onAccent: Color,
    val accentSoft: Color,
    val accentBorder: Color,
    val success: Color,
    val successSoft: Color,
    val warning: Color,
    val warningSoft: Color,
    val danger: Color,
    val dangerSoft: Color,
    /** Bubble fill for the user's own messages. */
    val ownBubble: Color
)

val DarkPalette = AppPalette(
    isLight = false,
    background = Color(0xFF0B0E13),
    surfaceBase = Color(0xFF11151C),
    surfaceRaised = Color(0xFF171C25),
    surfaceHigh = Color(0xFF1E2430),
    outline = Color(0xFF232A36),
    outlineStrong = Color(0xFF313A4A),
    textPrimary = Color(0xFFE8EDF3),
    textSecondary = Color(0xFFC3CBD6),
    textMuted = Color(0xFF9BA6B5),
    textSubtle = Color(0xFF6E7989),
    accent = Color(0xFF2EC5D3),
    accentPressed = Color(0xFF57D6E1),
    onAccent = Color(0xFF031A1D),
    accentSoft = Color(0x212EC5D3),
    accentBorder = Color(0x662EC5D3),
    success = Color(0xFF3FCF8E),
    successSoft = Color(0x213FCF8E),
    warning = Color(0xFFF0B44C),
    warningSoft = Color(0x1FF0B44C),
    danger = Color(0xFFF16273),
    dangerSoft = Color(0x1FF16273),
    ownBubble = Color(0xFF123238)
)

val LightPalette = AppPalette(
    isLight = true,
    background = Color(0xFFF5F7FA),
    surfaceBase = Color(0xFFFFFFFF),
    surfaceRaised = Color(0xFFF0F3F7),
    surfaceHigh = Color(0xFFE6EBF1),
    outline = Color(0xFFDCE2EA),
    outlineStrong = Color(0xFFC5CDD8),
    textPrimary = Color(0xFF121821),
    textSecondary = Color(0xFF2E3846),
    textMuted = Color(0xFF4A5565),
    textSubtle = Color(0xFF687384),
    accent = Color(0xFF0A8792),
    accentPressed = Color(0xFF087079),
    onAccent = Color(0xFFFFFFFF),
    accentSoft = Color(0x1A0A8792),
    accentBorder = Color(0x590A8792),
    success = Color(0xFF12804F),
    successSoft = Color(0x1A12804F),
    warning = Color(0xFF9A5B00),
    warningSoft = Color(0x1A9A5B00),
    danger = Color(0xFFC22A3F),
    dangerSoft = Color(0x14C22A3F),
    ownBubble = Color(0xFFDDF1F3)
)

val LocalAppPalette = staticCompositionLocalOf { DarkPalette }

val Background: Color @Composable @ReadOnlyComposable get() = LocalAppPalette.current.background
val SurfaceBase: Color @Composable @ReadOnlyComposable get() = LocalAppPalette.current.surfaceBase
val SurfaceRaised: Color @Composable @ReadOnlyComposable get() = LocalAppPalette.current.surfaceRaised
val SurfaceHigh: Color @Composable @ReadOnlyComposable get() = LocalAppPalette.current.surfaceHigh
val Outline: Color @Composable @ReadOnlyComposable get() = LocalAppPalette.current.outline
val OutlineStrong: Color @Composable @ReadOnlyComposable get() = LocalAppPalette.current.outlineStrong

val TextPrimary: Color @Composable @ReadOnlyComposable get() = LocalAppPalette.current.textPrimary
val TextSecondary: Color @Composable @ReadOnlyComposable get() = LocalAppPalette.current.textSecondary
val TextMuted: Color @Composable @ReadOnlyComposable get() = LocalAppPalette.current.textMuted
val TextSubtle: Color @Composable @ReadOnlyComposable get() = LocalAppPalette.current.textSubtle

val Accent: Color @Composable @ReadOnlyComposable get() = LocalAppPalette.current.accent
val AccentPressed: Color @Composable @ReadOnlyComposable get() = LocalAppPalette.current.accentPressed
val OnAccent: Color @Composable @ReadOnlyComposable get() = LocalAppPalette.current.onAccent
val AccentSoft: Color @Composable @ReadOnlyComposable get() = LocalAppPalette.current.accentSoft
val AccentBorder: Color @Composable @ReadOnlyComposable get() = LocalAppPalette.current.accentBorder

val Success: Color @Composable @ReadOnlyComposable get() = LocalAppPalette.current.success
val SuccessSoft: Color @Composable @ReadOnlyComposable get() = LocalAppPalette.current.successSoft
val Warning: Color @Composable @ReadOnlyComposable get() = LocalAppPalette.current.warning
val WarningSoft: Color @Composable @ReadOnlyComposable get() = LocalAppPalette.current.warningSoft
val Danger: Color @Composable @ReadOnlyComposable get() = LocalAppPalette.current.danger
val DangerSoft: Color @Composable @ReadOnlyComposable get() = LocalAppPalette.current.dangerSoft

val OwnBubble: Color @Composable @ReadOnlyComposable get() = LocalAppPalette.current.ownBubble

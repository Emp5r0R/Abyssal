package com.abyssal.chat.presentation.screens

import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.MotionDurationScale
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.ProgressBarRangeInfo
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.progressBarRangeInfo
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

enum class AbyssalMarkLoaderSize(val dimension: Dp) {
    Inline(21.dp),
    Small(36.dp),
    Medium(64.dp),
    Large(84.dp)
}

internal fun isAbyssalMarkAnimationEnabled(
    requested: Boolean,
    animationScale: Float
): Boolean = requested && animationScale.isFinite() && animationScale > 0f

internal fun isAbyssalMarkLoadingSemanticsEnabled(animated: Boolean): Boolean = animated

/**
 * A fixed-size, accessible loading state using the canonical Abyssal mark.
 * The logo's motion is disabled for static states and when system animations
 * are disabled, while the indeterminate state remains available to TalkBack.
 */
@Composable
fun AbyssalMarkLoader(
    modifier: Modifier = Modifier,
    size: AbyssalMarkLoaderSize = AbyssalMarkLoaderSize.Medium,
    description: String = "Loading",
    animated: Boolean = true
) {
    val motionDurationScale = rememberCoroutineScope().coroutineContext[MotionDurationScale]
    val shouldAnimate = isAbyssalMarkAnimationEnabled(
        requested = animated,
        animationScale = motionDurationScale?.scaleFactor ?: 1f
    )
    val shouldExposeLoadingSemantics = isAbyssalMarkLoadingSemanticsEnabled(animated)

    MirageLogo(
        modifier = modifier
            .size(size.dimension)
            .semantics(mergeDescendants = true) {
                contentDescription = description
                if (shouldExposeLoadingSemantics) {
                    liveRegion = LiveRegionMode.Polite
                    progressBarRangeInfo = ProgressBarRangeInfo.Indeterminate
                }
            },
        animated = shouldAnimate
    )
}

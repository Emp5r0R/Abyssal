package com.abyssal.chat.presentation.screens

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AbyssalMarkLoaderPolicyTest {
    @Test
    fun animationRequiresAnEnabledRequestAndPositiveSystemScale() {
        assertTrue(isAbyssalMarkAnimationEnabled(requested = true, animationScale = 1f))
        assertTrue(isAbyssalMarkAnimationEnabled(requested = true, animationScale = 0.5f))
        assertFalse(isAbyssalMarkAnimationEnabled(requested = false, animationScale = 1f))
        assertFalse(isAbyssalMarkAnimationEnabled(requested = true, animationScale = 0f))
        assertFalse(isAbyssalMarkAnimationEnabled(requested = true, animationScale = -1f))
        assertFalse(isAbyssalMarkAnimationEnabled(requested = true, animationScale = Float.NaN))
    }

    @Test
    fun loadingSemanticsFollowIntentEvenWhenMotionIsDisabled() {
        assertTrue(isAbyssalMarkLoadingSemanticsEnabled(animated = true))
        assertFalse(isAbyssalMarkLoadingSemanticsEnabled(animated = false))
        assertFalse(isAbyssalMarkAnimationEnabled(requested = true, animationScale = 0f))
    }
}

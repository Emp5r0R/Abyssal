package com.abyssal.chat.presentation.screens

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DirectVerificationQrTest {
    private val token = "abyssal:verify:v1:${"A".repeat(43)}"

    @Test
    fun acceptsOnlyCanonicalBoundedVerificationTokens() {
        assertTrue(isCanonicalVerificationToken(token))
        assertFalse(isCanonicalVerificationToken(" $token"))
        assertFalse(isCanonicalVerificationToken("abyssal:verify:v2:${"A".repeat(43)}"))
        assertFalse(isCanonicalVerificationToken("abyssal:verify:v1:${"A".repeat(42)}"))
        assertNull(verificationQrMatrix(token, 95))
        assertNull(verificationQrMatrix("wrong", 224))
    }

    @Test
    fun renderedMatrixUsesStableSquareDimensionsAndContainsBothModuleValues() {
        val matrix = requireNotNull(verificationQrMatrix(token, 224))
        assertEquals(224, matrix.width)
        assertEquals(224, matrix.height)
        var black = 0
        var white = 0
        for (y in 0 until matrix.height) {
            for (x in 0 until matrix.width) {
                if (matrix[x, y]) black += 1 else white += 1
            }
        }
        assertTrue(black > 0)
        assertTrue(white > 0)
    }
}

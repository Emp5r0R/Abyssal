package com.abyssal.chat.presentation.screens

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CoverPinDraftTest {
    @Test
    fun pinsWithZerosAreAcceptedWhenConfirmed() {
        assertTrue(CoverPinDraft(pin = "000000", confirm = "000000").isReady)
        assertTrue(CoverPinDraft(pin = "012345", confirm = "012345", duress = "098765").isReady)
        assertNull(CoverPinDraft(pin = "012345", confirm = "012345").problem())
    }

    @Test
    fun explainsWhatIsStillWrong() {
        assertEquals("Use 6 to 12 digits.", CoverPinDraft(pin = "12345", confirm = "12345").problem())
        assertEquals("Type the PIN again to confirm it.", CoverPinDraft(pin = "123456").problem())
        assertEquals("The PINs do not match.", CoverPinDraft(pin = "123456", confirm = "123465").problem())
        assertEquals(
            "The duress PIN also needs 6 to 12 digits.",
            CoverPinDraft(pin = "123456", confirm = "123456", duress = "99").problem()
        )
        assertEquals(
            "The duress PIN must differ from your PIN.",
            CoverPinDraft(pin = "123456", confirm = "123456", duress = "123456").problem()
        )
        assertFalse(CoverPinDraft(pin = "123456", confirm = "123456", duress = "123456").isReady)
    }

    @Test
    fun cleanKeepsOnlyDigitsUpToTheLimit() {
        assertEquals("0123", CoverPinDraft.clean(" 0-1a2.3 "))
        assertEquals("1".repeat(COVER_PIN_MAX_LENGTH), CoverPinDraft.clean("1".repeat(20)))
    }
}

package com.abyssal.chat.domain.model

import org.junit.Assert.assertEquals
import org.junit.Test

class CalculatorEntryTest {
    private fun type(keys: String, start: CalculatorEntry = CalculatorEntry()): CalculatorEntry =
        keys.fold(start) { entry, key -> entry.press(key.toString()) }

    @Test
    fun zerosAreKeptExactlyAsTyped() {
        assertEquals("000000", type("000000").submission())
        assertEquals("012345", type("012345").submission())
        assertEquals("100200", type("100200").display)
    }

    @Test
    fun emptyEntryShowsPlaceholderZeroWithoutSubmittingIt() {
        val entry = CalculatorEntry()
        assertEquals("0", entry.display)
        assertEquals("", entry.submission())
        assertEquals("", type("5").press(CalculatorEntry.BACKSPACE).submission())
        assertEquals("0", type("5").press(CalculatorEntry.BACKSPACE).display)
    }

    @Test
    fun clearAndBackspaceEditTheTypedKeys() {
        assertEquals("12", type("123").press(CalculatorEntry.BACKSPACE).submission())
        assertEquals("", type("123").press(CalculatorEntry.CLEAR).submission())
        assertEquals("", CalculatorEntry().press(CalculatorEntry.BACKSPACE).submission())
    }

    @Test
    fun digitAfterResultStartsANewEntryButOperatorContinuesIt() {
        val shown = CalculatorEntry(result = "42")
        assertEquals("42", shown.display)
        assertEquals("012345", type("012345", shown).submission())
        assertEquals("42+1", type("+1", shown).submission())
        assertEquals("7", type("7", CalculatorEntry(result = CalculatorEntry.ERROR)).submission())
        assertEquals("+", type("+", CalculatorEntry(result = CalculatorEntry.ERROR)).submission())
    }

    @Test
    fun unknownKeysAreIgnoredAndLengthIsBounded() {
        assertEquals("1", type("1").press("x").press("").submission())
        val long = type("9".repeat(CalculatorEntry.MAX_LENGTH + 5))
        assertEquals(CalculatorEntry.MAX_LENGTH, long.submission().length)
    }
}

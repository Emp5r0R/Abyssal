package com.abyssal.chat.domain.model

/**
 * What has been typed on the calculator cover.
 *
 * Keys are kept exactly as typed, so a PIN such as `012345` or `000000` reaches
 * the verifier unchanged. "0" on an empty display is only a placeholder and is
 * never part of [typed]. After `=`, the result is shown; a digit starts a new
 * entry and an operator continues from the result, like a pocket calculator.
 */
data class CalculatorEntry(val typed: String = "", val result: String? = null) {
    val display: String
        get() = when {
            typed.isNotEmpty() -> typed
            result != null -> result
            else -> "0"
        }

    fun press(key: String): CalculatorEntry = when (key) {
        CLEAR -> CalculatorEntry()
        BACKSPACE -> if (typed.isEmpty()) CalculatorEntry() else CalculatorEntry(typed.dropLast(1))
        else -> append(key)
    }

    /** The text to evaluate and to check as a PIN when `=` is pressed. */
    fun submission(): String = typed

    private fun append(key: String): CalculatorEntry {
        if (key !in INPUT_KEYS) return this
        val continuesResult = typed.isEmpty() && result != null && result != ERROR && key in OPERATOR_KEYS
        val base = if (continuesResult) result.orEmpty() else typed
        if (base.length >= MAX_LENGTH) return CalculatorEntry(base)
        return CalculatorEntry(base + key)
    }

    companion object {
        const val CLEAR = "C"
        const val BACKSPACE = "⌫"
        const val EQUALS = "="
        const val ERROR = "Error"
        const val MAX_LENGTH = 40
        private val OPERATOR_KEYS = setOf("+", "-", "*", "/")
        private val INPUT_KEYS = setOf("0", "1", "2", "3", "4", "5", "6", "7", "8", "9", ".", "(", ")") + OPERATOR_KEYS
    }
}

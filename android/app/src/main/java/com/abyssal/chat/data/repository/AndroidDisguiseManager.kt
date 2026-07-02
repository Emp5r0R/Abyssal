package com.abyssal.chat.data.repository

import android.content.Context
import com.abyssal.chat.domain.repository.IDisguiseManager

class AndroidDisguiseManager(@Suppress("UNUSED_PARAMETER") context: Context) : IDisguiseManager {

    private var disguiseEnabled = false
    private var unlockPin = DEFAULT_PIN

    override fun setDisguiseEnabled(enabled: Boolean) {
        disguiseEnabled = enabled
    }

    override fun isDisguiseEnabled(): Boolean {
        return disguiseEnabled
    }

    override fun savePin(pin: String) {
        unlockPin = pin.ifBlank { DEFAULT_PIN }
    }

    override fun verifyPin(pin: String): Boolean {
        return pin == unlockPin
    }

    override fun getPin(): String {
        return unlockPin
    }

    private companion object {
        const val DEFAULT_PIN = "2026"
    }
}

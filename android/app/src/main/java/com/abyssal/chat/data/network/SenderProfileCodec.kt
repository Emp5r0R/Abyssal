package com.abyssal.chat.data.network

import java.security.SecureRandom
import org.json.JSONObject

internal object SenderProfileCodec {
    private val prefixes = listOf("Silent", "Silver", "Lunar", "Solar", "Quiet", "Hidden", "Distant", "Bright", "Amber", "Crimson", "Arctic", "Astral", "Velvet", "Crystal", "Cobalt", "Emerald")
    private val suffixes = listOf("Orbit", "Signal", "Comet", "Prism", "Echo", "Nova", "Pulse", "Aurora", "Horizon", "Vertex", "Beacon", "Quasar", "Cipher", "Zenith", "Vector", "Drift")
    private val namePattern = Regex("[A-Za-z][A-Za-z0-9_-]{0,35}")

    fun newDisplayName(): String {
        val entropy = ByteArray(8).also(SecureRandom()::nextBytes)
        return try { displayNameFromEntropy(entropy) } finally { entropy.fill(0) }
    }

    fun displayNameFromEntropy(entropy: ByteArray): String {
        require(entropy.size == 8)
        val hex = "0123456789ABCDEF"
        return buildString {
            append(prefixes[entropy[0].toInt() and 15])
            append(suffixes[entropy[1].toInt() and 15])
            for (index in 2..7) {
                val value = entropy[index].toInt() and 255
                append(hex[value ushr 4]); append(hex[value and 15])
            }
        }
    }

    fun encode(name: String): JSONObject {
        require(namePattern.matches(name))
        return JSONObject().put("version", 1).put("display_name", name)
    }

    fun decode(value: Any?): String? {
        if (value == null) return null
        val profile = value as? JSONObject ?: error("Profile unavailable")
        require(profile.length() == 2 && (profile.opt("version") as? Number)?.toDouble() == 1.0)
        val name = profile.opt("display_name") as? String ?: error("Profile unavailable")
        encode(name)
        return name
    }
}

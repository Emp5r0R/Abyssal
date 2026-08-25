package com.abyssal.chat.data.network

import java.security.SecureRandom
import org.json.JSONObject

/** Exact relay transport padding for every non-message WebSocket frame. */
internal object ControlTransportPadding {
    private val buckets = intArrayOf(
        4096,
        16_384,
        65_536,
        262_144,
        1_048_576,
        4_194_304,
        16_777_216,
        17_825_792
    )

    internal const val LEGACY_DOMAIN_MAX_BYTES = 1_048_576
    internal const val MLS_DOMAIN_MAX_BYTES = 16_777_216
    internal const val MAX_WIRE_BYTES = 17_825_792

    private const val FILLER_ALPHABET =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    private val fillerPattern = Regex("^[A-Za-z0-9_-]*$")
    private val secureRandom = SecureRandom()

    internal fun padOutgoing(frame: JSONObject, domainLimit: Int): String? {
        if (!validDomainLimit(domainLimit) || !validControlFrame(frame)) return null
        val inner = runCatching { frame.toString() }.getOrNull() ?: return null
        if (utf8ByteLength(inner, domainLimit) == null) return null
        val bucket = canonicalBucket(inner, domainLimit) ?: return null
        val prefix = inner.dropLast(1)
        val emptySuffix = suffix(bucket, "")
        val emptyBytes = utf8ByteLength(prefix, domainLimit) ?: return null
        val fillerLength = bucket - emptyBytes - emptySuffix.length
        val filler = randomFiller(fillerLength, wireLimit(domainLimit)) ?: return null
        val padded = prefix + suffix(bucket, filler)
        return padded.takeIf { utf8ByteLength(it, bucket) == bucket }
    }

    /** Validates transport padding, then removes its fields from [frame]. */
    internal fun validateAndStripIncoming(
        rawText: String,
        frame: JSONObject,
        domainLimit: Int
    ): Boolean {
        if (!validDomainLimit(domainLimit) ||
            frame.opt("type") !is String ||
            frame.optString("type") == "message"
        ) return false
        val bucket = integerValue(frame.opt("padding_bucket")) ?: return false
        val padding = frame.opt("padding") as? String ?: return false
        val maxWire = wireLimit(domainLimit)
        if (bucket !in buckets || bucket > maxWire || padding.length > maxWire ||
            !fillerPattern.matches(padding)
        ) return false
        val suffix = suffix(bucket, padding)
        if (!rawText.endsWith(suffix)) return false
        val inner = rawText.dropLast(suffix.length) + "}"
        if (utf8ByteLength(inner, domainLimit) == null) return false
        val canonicalBucket = canonicalBucket(inner, domainLimit) ?: return false
        val prefix = inner.dropLast(1)
        val emptyBytes = utf8ByteLength(prefix, domainLimit) ?: return false
        val expectedPadding = canonicalBucket - emptyBytes - suffix(canonicalBucket, "").length
        if (bucket != canonicalBucket || padding.length != expectedPadding ||
            utf8ByteLength(rawText, canonicalBucket) != canonicalBucket
        ) return false
        frame.remove("padding_bucket")
        frame.remove("padding")
        return true
    }

    private fun validControlFrame(frame: JSONObject): Boolean =
        frame.opt("type") is String &&
            frame.optString("type") != "message" &&
            !frame.has("padding_bucket") &&
            !frame.has("padding")

    private fun canonicalBucket(inner: String, domainLimit: Int): Int? {
        if (!inner.startsWith('{') || !inner.endsWith('}')) return null
        val prefixBytes = utf8ByteLength(inner.dropLast(1), domainLimit) ?: return null
        val maxWire = wireLimit(domainLimit)
        return buckets.firstOrNull { bucket ->
            bucket <= maxWire && prefixBytes + suffix(bucket, "").length <= bucket
        }
    }

    private fun validDomainLimit(limit: Int): Boolean =
        limit == LEGACY_DOMAIN_MAX_BYTES || limit == MLS_DOMAIN_MAX_BYTES

    private fun wireLimit(domainLimit: Int): Int =
        if (domainLimit == LEGACY_DOMAIN_MAX_BYTES) LEGACY_DOMAIN_MAX_BYTES else MAX_WIRE_BYTES

    private fun suffix(bucket: Int, padding: String): String =
        ",\"padding_bucket\":$bucket,\"padding\":\"$padding\"}"

    private fun randomFiller(length: Int, max: Int): String? {
        if (length < 0 || length > max) return null
        val randomBytes = ByteArray(length)
        return try {
            secureRandom.nextBytes(randomBytes)
            val filler = CharArray(length)
            for (index in randomBytes.indices) {
                filler[index] = FILLER_ALPHABET[randomBytes[index].toInt() and 63]
            }
            try {
                String(filler)
            } finally {
                filler.fill('\u0000')
            }
        } finally {
            randomBytes.fill(0)
        }
    }

    private fun integerValue(value: Any?): Int? = when (value) {
        is Int -> value
        is Long -> value.takeIf { it in Int.MIN_VALUE..Int.MAX_VALUE }?.toInt()
        else -> null
    }

    private fun utf8ByteLength(value: String, limit: Int): Int? {
        var bytes = 0L
        var index = 0
        while (index < value.length) {
            val character = value[index]
            val width = when {
                character.code <= 0x7f -> 1
                character.code <= 0x7ff -> 2
                Character.isHighSurrogate(character) && index + 1 < value.length &&
                    Character.isLowSurrogate(value[index + 1]) -> {
                    index += 1
                    4
                }
                Character.isSurrogate(character) -> 1
                else -> 3
            }
            bytes += width
            if (bytes > limit) return null
            index += 1
        }
        return bytes.toInt()
    }
}

internal fun JSONObject.padOutgoingControl(domainLimit: Int): String? =
    ControlTransportPadding.padOutgoing(this, domainLimit)

internal fun JSONObject.validateAndStripIncomingControlPadding(
    rawText: String,
    domainLimit: Int
): Boolean = ControlTransportPadding.validateAndStripIncoming(rawText, this, domainLimit)

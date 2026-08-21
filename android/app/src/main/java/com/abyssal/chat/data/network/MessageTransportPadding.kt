package com.abyssal.chat.data.network

import java.security.SecureRandom
import org.json.JSONArray
import org.json.JSONObject

/** Exact relay transport padding for protocol-v9 encrypted message frames. */
internal object MessageTransportPadding {
    private val buckets = intArrayOf(4096, 16_384, 65_536, 262_144, 1_048_576)
    internal const val MAX_BUCKET = 1_048_576

    private const val PROTOCOL_VERSION = 9
    private const val MAX_RECIPIENT_ENVELOPES = 256
    private const val FILLER_ALPHABET =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    private val fillerPattern = Regex("^[A-Za-z0-9_-]*$")
    private val secureRandom = SecureRandom()

    private val outgoingKeys = setOf(
        "type", "chat_id", "version", "message_id", "nonce_b64", "ciphertext_b64",
        "state_revision", "identity_envelope_b64", "identity_public_b64", "prekey_id",
        "state_signature_b64", "envelopes", "directory_node_id", "directory_revision",
        "directory_digest"
    )
    private val incomingKeys = setOf(
        "type", "chat_id", "version", "message_id", "nonce_b64", "ciphertext_b64",
        "signature_b64", "wrapped_key_b64", "prekey_id", "is_prekey", "sender_username",
        "sender_public_key_b64", "identity_public_b64", "directory_node_id",
        "directory_revision", "directory_digest", "padding_bucket", "padding"
    )
    private val envelopeKeys = setOf(
        "recipient_username", "wrapped_key_b64", "prekey_id", "is_prekey", "signature_b64"
    )

    /** Returns a newly serialized padded frame and never mutates [frame]. */
    internal fun padOutgoingMessage(frame: JSONObject): String? {
        if (!validOutgoingFrame(frame)) return null
        for (bucket in buckets) {
            val empty = serializeOutgoing(frame, bucket, "") ?: return null
            val emptyBytes = utf8ByteLength(empty, bucket) ?: continue
            val fillerLength = bucket - emptyBytes
            val filler = randomFiller(fillerLength) ?: return null
            val serialized = serializeOutgoing(frame, bucket, filler)
            if (serialized != null && utf8ByteLength(serialized, bucket) == bucket) {
                return serialized
            }
            return null
        }
        return null
    }

    /** Validates relay padding, then removes transport-only fields on success. */
    internal fun validateAndStripIncomingMessagePadding(
        rawText: String,
        frame: JSONObject
    ): Boolean {
        if (!validIncomingFrame(frame)) return false
        val bucket = integerValue(frame.opt("padding_bucket")) ?: return false
        val padding = frame.opt("padding") as? String ?: return false
        if (bucket !in buckets || padding.length > MAX_BUCKET || !fillerPattern.matches(padding)) {
            return false
        }

        var canonicalBucket: Int? = null
        var emptyBytes = 0
        for (candidate in buckets) {
            val empty = serializeIncoming(frame, candidate, "") ?: return false
            val bytes = utf8ByteLength(empty, candidate) ?: continue
            canonicalBucket = candidate
            emptyBytes = bytes
            break
        }
        if (canonicalBucket == null || bucket != canonicalBucket) return false
        if (padding.length != canonicalBucket - emptyBytes) return false

        val serialized = serializeIncoming(frame, bucket, padding) ?: return false
        if (utf8ByteLength(serialized, bucket) != bucket) return false
        if (utf8ByteLength(rawText, MAX_BUCKET) != bucket) return false

        frame.remove("padding_bucket")
        frame.remove("padding")
        return true
    }

    internal fun isCanonicalWireText(value: String): Boolean =
        utf8ByteLength(value, MAX_BUCKET)?.let { it in buckets } == true

    private fun validOutgoingFrame(frame: JSONObject): Boolean {
        if (!hasExactKeys(frame, outgoingKeys) || frame.opt("type") as? String != "message") {
            return false
        }
        if (integerValue(frame.opt("version")) != PROTOCOL_VERSION) return false
        if (!allStrings(
                frame,
                "chat_id", "message_id", "nonce_b64", "ciphertext_b64",
                "identity_envelope_b64", "identity_public_b64", "prekey_id",
                "state_signature_b64", "directory_node_id", "directory_digest"
            )
        ) return false
        if (positiveLong(frame.opt("state_revision")) == null ||
            positiveLong(frame.opt("directory_revision")) == null
        ) return false
        val envelopes = frame.opt("envelopes") as? JSONArray ?: return false
        if (envelopes.length() == 0 || envelopes.length() > MAX_RECIPIENT_ENVELOPES) return false
        for (index in 0 until envelopes.length()) {
            val envelope = envelopes.opt(index) as? JSONObject ?: return false
            if (!hasExactKeys(envelope, envelopeKeys) ||
                !allStrings(
                    envelope,
                    "recipient_username", "wrapped_key_b64", "prekey_id", "signature_b64"
                ) || envelope.opt("is_prekey") !is Boolean
            ) return false
        }
        return true
    }

    private fun validIncomingFrame(frame: JSONObject): Boolean {
        if (!hasExactKeys(frame, incomingKeys) || frame.opt("type") as? String != "message") {
            return false
        }
        if (integerValue(frame.opt("version")) != PROTOCOL_VERSION) return false
        if (!allStrings(
                frame,
                "chat_id", "message_id", "nonce_b64", "ciphertext_b64", "signature_b64",
                "wrapped_key_b64", "prekey_id", "sender_username", "sender_public_key_b64",
                "identity_public_b64", "directory_node_id", "directory_digest", "padding"
            )
        ) return false
        if (frame.opt("is_prekey") !is Boolean) return false
        return positiveLong(frame.opt("directory_revision")) != null &&
            integerValue(frame.opt("padding_bucket")) != null
    }

    private fun serializeOutgoing(frame: JSONObject, bucket: Int, padding: String): String? =
        runCatching {
            val envelopes = frame.getJSONArray("envelopes")
            val serializedEnvelopes = StringBuilder("[")
            for (index in 0 until envelopes.length()) {
                val envelope = envelopes.getJSONObject(index)
                if (index != 0) serializedEnvelopes.append(',')
                serializedEnvelopes
                    .append("{\"recipient_username\":")
                    .append(quote(envelope, "recipient_username"))
                    .append(",\"wrapped_key_b64\":")
                    .append(quote(envelope, "wrapped_key_b64"))
                    .append(",\"prekey_id\":")
                    .append(quote(envelope, "prekey_id"))
                    .append(",\"is_prekey\":")
                    .append(envelope.getBoolean("is_prekey"))
                    .append(",\"signature_b64\":")
                    .append(quote(envelope, "signature_b64"))
                    .append('}')
            }
            serializedEnvelopes.append(']')
            buildString {
                append("{\"type\":\"message\",\"chat_id\":")
                append(quote(frame, "chat_id"))
                append(",\"version\":9,\"message_id\":")
                append(quote(frame, "message_id"))
                append(",\"nonce_b64\":")
                append(quote(frame, "nonce_b64"))
                append(",\"ciphertext_b64\":")
                append(quote(frame, "ciphertext_b64"))
                append(",\"envelopes\":")
                append(serializedEnvelopes)
                append(",\"state_revision\":")
                append(positiveLong(frame.opt("state_revision")))
                append(",\"identity_envelope_b64\":")
                append(quote(frame, "identity_envelope_b64"))
                append(",\"identity_public_b64\":")
                append(quote(frame, "identity_public_b64"))
                append(",\"prekey_id\":")
                append(quote(frame, "prekey_id"))
                append(",\"state_signature_b64\":")
                append(quote(frame, "state_signature_b64"))
                append(",\"directory_node_id\":")
                append(quote(frame, "directory_node_id"))
                append(",\"directory_revision\":")
                append(positiveLong(frame.opt("directory_revision")))
                append(",\"directory_digest\":")
                append(quote(frame, "directory_digest"))
                append(",\"padding_bucket\":")
                append(bucket)
                append(",\"padding\":")
                append(JSONObject.quote(padding))
                append('}')
            }
        }.getOrNull()

    private fun serializeIncoming(frame: JSONObject, bucket: Int, padding: String): String? =
        runCatching {
            buildString {
                append("{\"type\":\"message\",\"chat_id\":")
                append(quote(frame, "chat_id"))
                append(",\"version\":9,\"message_id\":")
                append(quote(frame, "message_id"))
                append(",\"nonce_b64\":")
                append(quote(frame, "nonce_b64"))
                append(",\"ciphertext_b64\":")
                append(quote(frame, "ciphertext_b64"))
                append(",\"signature_b64\":")
                append(quote(frame, "signature_b64"))
                append(",\"wrapped_key_b64\":")
                append(quote(frame, "wrapped_key_b64"))
                append(",\"prekey_id\":")
                append(quote(frame, "prekey_id"))
                append(",\"is_prekey\":")
                append(frame.getBoolean("is_prekey"))
                append(",\"sender_username\":")
                append(quote(frame, "sender_username"))
                append(",\"sender_public_key_b64\":")
                append(quote(frame, "sender_public_key_b64"))
                append(",\"identity_public_b64\":")
                append(quote(frame, "identity_public_b64"))
                append(",\"directory_node_id\":")
                append(quote(frame, "directory_node_id"))
                append(",\"directory_revision\":")
                append(positiveLong(frame.opt("directory_revision")))
                append(",\"directory_digest\":")
                append(quote(frame, "directory_digest"))
                append(",\"padding_bucket\":")
                append(bucket)
                append(",\"padding\":")
                append(JSONObject.quote(padding))
                append('}')
            }
        }.getOrNull()

    private fun randomFiller(length: Int): String? {
        if (length < 0 || length > MAX_BUCKET) return null
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

    private fun allStrings(frame: JSONObject, vararg keys: String): Boolean =
        keys.all { frame.opt(it) is String }

    private fun hasExactKeys(frame: JSONObject, expected: Set<String>): Boolean {
        val actual = frame.keys().asSequence().toSet()
        return actual.size == expected.size && actual == expected
    }

    private fun integerValue(value: Any?): Int? = when (value) {
        is Int -> value
        is Long -> value.takeIf { it in Int.MIN_VALUE..Int.MAX_VALUE }?.toInt()
        else -> null
    }

    private fun positiveLong(value: Any?): Long? = when (value) {
        is Int -> value.toLong().takeIf { it > 0 }
        is Long -> value.takeIf { it > 0 }
        else -> null
    }

    private fun quote(frame: JSONObject, key: String): String =
        JSONObject.quote(frame.getString(key))

    private fun utf8ByteLength(value: String, limit: Int): Int? {
        var bytes = 0L
        var index = 0
        while (index < value.length) {
            val character = value[index]
            val width = when {
                character.code <= 0x7f -> 1
                character.code <= 0x7ff -> 2
                Character.isHighSurrogate(character) &&
                    index + 1 < value.length && Character.isLowSurrogate(value[index + 1]) -> {
                    index += 1
                    4
                }
                // Java and Okio encode an isolated UTF-16 surrogate with the
                // one-byte '?' replacement. WebSocket input itself is valid UTF-8.
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

internal fun JSONObject.padOutgoingMessage(): String? =
    MessageTransportPadding.padOutgoingMessage(this)

internal fun JSONObject.validateAndStripIncomingMessagePadding(rawText: String): Boolean =
    MessageTransportPadding.validateAndStripIncomingMessagePadding(rawText, this)

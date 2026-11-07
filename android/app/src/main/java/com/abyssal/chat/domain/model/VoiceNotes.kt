package com.abyssal.chat.domain.model

import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Locale

/**
 * Voice messages are ordinary encrypted FILE attachments with an audio MIME
 * type, plus `voice: true` and `duration_ms` in the encrypted metadata, the
 * same fields as the web client. Older clients show them as a playable file.
 */
object VoiceNotes {
    /** Longest recording, so a voice message stays a few megabytes. */
    const val MAX_DURATION_MS = 120_000L
    /** Shorter taps are treated as accidental and not sent. */
    const val MIN_DURATION_MS = 500L
    const val SAMPLE_RATE = 16_000
    const val FILE_NAME = "Voice message.wav"
    const val MIME_TYPE = "audio/wav"
    private const val BYTES_PER_SAMPLE = 2

    /** Most PCM bytes kept in memory: the duration limit at 16 kHz, 16-bit mono. */
    const val MAX_PCM_BYTES = (SAMPLE_RATE * BYTES_PER_SAMPLE * (MAX_DURATION_MS / 1000)).toInt()

    fun isAudioMime(mimeType: String?): Boolean =
        mimeType != null && Regex("^audio/[a-z0-9.+-]+(;.*)?$", RegexOption.IGNORE_CASE).matches(mimeType)

    /** The voice length to show, or null when the metadata is not a voice message. */
    fun readDuration(json: JSONObject, mediaType: String, mimeType: String): Long? {
        if (json.opt("voice") != true || mediaType != "FILE" || !isAudioMime(mimeType)) return null
        val value = (json.opt("duration_ms") as? Number)?.toDouble() ?: return 0L
        if (!value.isFinite()) return 0L
        return value.toLong().coerceIn(0L, MAX_DURATION_MS)
    }

    /** Duration of 16-bit mono PCM at [SAMPLE_RATE]. */
    fun pcmDurationMs(pcmBytes: Int): Long = pcmBytes.toLong() * 1000L / (SAMPLE_RATE * BYTES_PER_SAMPLE)

    /** A RIFF/WAVE file around 16-bit mono PCM. */
    fun wav(pcm: ByteArray, length: Int = pcm.size): ByteArray {
        require(length in 0..pcm.size && length % BYTES_PER_SAMPLE == 0)
        val header = ByteBuffer.allocate(44).order(ByteOrder.LITTLE_ENDIAN).apply {
            put("RIFF".toByteArray(Charsets.US_ASCII)); putInt(36 + length)
            put("WAVE".toByteArray(Charsets.US_ASCII))
            put("fmt ".toByteArray(Charsets.US_ASCII)); putInt(16)
            putShort(1) // PCM
            putShort(1) // mono
            putInt(SAMPLE_RATE); putInt(SAMPLE_RATE * BYTES_PER_SAMPLE)
            putShort(BYTES_PER_SAMPLE.toShort()); putShort(16)
            put("data".toByteArray(Charsets.US_ASCII)); putInt(length)
        }.array()
        return ByteArray(44 + length).also { out ->
            header.copyInto(out)
            pcm.copyInto(out, 44, 0, length)
        }
    }

    /** Where the samples of a 16-bit PCM WAV file are. */
    data class WavInfo(val sampleRate: Int, val channels: Int, val dataOffset: Int, val dataLength: Int) {
        val frames: Int get() = dataLength / (channels * BYTES_PER_SAMPLE)
    }

    /**
     * Parses a 16-bit PCM WAV strictly (mono or stereo, 8-48 kHz), so it can be
     * played straight from memory without the system media parser. Returns
     * null for anything else, which is then left to the media player.
     */
    fun parseWav(bytes: ByteArray): WavInfo? {
        if (bytes.size < 44) return null
        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        fun tag(at: Int) = String(bytes, at, 4, Charsets.US_ASCII)
        if (tag(0) != "RIFF" || tag(8) != "WAVE") return null
        var position = 12
        var format: Triple<Int, Int, Int>? = null
        while (position + 8 <= bytes.size) {
            val id = tag(position)
            val size = buffer.getInt(position + 4)
            if (size < 0 || size > bytes.size - position - 8) {
                // A streamed "data" chunk may declare more than was written; use what is there.
                if (id != "data") return null
            }
            val body = position + 8
            when (id) {
                "fmt " -> {
                    if (size < 16) return null
                    val audioFormat = buffer.getShort(body).toInt()
                    val channels = buffer.getShort(body + 2).toInt()
                    val rate = buffer.getInt(body + 4)
                    val bits = buffer.getShort(body + 14).toInt()
                    if (audioFormat != 1 || bits != 16 || channels !in 1..2 || rate !in 8_000..48_000) return null
                    format = Triple(rate, channels, bits)
                }
                "data" -> {
                    val (rate, channels, _) = format ?: return null
                    val available = minOf(if (size < 0) Int.MAX_VALUE else size, bytes.size - body)
                    val length = available - available % (channels * BYTES_PER_SAMPLE)
                    return if (length > 0) WavInfo(rate, channels, body, length) else null
                }
            }
            if (size < 0) return null
            position = body + size + (size and 1)
        }
        return null
    }

    /** "0:07", "1:45". */
    fun format(durationMs: Long): String {
        val seconds = (durationMs.coerceAtLeast(0L) + 500L) / 1000L
        return String.format(Locale.ROOT, "%d:%02d", seconds / 60, seconds % 60)
    }
}

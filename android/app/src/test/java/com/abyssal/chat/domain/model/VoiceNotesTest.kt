package com.abyssal.chat.domain.model

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

class VoiceNotesTest {
    @Test
    fun readsTheWebVoiceFieldsOnlyFromAudioFiles() {
        val voice = JSONObject("""{"voice":true,"duration_ms":7400}""")
        assertEquals(7_400L, VoiceNotes.readDuration(voice, "FILE", "audio/webm"))
        assertEquals(VoiceNotes.MAX_DURATION_MS, VoiceNotes.readDuration(JSONObject("""{"voice":true,"duration_ms":1e12}"""), "FILE", "audio/wav"))
        assertEquals(0L, VoiceNotes.readDuration(JSONObject("""{"voice":true,"duration_ms":"x"}"""), "FILE", "audio/ogg"))
        assertNull(VoiceNotes.readDuration(voice, "IMAGE", "audio/webm"))
        assertNull(VoiceNotes.readDuration(voice, "FILE", "application/pdf"))
        assertNull(VoiceNotes.readDuration(JSONObject("""{"voice":"true"}"""), "FILE", "audio/ogg"))
        assertTrue(VoiceNotes.isAudioMime("audio/webm;codecs=opus"))
        assertFalse(VoiceNotes.isAudioMime("video/webm"))
    }

    @Test
    fun wrapsPcmInAValidWaveHeader() {
        val pcm = ByteArray(32_000) { (it % 7).toByte() }
        val wav = VoiceNotes.wav(pcm, 32_000)
        assertEquals(44 + 32_000, wav.size)
        val header = ByteBuffer.wrap(wav).order(ByteOrder.LITTLE_ENDIAN)
        assertEquals("RIFF", String(wav, 0, 4, Charsets.US_ASCII))
        assertEquals(36 + 32_000, header.getInt(4))
        assertEquals("WAVE", String(wav, 8, 4, Charsets.US_ASCII))
        assertEquals(1, header.getShort(20).toInt())
        assertEquals(1, header.getShort(22).toInt())
        assertEquals(VoiceNotes.SAMPLE_RATE, header.getInt(24))
        assertEquals(16, header.getShort(34).toInt())
        assertEquals(32_000, header.getInt(40))
        assertArrayEquals(pcm, wav.copyOfRange(44, wav.size))
        assertEquals(1_000L, VoiceNotes.pcmDurationMs(32_000))
        assertEquals(VoiceNotes.MAX_DURATION_MS, VoiceNotes.pcmDurationMs(VoiceNotes.MAX_PCM_BYTES))
    }

    @Test
    fun parsesOwnWavFilesAndRejectsOtherAudio() {
        val wav = VoiceNotes.wav(ByteArray(32_000) { 1 }, 32_000)
        val info = VoiceNotes.parseWav(wav)!!
        assertEquals(VoiceNotes.SAMPLE_RATE, info.sampleRate)
        assertEquals(1, info.channels)
        assertEquals(44, info.dataOffset)
        assertEquals(32_000, info.dataLength)
        assertEquals(16_000, info.frames)
        // Truncated data is played as far as it goes.
        assertEquals(31_000, VoiceNotes.parseWav(wav.copyOf(44 + 31_000))!!.dataLength)
        assertNull(VoiceNotes.parseWav(byteArrayOf(0x1a, 0x45, 0xdf.toByte(), 0xa3.toByte()) + ByteArray(60)))
        assertNull(VoiceNotes.parseWav(wav.copyOf().also { it[20] = 3 })) // not PCM
        assertNull(VoiceNotes.parseWav(wav.copyOf().also { it[34] = 8 })) // 8-bit
        assertNull(VoiceNotes.parseWav(wav.copyOf(30)))
    }

    @Test
    fun formatsDurations() {
        assertEquals("0:07", VoiceNotes.format(7_400))
        assertEquals("1:45", VoiceNotes.format(105_000))
        assertEquals("0:00", VoiceNotes.format(-5))
    }
}

package com.abyssal.chat.data.media

import android.annotation.SuppressLint
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import com.abyssal.chat.domain.model.VoiceNotes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Records 16 kHz mono PCM from the microphone into a fixed in-memory buffer,
 * never to disk. [stop] returns the recording as WAV bytes and wipes the PCM;
 * [cancel] wipes it without returning anything. Call start, stop and cancel
 * from one thread (the main thread); the capture loop runs on IO and is
 * joined before the buffer is read.
 */
internal class PcmVoiceRecorder {
    private var record: AudioRecord? = null
    private var job: Job? = null
    private var pcm: ByteArray? = null
    @Volatile private var length = 0

    val isRecording: Boolean get() = record != null

    /** Starts recording; [onLimit] runs when the length limit is reached. The caller holds RECORD_AUDIO. */
    @SuppressLint("MissingPermission")
    fun start(scope: CoroutineScope, onLimit: () -> Unit): Boolean {
        if (record != null) return false
        val minBuffer = AudioRecord.getMinBufferSize(
            VoiceNotes.SAMPLE_RATE, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT
        )
        if (minBuffer <= 0) return false
        val recorder = runCatching {
            AudioRecord(
                MediaRecorder.AudioSource.VOICE_RECOGNITION,
                VoiceNotes.SAMPLE_RATE,
                AudioFormat.CHANNEL_IN_MONO,
                AudioFormat.ENCODING_PCM_16BIT,
                minBuffer * 2
            )
        }.getOrNull() ?: return false
        if (recorder.state != AudioRecord.STATE_INITIALIZED || runCatching { recorder.startRecording() }.isFailure) {
            recorder.release()
            return false
        }
        val buffer = ByteArray(VoiceNotes.MAX_PCM_BYTES)
        pcm = buffer
        length = 0
        record = recorder
        job = scope.launch(Dispatchers.IO) {
            val chunk = ByteArray(minBuffer)
            try {
                while (isActive) {
                    val read = recorder.read(chunk, 0, chunk.size)
                    if (read <= 0) continue
                    val room = buffer.size - length
                    val take = minOf(read - read % 2, room)
                    chunk.copyInto(buffer, length, 0, take)
                    length += take
                    if (length >= buffer.size) {
                        launch(Dispatchers.Main) { onLimit() }
                        break
                    }
                }
            } finally {
                chunk.fill(0)
            }
        }
        return true
    }

    /** Stops and returns the recording as WAV, or null if nothing usable was captured. */
    suspend fun stop(): ByteArray? {
        val captured = finish() ?: return null
        val (buffer, size) = captured
        return try {
            if (VoiceNotes.pcmDurationMs(size) < VoiceNotes.MIN_DURATION_MS) null else VoiceNotes.wav(buffer, size)
        } finally {
            buffer.fill(0)
        }
    }

    suspend fun cancel() {
        finish()?.first?.fill(0)
    }

    private suspend fun finish(): Pair<ByteArray, Int>? {
        val recorder = record ?: return null
        record = null
        // stop() unblocks a pending read, so the capture loop can be joined.
        runCatching { recorder.stop() }
        job?.cancelAndJoin()
        job = null
        recorder.release()
        val buffer = pcm ?: return null
        pcm = null
        return buffer to (length - length % 2)
    }
}

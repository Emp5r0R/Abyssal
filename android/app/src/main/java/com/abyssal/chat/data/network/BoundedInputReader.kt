package com.abyssal.chat.data.network

import java.io.ByteArrayOutputStream
import java.io.InputStream

/** Reads an untrusted stream without allowing it to grow beyond the caller's limit. */
internal object BoundedInputReader {
    private const val CHUNK_BYTES = 64 * 1024

    /** Reads an exact positive-length body into one destination allocation. */
    fun readExact(input: InputStream, expectedBytes: Long, maxBytes: Long): ByteArray? {
        if (
            expectedBytes <= 0L ||
            expectedBytes > maxBytes ||
            expectedBytes > Int.MAX_VALUE.toLong()
        ) return null
        val output = ByteArray(expectedBytes.toInt())
        var offset = 0
        var complete = false
        return try {
            while (offset < output.size) {
                val count = input.read(output, offset, output.size - offset)
                when {
                    count < 0 -> return null
                    count == 0 -> {
                        val next = input.read()
                        if (next < 0) return null
                        output[offset++] = next.toByte()
                    }
                    count > output.size - offset -> return null
                    else -> offset += count
                }
            }
            if (input.read() >= 0) return null
            complete = true
            output
        } catch (_: Exception) {
            null
        } finally {
            if (!complete) output.fill(0)
        }
    }

    fun read(input: InputStream, maxBytes: Long): ByteArray? {
        require(maxBytes in 0L..Int.MAX_VALUE.toLong())
        val output = WipingByteArrayOutputStream(minOf(maxBytes, CHUNK_BYTES.toLong()).toInt())
        val chunk = ByteArray(CHUNK_BYTES)
        return try {
            while (true) {
                val count = input.read(chunk)
                if (count < 0) break
                if (count == 0) continue
                if (output.size().toLong() + count > maxBytes) return null
                output.write(chunk, 0, count)
            }
            output.toByteArray()
        } catch (_: Exception) {
            null
        } finally {
            chunk.fill(0)
            output.wipe()
        }
    }

    private class WipingByteArrayOutputStream(initialSize: Int) : ByteArrayOutputStream(initialSize) {
        fun wipe() {
            buf.fill(0)
            reset()
        }
    }
}

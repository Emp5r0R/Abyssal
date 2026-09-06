package com.abyssal.chat.data.qr

import java.io.InputStream
import java.io.InterruptedIOException

internal object QrImageBytes {
    fun read(input: InputStream, maximum: Int = 8 * 1024 * 1024): ByteArray {
        require(maximum in 1..8 * 1024 * 1024)
        val deadline = System.nanoTime() + 10_000_000_000L
        val bytes = ByteArray(maximum)
        var offset = 0
        try {
            while (true) {
                if (Thread.currentThread().isInterrupted || System.nanoTime() >= deadline) throw InterruptedIOException()
                if (offset == maximum) {
                    require(input.read() == -1) { "QR image rejected" }
                    break
                }
                val count = input.read(bytes, offset, minOf(64 * 1024, maximum - offset))
                if (count < 0) break
                require(count in 1..minOf(64 * 1024, maximum - offset)) { "QR image rejected" }
                offset += count
            }
            if (Thread.currentThread().isInterrupted || System.nanoTime() >= deadline) throw InterruptedIOException()
            require(offset > 0) { "QR image rejected" }
            return bytes.copyOf(offset)
        } finally { bytes.fill(0) }
    }
}

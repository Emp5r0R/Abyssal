package com.abyssal.chat.data.network

import java.io.ByteArrayInputStream
import java.io.InputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Test

class BoundedInputReaderTest {
    @Test
    fun readsExactlyUpToLimit() {
        val source = ByteArray(128) { it.toByte() }

        val result = BoundedInputReader.read(ByteArrayInputStream(source), source.size.toLong())

        assertArrayEquals(source, result)
    }

    @Test
    fun rejectsUnknownLengthStreamBeforeReturningOversizedData() {
        val source = ByteArray(129) { it.toByte() }

        val result = BoundedInputReader.read(
            UnknownLengthInputStream(source),
            maxBytes = 128L
        )

        assertNull(result)
    }

    @Test
    fun zeroLimitAcceptsOnlyAnEmptyStream() {
        assertArrayEquals(
            ByteArray(0),
            BoundedInputReader.read(ByteArrayInputStream(ByteArray(0)), maxBytes = 0L)
        )
        assertNull(
            BoundedInputReader.read(ByteArrayInputStream(byteArrayOf(1)), maxBytes = 0L)
        )
    }

    private class UnknownLengthInputStream(private val bytes: ByteArray) : InputStream() {
        private var offset = 0

        override fun read(): Int {
            if (offset >= bytes.size) return -1
            return bytes[offset++].toInt() and 0xff
        }

        override fun read(buffer: ByteArray, start: Int, length: Int): Int {
            if (offset >= bytes.size) return -1
            val count = minOf(length, bytes.size - offset)
            bytes.copyInto(buffer, start, offset, offset + count)
            offset += count
            return count
        }
    }
}

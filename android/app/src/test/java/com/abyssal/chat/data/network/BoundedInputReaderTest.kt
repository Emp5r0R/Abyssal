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

    @Test
    fun exactReaderRequiresPositiveLengthAndRejectsTruncatedOrExtraData() {
        val source = byteArrayOf(1, 2, 3)

        assertNull(BoundedInputReader.readExact(ByteArrayInputStream(source), 0L, 3L))
        assertNull(BoundedInputReader.readExact(ByteArrayInputStream(source), -1L, 3L))
        assertNull(BoundedInputReader.readExact(ByteArrayInputStream(source), 4L, 4L))
        assertNull(BoundedInputReader.readExact(ByteArrayInputStream(source + byteArrayOf(4)), 3L, 3L))
        assertArrayEquals(
            source,
            BoundedInputReader.readExact(ByteArrayInputStream(source), source.size.toLong(), 3L)
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

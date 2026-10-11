package com.abyssal.chat.data.qr

import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.nio.ByteBuffer
import org.junit.Assert.*
import org.junit.Test

class InviteQrDecoderTest {
    /** Renders [text] as greyscale with blank rows between module rows, inverted or borderless. */
    private fun render(text: String, scale: Int, margin: Int, gapRows: Int = 0, invert: Boolean = false): Triple<ByteArray, Int, Int> {
        val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0, mapOf(EncodeHintType.MARGIN to margin))
        val side = matrix.width * scale
        val pixels = ByteArray(side * side) { index ->
            val x = index % side
            val y = index / side
            val inGap = gapRows > 0 && y % scale >= scale - gapRows
            val dark = !inGap && matrix[x / scale, y / scale]
            if (dark != invert) 0 else 255.toByte()
        }
        return Triple(pixels, side, side)
    }

    @Test fun stillImagesReadThroughTerminalGapsInversionAndMissingBorders() {
        val text = "abyssal:invite:" + "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z".repeat(10)
        val cases = listOf(
            render(text, scale = 8, margin = 2, gapRows = 3),
            render(text, scale = 4, margin = 4, invert = true),
            render(text, scale = 4, margin = 0),
        )
        for ((pixels, width, height) in cases) {
            assertEquals(text, InviteQrDecoder.decodeLuminance(pixels, width, height, thorough = true))
        }
        val (blank, side, _) = Triple(ByteArray(300 * 300) { 255.toByte() }, 300, 300)
        assertNull(InviteQrDecoder.decodeLuminance(blank, side, side, thorough = true))
    }

    @Test fun cameraPlaneStridesAndOffsetsAreBounded() {
        val buffer = ByteBuffer.wrap(byteArrayOf(99, 0, 9, 1, 9, 88, 2, 9, 3))
        buffer.position(1)
        assertArrayEquals(byteArrayOf(0, 1, 2, 3), InviteQrDecoder.copyPlane(buffer, 2, 2, 5, 2))
        assertEquals(1, buffer.position())
        assertThrows(IllegalArgumentException::class.java) { InviteQrDecoder.copyPlane(buffer, 100_000, 2, 5, 2) }
        assertThrows(IllegalArgumentException::class.java) { InviteQrDecoder.copyPlane(buffer, 2, 2, Int.MAX_VALUE, 2) }
        assertThrows(IllegalArgumentException::class.java) { InviteQrDecoder.copyPlane(buffer, 3, 2, 2, 2) }
    }

    @Test fun realPngAndJpegDecodeTheSameSignedInviteLocally() {
        for ((file, mime) in listOf("invite-v1.png" to "image/png", "invite-v1.jpeg" to "image/jpeg", "invite-qrencode.png" to "image/png")) {
            val bytes = requireNotNull(javaClass.getResourceAsStream("/qr/$file")).use { it.readBytes() }
            try {
                assertEquals(INVITE, InviteQrDecoder.decodeImage(bytes, mime))
                assertTrue(InviteQrDecoder.isVerifiedInvite(INVITE, false, 2_000_000_000))
                assertThrows(Exception::class.java) { InviteQrDecoder.decodeImage(bytes, "image/svg+xml") }
            } finally { bytes.fill(0) }
        }
    }

    @Test fun maliciousQrContentsNeverBecomeAConnection() {
        for (value in listOf("file:///etc/passwd", "https://evil.example", "intent://open", "data:image/svg+xml,test", "x".repeat(2049))) {
            assertFalse(InviteQrDecoder.isVerifiedInvite(value, false))
        }
        assertFalse(InviteQrDecoder.isVerifiedInvite(INVITE.dropLast(1) + "A", false, 2_000_000_000))
        assertFalse(InviteQrDecoder.isVerifiedInvite(INVITE, false, 2_100_000_001))
        assertThrows(Exception::class.java) {
            InviteQrDecoder.decodeImage("<svg><image href='file:///etc/passwd'/></svg>".toByteArray(), "image/png")
        }
    }

    @Test fun fileReadBoundsZeroProgressAndFailureCleanup() {
        assertArrayEquals(byteArrayOf(1, 2), QrImageBytes.read(ByteArrayInputStream(byteArrayOf(1, 2)), 2))
        assertThrows(IllegalArgumentException::class.java) { QrImageBytes.read(ByteArrayInputStream(byteArrayOf(1, 2, 3)), 2) }
        assertThrows(IllegalArgumentException::class.java) { QrImageBytes.read(ByteArrayInputStream(byteArrayOf()), 2) }
        var destination: ByteArray? = null
        val hostile = object : InputStream() {
            override fun read() = 0
            override fun read(bytes: ByteArray, off: Int, len: Int): Int {
                destination = bytes
                bytes.fill(42)
                return 0
            }
        }
        assertThrows(IllegalArgumentException::class.java) { QrImageBytes.read(hostile, 2) }
        assertTrue(requireNotNull(destination).all { it == 0.toByte() })
    }

    companion object {
        const val INVITE = "abyssal:invite:glh3igFwb3JnLmFieXNzYWwuY2hhdAFYINBKsjJ0K7SrOhNovUYV5ObQIkq3GgFrr4UgozLJd4c3gYMBcG5vZGUuZXhhbXBsZS5jb20ZAbtYICIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiCQoAGn0rdQBYQDgZJxVYJlrtgAJBj4VbdykqYpymbDWTNY0Uz-18fOOxGzi6fwKTPzEnVkJ6QldbfyY0pl1JJchNJv3TknkT-Qs"
    }
}

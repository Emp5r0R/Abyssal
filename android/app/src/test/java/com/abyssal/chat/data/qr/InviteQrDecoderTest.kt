package com.abyssal.chat.data.qr

import java.io.ByteArrayInputStream
import java.io.InputStream
import java.nio.ByteBuffer
import org.junit.Assert.*
import org.junit.Test

class InviteQrDecoderTest {
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

package com.abyssal.chat.data.network

import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class VerifiedApkFileWriterTest {
    @get:Rule
    val temporary = TemporaryFolder()

    @Test
    fun writesOnlyAnExactSizeAndDigestMatch() {
        val bytes = "verified apk bytes".toByteArray()
        val output = temporary.root.resolve("update.apk")

        assertTrue(
            VerifiedApkFileWriter.write(
                ByteArrayInputStream(bytes),
                output,
                bytes.size.toLong(),
                sha256(bytes)
            )
        )
        assertArrayEquals(bytes, output.readBytes())
    }

    @Test
    fun rejectsDigestMismatchTruncationAndOverflowWithoutLeavingAFile() {
        val bytes = ByteArray(32) { it.toByte() }
        val cases = listOf(
            Triple(bytes, bytes.size.toLong(), "0".repeat(64)),
            Triple(bytes.copyOf(bytes.size - 1), bytes.size.toLong(), sha256(bytes)),
            Triple(bytes + 1, bytes.size.toLong(), sha256(bytes))
        )

        cases.forEachIndexed { index, (body, size, digest) ->
            val output = temporary.root.resolve("rejected-$index.apk")
            assertFalse(VerifiedApkFileWriter.write(ByteArrayInputStream(body), output, size, digest))
            assertFalse(output.exists())
        }
    }

    @Test
    fun refusesToOverwriteAndCleansUpAfterReadFailure() {
        val existing = temporary.newFile("existing.apk").apply { writeText("keep") }
        assertFalse(
            VerifiedApkFileWriter.write(
                ByteArrayInputStream(byteArrayOf(1)),
                existing,
                1,
                sha256(byteArrayOf(1))
            )
        )
        assertArrayEquals("keep".toByteArray(), existing.readBytes())

        val failed = temporary.root.resolve("failed.apk")
        assertFalse(
            VerifiedApkFileWriter.write(
                object : InputStream() {
                    override fun read(): Int = throw IOException("failed")
                    override fun read(buffer: ByteArray, offset: Int, length: Int): Int =
                        throw IOException("failed")
                },
                failed,
                1,
                sha256(byteArrayOf(1))
            )
        )
        assertFalse(failed.exists())
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes)
        .joinToString("") { byte -> "%02x".format(byte) }
}

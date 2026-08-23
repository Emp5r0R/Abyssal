package com.abyssal.chat.data.network

import java.io.File
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import java.security.MessageDigest

internal object VerifiedApkFileWriter {
    private val sha256Pattern = Regex("^[0-9a-f]{64}$")

    fun write(
        input: InputStream,
        output: File,
        expectedSize: Long,
        expectedSha256Hex: String
    ): Boolean {
        if (expectedSize <= 0L || !sha256Pattern.matches(expectedSha256Hex)) return false
        val expectedDigest = expectedSha256Hex.chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        val digest = MessageDigest.getInstance("SHA-256")
        var total = 0L
        var accepted = false
        var created = false
        try {
            val destination = Files.newOutputStream(
                output.toPath(),
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE
            )
            created = true
            destination.use {
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    if (read == 0) return false
                    total = Math.addExact(total, read.toLong())
                    if (total > expectedSize) return false
                    digest.update(buffer, 0, read)
                    it.write(buffer, 0, read)
                }
                it.flush()
            }
            if (total != expectedSize) return false
            val actualDigest = digest.digest()
            try {
                accepted = MessageDigest.isEqual(expectedDigest, actualDigest)
                return accepted
            } finally {
                actualDigest.fill(0)
            }
        } catch (_: Exception) {
            return false
        } finally {
            buffer.fill(0)
            expectedDigest.fill(0)
            if (!accepted && created) output.delete()
        }
    }
}

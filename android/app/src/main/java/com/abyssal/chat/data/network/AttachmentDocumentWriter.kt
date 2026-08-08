package com.abyssal.chat.data.network

import java.io.OutputStream
import java.util.concurrent.CancellationException

internal object AttachmentDocumentWriter {
    private const val CHUNK_BYTES = 64 * 1024

    fun writeIfNonEmpty(bytes: ByteArray, openOutput: () -> OutputStream?): Boolean {
        if (bytes.isEmpty()) return false
        val output = openOutput() ?: return false
        return try {
            output.use { write(bytes, it) }
            true
        } catch (error: CancellationException) {
            throw error
        } catch (_: Exception) {
            false
        }
    }

    fun writeIfNonEmptyOrDelete(
        bytes: ByteArray,
        openOutput: () -> OutputStream?,
        deleteOutput: () -> Unit
    ): Boolean {
        val written = try {
            writeIfNonEmpty(bytes, openOutput)
        } catch (error: CancellationException) {
            runCatching { deleteOutput() }
            throw error
        }
        if (!written) deleteOutput()
        return written
    }

    fun write(bytes: ByteArray, output: OutputStream) {
        var offset = 0
        while (offset < bytes.size) {
            val count = minOf(CHUNK_BYTES, bytes.size - offset)
            output.write(bytes, offset, count)
            offset += count
        }
        output.flush()
    }
}

package com.abyssal.chat.data.network

import java.io.OutputStream
import java.util.concurrent.CancellationException

internal object AttachmentDocumentWriter {
    private const val CHUNK_BYTES = 64 * 1024

    fun writeIfNonEmpty(
        bytes: ByteArray,
        shouldCancel: () -> Boolean = { false },
        openOutput: () -> OutputStream?
    ): Boolean {
        if (bytes.isEmpty()) return false
        val output = openOutput() ?: return false
        return try {
            output.use { write(bytes, it, shouldCancel) }
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
        deleteOutput: () -> Unit,
        shouldCancel: () -> Boolean = { false }
    ): Boolean {
        val written = try {
            writeIfNonEmpty(bytes, shouldCancel, openOutput)
        } catch (error: CancellationException) {
            runCatching { deleteOutput() }
            throw error
        }
        if (!written) deleteOutput()
        return written
    }

    fun write(
        bytes: ByteArray,
        output: OutputStream,
        shouldCancel: () -> Boolean = { false }
    ) {
        var offset = 0
        while (offset < bytes.size) {
            if (shouldCancel()) throw CancellationException("attachment save cancelled")
            val count = minOf(CHUNK_BYTES, bytes.size - offset)
            output.write(bytes, offset, count)
            offset += count
        }
        output.flush()
    }
}

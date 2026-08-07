package com.abyssal.chat.data.network

import java.io.OutputStream

internal object AttachmentDocumentWriter {
    private const val CHUNK_BYTES = 64 * 1024

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

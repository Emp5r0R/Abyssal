package com.abyssal.chat.data.network

import android.content.ContentResolver
import android.net.Uri
import com.abyssal.chat.domain.repository.IAttachmentPlaintextSource
import java.io.ByteArrayInputStream
import java.io.FilterInputStream
import java.io.IOException
import java.io.InputStream
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

class ByteArrayAttachmentSource(
    private val bytes: ByteArray
) : IAttachmentPlaintextSource {
    private val opened = AtomicBoolean(false)
    private val destroyed = AtomicBoolean(false)

    override val sizeBytes: Long = bytes.size.toLong()

    override fun openStream(): InputStream {
        if (destroyed.get() || !opened.compareAndSet(false, true)) {
            throw IOException("Attachment unavailable")
        }
        return ByteArrayInputStream(bytes)
    }

    override fun destroy() {
        if (destroyed.compareAndSet(false, true)) bytes.fill(0)
    }
}

class ContentUriAttachmentSource(
    private val resolver: ContentResolver,
    private val uri: Uri,
    override val sizeBytes: Long
) : IAttachmentPlaintextSource {
    private val opened = AtomicBoolean(false)
    private val destroyed = AtomicBoolean(false)
    private val activeStream = AtomicReference<InputStream?>(null)

    override fun openStream(): InputStream {
        if (destroyed.get() || !opened.compareAndSet(false, true)) {
            throw IOException("Attachment unavailable")
        }
        val stream = resolver.openInputStream(uri) ?: throw IOException("Attachment unavailable")
        if (destroyed.get() || !activeStream.compareAndSet(null, stream)) {
            stream.close()
            throw IOException("Attachment unavailable")
        }
        return object : FilterInputStream(stream) {
            private val closed = AtomicBoolean(false)

            override fun close() {
                if (closed.compareAndSet(false, true)) {
                    activeStream.compareAndSet(stream, null)
                    super.close()
                }
            }
        }
    }

    override fun destroy() {
        destroyed.set(true)
        runCatching { activeStream.getAndSet(null)?.close() }
    }
}

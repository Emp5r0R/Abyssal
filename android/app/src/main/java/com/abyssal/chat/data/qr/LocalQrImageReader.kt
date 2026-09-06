package com.abyssal.chat.data.qr

import android.content.ContentResolver
import android.net.Uri
import android.os.CancellationSignal
import java.io.InputStream
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeout

/** A user-selected content grant is read in RAM; never resolve a name to a path. */
internal object LocalQrImageReader {
    const val MAX_BYTES = 8L * 1024 * 1024
    private val executor = ThreadPoolExecutor(1, 1, 0L, TimeUnit.SECONDS, ArrayBlockingQueue(1))

    suspend fun read(resolver: ContentResolver, uri: Uri): String = withTimeout(10_000) {
        require(uri.scheme == ContentResolver.SCHEME_CONTENT) { "QR image rejected" }
        suspendCancellableCoroutine { continuation ->
            val signal = CancellationSignal()
            val stream = AtomicReference<InputStream?>(null)
            val future = try {
                executor.submit {
                    var bytes: ByteArray? = null
                    try {
                        if (!continuation.isActive) return@submit
                        val mime = resolver.getType(uri).orEmpty()
                        require(mime.isEmpty() || mime == "image/png" || mime == "image/jpeg")
                        resolver.openAssetFileDescriptor(uri, "r", signal)?.use { descriptor ->
                            require(descriptor.length <= MAX_BYTES)
                            descriptor.createInputStream().use { input ->
                                stream.set(input)
                                if (!continuation.isActive) return@submit
                                bytes = QrImageBytes.read(input)
                                val value = InviteQrDecoder.decodeImage(requireNotNull(bytes), mime)
                                require(!value.isNullOrEmpty())
                                if (continuation.isActive) continuation.resume(value)
                            }
                        } ?: throw IllegalArgumentException("QR image rejected")
                    } catch (_: Exception) {
                        if (continuation.isActive) continuation.resumeWithException(IllegalArgumentException("QR image rejected"))
                    } finally {
                        stream.set(null)
                        bytes?.fill(0)
                    }
                }
            } catch (_: Exception) {
                continuation.resumeWithException(IllegalArgumentException("QR image rejected"))
                null
            }
            continuation.invokeOnCancellation {
                signal.cancel()
                runCatching { stream.getAndSet(null)?.close() }
                future?.cancel(true)
                executor.purge()
            }
        }
    }
}

package com.abyssal.chat.data.network

import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.suspendCancellableCoroutine
import okhttp3.Call
import okhttp3.Callback
import okhttp3.Response

/**
 * Bridges an OkHttp callback to a cancellable coroutine while keeping response ownership
 * on this function. The response is always closed, including a late callback after cancel.
 */
@OptIn(ExperimentalCoroutinesApi::class)
internal suspend fun <T> awaitHttpResponse(
    call: Call,
    onCancellation: (T) -> Unit = {},
    onLateResponse: (Response) -> Unit = {},
    consume: (Response) -> T
): T = suspendCancellableCoroutine { continuation ->
    val settled = AtomicBoolean(false)
    continuation.invokeOnCancellation { call.cancel() }
    try {
        call.enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                if (!continuation.isActive || !settled.compareAndSet(false, true)) return
                continuation.resumeWithException(e)
            }

            override fun onResponse(call: Call, response: Response) {
                if (!continuation.isActive || !settled.compareAndSet(false, true)) {
                    response.use { runCatching { onLateResponse(it) } }
                    return
                }
                val result = try {
                    response.use(consume)
                } catch (error: Exception) {
                    if (continuation.isActive) continuation.resumeWithException(error)
                    return
                }
                if (!continuation.isActive) {
                    onCancellation(result)
                    return
                }
                continuation.resume(result) { onCancellation(result) }
            }
        })
    } catch (error: Exception) {
        if (continuation.isActive && settled.compareAndSet(false, true)) {
            continuation.resumeWithException(error)
        }
    }
}

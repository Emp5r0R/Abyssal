package com.abyssal.chat.data.network

import java.util.Locale

/**
 * The wire protocol remains capped at 20/100/200 MiB. Android admits a
 * smaller buffer when the process heap cannot safely hold the plaintext,
 * encrypted blob, native bridge copies, and UI/runtime headroom together.
 */
internal object AttachmentMemoryPolicy {
    const val IMAGE_LIMIT_BYTES = 20L * 1024L * 1024L
    const val VIDEO_LIMIT_BYTES = 100L * 1024L * 1024L
    const val FILE_LIMIT_BYTES = 200L * 1024L * 1024L
    const val HEAP_HEADROOM_BYTES = 64L * 1024L * 1024L
    const val SIMULTANEOUS_COPY_FACTOR = 4L

    fun protocolLimitBytes(mediaType: String): Long = when (mediaType.uppercase(Locale.ROOT)) {
        "IMAGE" -> IMAGE_LIMIT_BYTES
        "VIDEO" -> VIDEO_LIMIT_BYTES
        else -> FILE_LIMIT_BYTES
    }

    /** Returns zero when the process cannot safely admit even a one-byte payload. */
    fun effectiveLimitBytes(protocolLimitBytes: Long, availableHeapBytes: Long): Long {
        if (protocolLimitBytes <= 0L || availableHeapBytes <= HEAP_HEADROOM_BYTES) return 0L
        val copyBudget = (availableHeapBytes - HEAP_HEADROOM_BYTES) / SIMULTANEOUS_COPY_FACTOR
        return minOf(protocolLimitBytes, copyBudget).coerceAtMost(Int.MAX_VALUE.toLong())
    }

    fun effectiveLimitBytes(mediaType: String, runtime: Runtime = Runtime.getRuntime()): Long {
        val usedHeap = (runtime.totalMemory() - runtime.freeMemory()).coerceAtLeast(0L)
        val availableHeap = (runtime.maxMemory() - usedHeap).coerceAtLeast(0L)
        return effectiveLimitBytes(protocolLimitBytes(mediaType), availableHeap)
    }

    fun effectiveWireLimitBytes(mediaType: String, runtime: Runtime = Runtime.getRuntime()): Long {
        val plaintextLimit = effectiveLimitBytes(mediaType, runtime)
        return if (plaintextLimit <= 0L) 0L else plaintextLimit + ATTACHMENT_WIRE_OVERHEAD_BYTES
    }
}

internal fun protocolAttachmentLimitBytes(mediaType: String): Long =
    AttachmentMemoryPolicy.protocolLimitBytes(mediaType)

internal fun attachmentSelectionLimitBytes(mediaType: String): Long =
    AttachmentMemoryPolicy.effectiveLimitBytes(mediaType)

internal fun attachmentWireSelectionLimitBytes(mediaType: String): Long =
    AttachmentMemoryPolicy.effectiveWireLimitBytes(mediaType)

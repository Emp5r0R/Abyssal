package com.abyssal.chat.data.network

import org.junit.Assert.assertEquals
import org.junit.Test

class AttachmentMemoryPolicyTest {
    @Test
    fun protocolLimitsRemainStableAndCaseInsensitive() {
        assertEquals(20L * 1024L * 1024L, AttachmentMemoryPolicy.protocolLimitBytes("image"))
        assertEquals(100L * 1024L * 1024L, AttachmentMemoryPolicy.protocolLimitBytes("VIDEO"))
        assertEquals(200L * 1024L * 1024L, AttachmentMemoryPolicy.protocolLimitBytes("file"))
        assertEquals(200L * 1024L * 1024L, AttachmentMemoryPolicy.protocolLimitBytes("unknown"))
    }

    @Test
    fun effectiveLimitHonorsHeadroomAndCopyFactorAtExactBoundaries() {
        val protocolLimit = AttachmentMemoryPolicy.VIDEO_LIMIT_BYTES
        val exactHeap = AttachmentMemoryPolicy.HEAP_HEADROOM_BYTES +
            protocolLimit * AttachmentMemoryPolicy.SIMULTANEOUS_COPY_FACTOR

        assertEquals(0L, AttachmentMemoryPolicy.effectiveLimitBytes(1L, AttachmentMemoryPolicy.HEAP_HEADROOM_BYTES))
        assertEquals(
            1L,
            AttachmentMemoryPolicy.effectiveLimitBytes(
                1L,
                AttachmentMemoryPolicy.HEAP_HEADROOM_BYTES + AttachmentMemoryPolicy.SIMULTANEOUS_COPY_FACTOR
            )
        )
        assertEquals(
            protocolLimit,
            AttachmentMemoryPolicy.effectiveLimitBytes(protocolLimit, exactHeap)
        )
        assertEquals(
            protocolLimit - 1L,
            AttachmentMemoryPolicy.effectiveLimitBytes(
                protocolLimit,
                exactHeap - AttachmentMemoryPolicy.SIMULTANEOUS_COPY_FACTOR
            )
        )
    }

    @Test
    fun effectiveLimitRejectsInvalidHeapAndSaturatesOverflow() {
        assertEquals(0L, AttachmentMemoryPolicy.effectiveLimitBytes(1L, -1L))
        assertEquals(0L, AttachmentMemoryPolicy.effectiveLimitBytes(0L, Long.MAX_VALUE))
        assertEquals(0L, AttachmentMemoryPolicy.effectiveLimitBytes(-1L, Long.MAX_VALUE))
        assertEquals(
            Int.MAX_VALUE.toLong(),
            AttachmentMemoryPolicy.effectiveLimitBytes(Long.MAX_VALUE, Long.MAX_VALUE)
        )
    }
}

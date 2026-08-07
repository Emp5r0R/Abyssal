package com.abyssal.chat.domain.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AttachmentSavePolicyTest {
    @Test
    fun onlyRegularDownloadableMediaCanBeSaved() {
        val regular = mediaMessage()

        assertTrue(AttachmentSavePolicy.canSave(regular))
        assertFalse(AttachmentSavePolicy.canSave(regular.copy(oneTimeView = true)))
        assertFalse(AttachmentSavePolicy.canSave(regular.copy(saveAllowed = false)))
        assertFalse(AttachmentSavePolicy.canSave(regular.copy(isMedia = false)))
        assertFalse(AttachmentSavePolicy.canSave(regular.copy(attachmentId = null)))
    }

    @Test
    fun originalExtensionIsPreservedAndUnsafeCharactersAreRemoved() {
        assertEquals("evidence.tar.gz", AttachmentSavePolicy.sanitizedFileName("evidence.tar.gz"))
        assertEquals(
            "_.._report_.pdf",
            AttachmentSavePolicy.sanitizedFileName(" ../..\\report\u202e.pdf ")
        )
        assertEquals("attachment", AttachmentSavePolicy.sanitizedFileName(" ... "))
    }

    @Test
    fun longNamesStayBoundedWithoutDroppingExtensionOrSplittingUnicode() {
        val name = "🔐".repeat(200) + ".mp4"
        val sanitized = AttachmentSavePolicy.sanitizedFileName(name)

        assertTrue(sanitized.endsWith(".mp4"))
        assertEquals(160, sanitized.codePointCount(0, sanitized.length))
    }

    private fun mediaMessage() = Message(
        id = "message-1",
        sender = "You",
        receiver = "peer",
        content = "document.pdf",
        timestampMs = 1L,
        selfDestructDurationSec = 0,
        isMedia = true,
        mediaType = "FILE",
        attachmentId = "attachment-1",
        attachmentName = "document.pdf",
        attachmentMimeType = "application/pdf"
    )
}

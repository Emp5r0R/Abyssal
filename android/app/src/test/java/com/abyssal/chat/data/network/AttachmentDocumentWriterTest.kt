package com.abyssal.chat.data.network

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.OutputStream
import java.util.concurrent.CancellationException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AttachmentDocumentWriterTest {
    @Test
    fun explicitSaveWritesAuthenticatedPlaintextBytesWithoutEnvelope() {
        val attachmentBytes = ByteArray(150_000) { index -> (index % 251).toByte() }
        val originalSnapshot = attachmentBytes.copyOf()
        val output = ByteArrayOutputStream()

        assertTrue(AttachmentDocumentWriter.writeIfNonEmpty(attachmentBytes) { output })

        assertArrayEquals(originalSnapshot, output.toByteArray())
        assertArrayEquals(originalSnapshot, attachmentBytes)
    }

    @Test
    fun emptyAttachmentDoesNotOpenOrTruncateDestination() {
        var opened = false

        assertFalse(
            AttachmentDocumentWriter.writeIfNonEmpty(ByteArray(0)) {
                opened = true
                ByteArrayOutputStream()
            }
        )

        assertFalse(opened)
    }

    @Test
    fun failedWriteDeletesProviderCreatedDestination() {
        var deleted = false

        val result = AttachmentDocumentWriter.writeIfNonEmptyOrDelete(
            bytes = byteArrayOf(1, 2, 3),
            openOutput = {
                object : OutputStream() {
                    override fun write(value: Int) = throw IOException("provider failed")
                }
            },
            deleteOutput = { deleted = true }
        )

        assertFalse(result)
        assertTrue(deleted)
    }

    @Test
    fun emptyPayloadDeletesPickerCreatedDestinationWithoutOpeningIt() {
        var opened = false
        var deleted = false

        val result = AttachmentDocumentWriter.writeIfNonEmptyOrDelete(
            bytes = ByteArray(0),
            openOutput = {
                opened = true
                ByteArrayOutputStream()
            },
            deleteOutput = { deleted = true }
        )

        assertFalse(result)
        assertFalse(opened)
        assertTrue(deleted)
    }

    @Test
    fun nullProviderStreamDeletesPickerCreatedDestination() {
        var deleted = false

        val result = AttachmentDocumentWriter.writeIfNonEmptyOrDelete(
            bytes = byteArrayOf(1),
            openOutput = { null },
            deleteOutput = { deleted = true }
        )

        assertFalse(result)
        assertTrue(deleted)
    }

    @Test
    fun cancellationDeletesPartialPickerDestinationAndPropagates() {
        var deleted = false
        val cancellation = CancellationException("cancelled")

        try {
            AttachmentDocumentWriter.writeIfNonEmptyOrDelete(
                bytes = byteArrayOf(1, 2, 3),
                openOutput = {
                    object : OutputStream() {
                        override fun write(value: Int) = throw cancellation
                    }
                },
                deleteOutput = { deleted = true }
            )
        } catch (error: CancellationException) {
            assertTrue(error === cancellation)
        }

        assertTrue(deleted)
    }
}

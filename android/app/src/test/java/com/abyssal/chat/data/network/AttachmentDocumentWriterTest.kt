package com.abyssal.chat.data.network

import java.io.ByteArrayOutputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Test

class AttachmentDocumentWriterTest {
    @Test
    fun explicitSaveWritesAuthenticatedPlaintextBytesWithoutEnvelope() {
        val attachmentBytes = ByteArray(150_000) { index -> (index % 251).toByte() }
        val originalSnapshot = attachmentBytes.copyOf()
        val output = ByteArrayOutputStream()

        AttachmentDocumentWriter.write(attachmentBytes, output)

        assertArrayEquals(originalSnapshot, output.toByteArray())
        assertArrayEquals(originalSnapshot, attachmentBytes)
    }
}

package com.abyssal.chat.data.network

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody
import okio.Buffer
import okio.BufferedSource
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class EncryptedAttachmentServiceTest {
    @Test
    fun serializedAttachmentBoundAccountsForBase64AndRecipientEnvelopes() {
        assertEquals(4L, base64NoPaddingLength(3L))
        assertEquals(2L, base64NoPaddingLength(1L))
        assertTrue(maxSerializedAttachmentBytes("FILE") > 200L * 1024L * 1024L)
        assertTrue(maxSerializedAttachmentBytes("VIDEO") < maxSerializedAttachmentBytes("FILE"))
        assertTrue(maxSerializedAttachmentBytes("IMAGE") < maxSerializedAttachmentBytes("VIDEO"))
    }

    @Test
    fun acceptsEncryptedAttachmentAtConfiguredBound() {
        val body = ByteArray(128) { it.toByte() }
            .toResponseBody("application/octet-stream".toMediaType())

        val result = readBoundedAttachmentBody(body)

        assertArrayEquals(ByteArray(128) { it.toByte() }, result)
    }

    @Test
    fun rejectsBodyWithDeclaredLengthBeyondConfiguredBound() {
        val body = object : ResponseBody() {
            override fun contentType() = "application/octet-stream".toMediaType()
            override fun contentLength() = MAX_ENCRYPTED_ATTACHMENT_BYTES + 1L
            override fun source(): BufferedSource = Buffer().writeByte(1)
        }

        assertNull(readBoundedAttachmentBody(body))
    }

    @Test
    fun rejectsOversizedUploadResponseWithoutReadingItAll() {
        val body = object : ResponseBody() {
            override fun contentType() = "application/json".toMediaType()
            override fun contentLength() = MAX_ATTACHMENT_UPLOAD_RESPONSE_BYTES + 1L
            override fun source(): BufferedSource = Buffer().writeUtf8("{\"accepted\":true}")
        }

        assertNull(readBoundedAttachmentResponse(body))
    }
}

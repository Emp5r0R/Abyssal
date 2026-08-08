package com.abyssal.chat.presentation.viewmodel

import com.abyssal.chat.domain.model.Message
import com.abyssal.chat.domain.model.RecipientIdentity
import com.abyssal.chat.domain.model.IdentityValidationResult
import kotlinx.coroutines.Job
import org.json.JSONObject
import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ChatViewModelPolicyTest {
    @Test
    fun soloForumCanStoreTextLocallyWithoutCryptoRecipients() {
        assertTrue(isLocalOnlyForum("forum_general", emptyList()))
        assertFalse(isLocalOnlyForum("forum_general", listOf(recipient("Bob"))))
        assertFalse(isLocalOnlyForum("dm_bob", emptyList()))
        assertFalse(isLocalOnlyForum("forum_general", null))
    }

    @Test
    fun decryptedAttachmentMustMatchAuthenticatedMessageSize() {
        assertTrue(isDecryptedAttachmentSizeValid(actualBytes = 4L, expectedBytes = 4L, maxBytes = 10L))
        assertFalse(isDecryptedAttachmentSizeValid(actualBytes = 3L, expectedBytes = 4L, maxBytes = 10L))
        assertFalse(isDecryptedAttachmentSizeValid(actualBytes = 0L, expectedBytes = 0L, maxBytes = 10L))
        assertFalse(isDecryptedAttachmentSizeValid(actualBytes = 11L, expectedBytes = 11L, maxBytes = 10L))
    }

    @Test
    fun accountEntryGateRejectsConcurrentAndCanceledResults() {
        val activeJob = Job()
        assertFalse(canStartAccountEntry(activeJob))
        activeJob.cancel()
        assertTrue(canStartAccountEntry(activeJob))

        val valid = IdentityValidationResult(
            accepted = true,
            token = "token",
            publicKey = ByteArray(128),
            prekeyId = "prekey"
        )
        assertTrue(canInstallAccountEntryResult(true, valid))
        assertFalse(canInstallAccountEntryResult(false, valid))
        valid.publicKey?.fill(0)
    }

    @Test
    fun attachmentMetadataMatchesWebWireFieldsWithoutLegacyCryptoId() {
        val key = ByteArray(32) { it.toByte() }
        val message = Message(
            id = "5dbf06b8-fca4-46c4-8f26-5589e7024d94",
            sender = "You",
            receiver = "Bob",
            content = "report.pdf",
            timestampMs = 1L,
            selfDestructDurationSec = 30,
            isMedia = true,
            mediaType = "FILE",
            attachmentId = "123e4567-e89b-12d3-a456-426614174000",
            attachmentCipherVersion = ATTACHMENT_CIPHER_VERSION,
            attachmentKey = key,
            attachmentName = "report.pdf",
            attachmentMimeType = "application/pdf",
            attachmentSizeBytes = 4L
        )

        try {
            val json = attachmentMetadataJson(message, "Alice")

            assertEquals("attachment", json.optString("kind"))
            assertEquals(message.id, json.optString("id"))
            assertEquals(ATTACHMENT_CIPHER_VERSION, json.optInt("attachment_cipher_version"))
            assertTrue(json.optString("attachment_key_b64").matches(Regex("^[A-Za-z0-9_-]{43}$")))
            assertFalse(json.has("attachment_crypto_id"))
        } finally {
            key.fill(0)
        }
    }

    private fun recipient(username: String) = RecipientIdentity(
        username = username,
        publicKey = ByteArray(128),
        prekeyId = "prekey-1"
    )
}

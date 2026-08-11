package com.abyssal.chat.presentation.viewmodel

import com.abyssal.chat.domain.model.Message
import com.abyssal.chat.domain.model.RecipientIdentity
import com.abyssal.chat.domain.model.IdentityValidationResult
import com.abyssal.chat.domain.model.IdentityStateSnapshot
import java.util.concurrent.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
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
    fun calculatorResultCannotOverwriteNewerInputOrCancelledJob() {
        assertTrue(canApplyCalculatorEvaluation(4L, 4L, true))
        assertFalse(canApplyCalculatorEvaluation(3L, 4L, true))
        assertFalse(canApplyCalculatorEvaluation(4L, 4L, false))
    }

    @Test
    fun acknowledgementFailuresAreContainedAndNativeBuffersAreWiped() = runBlocking {
        assertFalse(
            acknowledgeWithEphemeralState(
                snapshot = { throw IllegalStateException("snapshot") },
                signAction = { error("signer must not run") },
                send = { _, _ -> error("transport must not run") }
            )
        )

        val signerState = testIdentityState(1)
        assertFalse(
            acknowledgeWithEphemeralState(
                snapshot = { signerState },
                signAction = { throw IllegalStateException("signer") },
                send = { _, _ -> error("transport must not run") }
            )
        )
        assertIdentityStateWiped(signerState)

        val transportState = testIdentityState(2)
        val transportSignature = ByteArray(ACK_SIGNATURE_BYTES) { 3 }
        assertFalse(
            acknowledgeWithEphemeralState(
                snapshot = { transportState },
                signAction = { transportSignature },
                send = { _, _ -> throw IllegalStateException("transport") }
            )
        )
        assertIdentityStateWiped(transportState)
        assertArrayEquals(ByteArray(ACK_SIGNATURE_BYTES), transportSignature)

        val canceledState = testIdentityState(4)
        var cancellationRethrown = false
        try {
            acknowledgeWithEphemeralState(
                snapshot = { canceledState },
                signAction = { throw CancellationException("cancelled") },
                send = { _, _ -> true }
            )
        } catch (_: CancellationException) {
            cancellationRethrown = true
        }
        assertTrue(cancellationRethrown)
        assertIdentityStateWiped(canceledState)

        val sendCanceledState = testIdentityState(5)
        val sendCanceledSignature = ByteArray(ACK_SIGNATURE_BYTES) { 6 }
        cancellationRethrown = false
        try {
            acknowledgeWithEphemeralState(
                snapshot = { sendCanceledState },
                signAction = { sendCanceledSignature },
                send = { _, _ -> throw CancellationException("send cancelled") }
            )
        } catch (_: CancellationException) {
            cancellationRethrown = true
        }
        assertTrue(cancellationRethrown)
        assertIdentityStateWiped(sendCanceledState)
        assertArrayEquals(ByteArray(ACK_SIGNATURE_BYTES), sendCanceledSignature)
    }

    @Test
    fun externalPickerCallbacksAreGenerationScopedAndExpire() {
        val gate = ExternalSystemUiTokenGate()
        val first = gate.begin()
        val second = gate.begin()

        assertFalse(gate.end(first))
        assertTrue(gate.activeToken() == second)
        assertTrue(gate.end(second))
        assertFalse(gate.end(second))

        val expired = gate.begin()
        assertTrue(gate.expire(expired))
        assertFalse(gate.end(expired))
    }

    @Test
    fun uploadedAttachmentIsDeletedUntilMetadataIsAccepted() {
        assertTrue(shouldDeleteUploadedAttachment("123e4567-e89b-12d3-a456-426614174000", false))
        assertFalse(shouldDeleteUploadedAttachment("123e4567-e89b-12d3-a456-426614174000", true))
        assertFalse(shouldDeleteUploadedAttachment(null, false))
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

    private fun testIdentityState(seed: Int) = IdentityStateSnapshot(
        revision = seed.toULong(),
        envelope = ByteArray(4) { seed.toByte() },
        identityPublicKey = ByteArray(4) { (seed + 1).toByte() },
        prekeyId = "prekey-$seed",
        stateSignature = ByteArray(4) { (seed + 2).toByte() }
    )

    private fun assertIdentityStateWiped(state: IdentityStateSnapshot) {
        assertArrayEquals(ByteArray(state.envelope.size), state.envelope)
        assertArrayEquals(ByteArray(state.identityPublicKey.size), state.identityPublicKey)
        assertArrayEquals(ByteArray(state.stateSignature.size), state.stateSignature)
    }
}

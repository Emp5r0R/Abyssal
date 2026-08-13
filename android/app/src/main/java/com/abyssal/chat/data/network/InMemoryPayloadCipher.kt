package com.abyssal.chat.data.network

import com.abyssal.chat.domain.model.EncryptedTransportPayload
import com.abyssal.chat.domain.model.IncomingTransportPayload
import com.abyssal.chat.domain.model.IdentityStateSnapshot
import com.abyssal.chat.domain.model.RecipientEnvelope
import com.abyssal.chat.domain.model.RecipientIdentity
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.Locale
import org.json.JSONArray
import org.json.JSONObject
import uniffi.abyssal_core.E2eeSession
import uniffi.abyssal_core.RecipientPublicKey

internal class FatalPayloadCipherException(cause: Throwable) :
    IllegalStateException("Identity unavailable", cause)

class InMemoryPayloadCipher {
    private var session: E2eeSession? = null
    /** State visible after the last committed encrypt/decrypt operation. */
    private var committedState: IdentityStateSnapshot? = null
    /** State emitted by the one outbound operation awaiting relay admission. */
    private var pendingState: IdentityStateSnapshot? = null
    /** Snapshot to restore if that outbound operation is explicitly rejected. */
    private var pendingPreviousState: IdentityStateSnapshot? = null

    data class DecryptionResult(
        val plaintext: ByteArray
    )

    @Synchronized
    fun createIdentity(exportKey: ByteArray, context: ByteArray): IdentityMaterial {
        clear()
        val next = E2eeSession.create(exportKey)
        return try {
            session = next
            IdentityMaterial(
                publicKey = next.publicKey(),
                prekeyId = next.prekeyId(),
                envelope = next.sealIdentity(exportKey, context)
            )
        } catch (error: Exception) {
            next.close()
            throw error
        }
    }

    @Synchronized
    fun recoverIdentity(
        exportKey: ByteArray,
        context: ByteArray,
        envelope: ByteArray,
        expectedPublicKey: ByteArray
    ) {
        clear()
        session = E2eeSession.recover(exportKey, context, envelope, expectedPublicKey)
    }

    @Synchronized
    fun publicKey(): ByteArray = requireSession().publicKey()

    @Synchronized
    fun prekeyId(): String = requireSession().prekeyId()

    @Synchronized
    fun stateSnapshot(): IdentityStateSnapshot? = (pendingState ?: committedState)?.let {
        IdentityStateSnapshot(
            revision = it.revision,
            envelope = it.envelope.clone(),
            identityPublicKey = it.identityPublicKey.clone(),
            prekeyId = it.prekeyId,
            stateSignature = it.stateSignature.clone()
        )
    }

    @Synchronized
    fun encrypt(
        chatId: String,
        messageId: String,
        senderUsername: String,
        plainBytes: ByteArray,
        recipients: List<RecipientIdentity>
    ): EncryptedTransportPayload {
        check(pendingState == null) { "Outbound operation already pending" }
        wipeState(pendingPreviousState)
        pendingPreviousState = copyState(committedState)
        val uniqueRecipients = recipients
            .distinctBy { it.username.lowercase(Locale.ROOT) }
            .map { RecipientPublicKey(it.username, it.publicKey, it.prekeyId) }
        var encrypted: uniffi.abyssal_core.E2eePayload? = null
        return try {
            encrypted = requireSession().encrypt(
                chatId,
                messageId,
                senderUsername,
                plainBytes,
                uniqueRecipients
            )
            val native = requireNotNull(encrypted)
            pendingState = state(
                native.stateRevision,
                native.identityEnvelope,
                native.identityPublic,
                native.prekeyId,
                native.stateSignature
            )
            EncryptedTransportPayload(
                version = native.version.toInt(),
                messageId = native.messageId,
                nonce = native.nonce,
                ciphertext = native.ciphertext,
                envelopes = native.envelopes.map {
                    RecipientEnvelope(it.username, it.wrappedKey, it.prekeyId, it.isPrekey, it.signature)
                },
                stateRevision = native.stateRevision,
                identityEnvelope = native.identityEnvelope,
                identityPublicKey = native.identityPublic,
                prekeyId = native.prekeyId,
                stateSignature = native.stateSignature
            )
        } catch (error: Throwable) {
            val native = encrypted
            var rollbackFailure: Throwable? = null
            if (native != null) {
                try {
                    requireSession().rollbackOutbound(native.messageId, native.stateRevision)
                } catch (rollbackError: Throwable) {
                    rollbackFailure = rollbackError
                }
                wipeNativePayload(native)
            }
            wipeState(pendingState)
            pendingState = null
            wipeState(pendingPreviousState)
            pendingPreviousState = null
            if (rollbackFailure != null) {
                clear()
                throw FatalPayloadCipherException(requireNotNull(rollbackFailure))
            }
            throw error
        }
    }

    @Synchronized
    fun decrypt(payload: IncomingTransportPayload, recipientUsername: String): DecryptionResult {
        check(pendingState == null) { "Outbound operation already pending" }
        val decrypted = requireSession().decrypt(
            payload.chatId,
            payload.messageId,
            payload.senderUsername,
            payload.senderPublicKey,
            payload.version.toUInt(),
            payload.identityPublicKey,
            payload.nonce,
            payload.ciphertext,
            payload.signature,
            payload.wrappedKey,
            payload.prekeyId,
            payload.isPrekey,
            recipientUsername
        )
        var result: DecryptionResult? = null
        return try {
            try {
                replaceCommittedState(
                    decrypted.stateRevision,
                    decrypted.identityEnvelope,
                    decrypted.identityPublic,
                    decrypted.prekeyId,
                    decrypted.stateSignature
                )
            } catch (error: Throwable) {
                // Native decryption has already advanced the ratchet. If the
                // JVM wrapper cannot install that state, retaining this
                // session would make the next operation use an unknown state.
                // Clear all native/session material and make the failure
                // distinguishable from an ordinary authentication rejection.
                clearAfterFatalStateInstall(error)
            }
            result = DecryptionResult(plaintext = decrypted.plaintext)
            result
        } finally {
            if (result == null) decrypted.plaintext.fill(0)
            decrypted.identityEnvelope.fill(0)
            decrypted.identityPublic.fill(0)
            decrypted.stateSignature.fill(0)
        }
    }

    @Synchronized
    fun signAcknowledgement(
        chatId: String,
        messageId: String,
        senderUsername: String,
        usedPrekeyId: String
    ): ByteArray {
        val signature = requireSession().signAcknowledgement(
            chatId,
            messageId,
            senderUsername,
            usedPrekeyId
        )
        require(signature.size == ACK_SIGNATURE_BYTES)
        return signature
    }

    @Synchronized
    fun signRegistrationIdentityProof(
        nodeId: String,
        handshakeId: String,
        challenge: ByteArray,
        registrationUpload: ByteArray,
        identityPublic: ByteArray,
        prekeyId: String,
        identityEnvelope: ByteArray
    ): ByteArray {
        val signature = requireSession().signRegistrationIdentityProof(
            nodeId,
            handshakeId,
            challenge,
            registrationUpload,
            identityPublic,
            prekeyId,
            identityEnvelope
        )
        require(signature.size == ACK_SIGNATURE_BYTES)
        return signature
    }

    fun serialize(payload: EncryptedTransportPayload): ByteArray {
        require(payload.version == PROTOCOL_VERSION)
        require(payload.stateSignature.size == STATE_SIGNATURE_BYTES)
        val json = JSONObject()
            .put("version", payload.version)
            .put("message_id", payload.messageId)
            .put("identity_public_b64", encode(payload.identityPublicKey))
            .put("state_signature_b64", encode(payload.stateSignature))
            .put("nonce_b64", encode(payload.nonce))
            .put("ciphertext_b64", encode(payload.ciphertext))
            .put("envelopes", JSONArray().apply {
                payload.envelopes.forEach { envelope ->
                    put(
                        JSONObject()
                            .put("recipient_username", envelope.recipientUsername)
                            .put("wrapped_key_b64", encode(envelope.wrappedKey))
                            .put("prekey_id", envelope.prekeyId)
                            .put("is_prekey", envelope.isPrekey)
                            .put("signature_b64", encode(envelope.signature))
                    )
                }
            })
        return json.toString().toByteArray(StandardCharsets.UTF_8)
    }

    fun deserializeForRecipient(
        chatId: String,
        bytes: ByteArray,
        senderUsername: String,
        senderPublicKey: ByteArray,
        recipientUsername: String
    ): IncomingTransportPayload {
        require(bytes.size <= MAX_METADATA_SERIALIZED_BYTES)
        val json = JSONObject(String(bytes, StandardCharsets.UTF_8))
        require(json.optInt("version") == PROTOCOL_VERSION)
        val messageId = json.getString("message_id")
            .takeIf { isSafeIdentifier(it) }
            ?: throw IllegalArgumentException("Invalid message id")
        val envelopes = json.getJSONArray("envelopes")
        require(envelopes.length() in 1..MAX_RECIPIENT_ENVELOPES)
        val envelope = (0 until envelopes.length())
            .asSequence()
            .map { envelopes.getJSONObject(it) }
            .firstOrNull { it.getString("recipient_username") == recipientUsername }
            ?: throw IllegalArgumentException("Recipient unavailable")
        var nonce: ByteArray? = null
        var ciphertext: ByteArray? = null
        var signature: ByteArray? = null
        var wrappedKey: ByteArray? = null
        var senderKey: ByteArray? = null
        var identityPublicKey: ByteArray? = null
        var ownershipTransferred = false
        return try {
            val decodedNonce = decode(json.getString("nonce_b64"))
            val decodedCiphertext = decode(json.getString("ciphertext_b64"))
            val decodedSignature = decode(envelope.getString("signature_b64"))
            val decodedWrappedKey = envelope.getString("wrapped_key_b64").let(::decode)
            val decodedSenderKey = senderPublicKey.copyOf()
            val decodedIdentityPublicKey = decode(json.getString("identity_public_b64"))
            nonce = decodedNonce
            ciphertext = decodedCiphertext
            signature = decodedSignature
            wrappedKey = decodedWrappedKey
            senderKey = decodedSenderKey
            identityPublicKey = decodedIdentityPublicKey
            require(decodedNonce.size == MESSAGE_NONCE_BYTES)
            require(decodedCiphertext.isNotEmpty() && decodedCiphertext.size <= MAX_METADATA_CIPHERTEXT_BYTES)
            require(decodedSignature.size == MESSAGE_SIGNATURE_BYTES)
            require(decodedWrappedKey.isNotEmpty() && decodedWrappedKey.size <= MAX_WRAPPED_KEY_BYTES)
            require(decodedSenderKey.size == IDENTITY_PUBLIC_KEY_BYTES)
            require(decodedIdentityPublicKey.size == IDENTITY_PUBLIC_KEY_BYTES)
            val prekeyId = envelope.optString("prekey_id")
            val isPrekey = envelope.optBoolean("is_prekey", false)
            require(prekeyId.isEmpty() == !isPrekey)
            if (prekeyId.isNotEmpty()) require(PREKEY_ID_REGEX.matches(prekeyId))
            val payload = IncomingTransportPayload(
                chatId = chatId,
                messageId = messageId,
                version = PROTOCOL_VERSION,
                identityPublicKey = decodedIdentityPublicKey,
                nonce = decodedNonce,
                ciphertext = decodedCiphertext,
                signature = decodedSignature,
                wrappedKey = decodedWrappedKey,
                senderUsername = senderUsername,
                senderPublicKey = decodedSenderKey,
                prekeyId = prekeyId,
                isPrekey = isPrekey
            )
            ownershipTransferred = true
            payload
        } finally {
            if (!ownershipTransferred) {
                nonce?.fill(0)
                ciphertext?.fill(0)
                signature?.fill(0)
                wrappedKey?.fill(0)
                senderKey?.fill(0)
                identityPublicKey?.fill(0)
            }
        }
    }

    @Synchronized
    fun commitOutbound(messageId: String, revision: ULong) {
        val staged = pendingState ?: throw IllegalStateException("Outbound operation unavailable")
        require(staged.revision == revision) { "Outbound operation unavailable" }
        requireSession().commitOutbound(messageId, revision)
        wipeState(committedState)
        committedState = staged
        pendingState = null
        wipeState(pendingPreviousState)
        pendingPreviousState = null
    }

    @Synchronized
    fun rollbackOutbound(messageId: String, revision: ULong) {
        val staged = pendingState ?: throw IllegalStateException("Outbound operation unavailable")
        require(staged.revision == revision) { "Outbound operation unavailable" }
        requireSession().rollbackOutbound(messageId, revision)
        wipeState(staged)
        pendingState = null
        wipeState(committedState)
        committedState = pendingPreviousState
        pendingPreviousState = null
    }

    @Synchronized
    fun clear() {
        wipeState(committedState)
        wipeState(pendingState)
        wipeState(pendingPreviousState)
        committedState = null
        pendingState = null
        pendingPreviousState = null
        val activeSession = session
        session = null
        // Detach the session before closing it so even a native close failure
        // cannot leave this wrapper looking usable after a fatal transition.
        activeSession?.close()
    }

    private fun requireSession(): E2eeSession =
        session ?: throw IllegalStateException("Identity unavailable")

    private fun clearAfterFatalStateInstall(error: Throwable): Nothing {
        runCatching { clear() }
            .onFailure(error::addSuppressed)
        throw FatalPayloadCipherException(error)
    }

    private fun replaceCommittedState(
        revision: ULong,
        envelope: ByteArray,
        identityPublicKey: ByteArray,
        prekeyId: String,
        stateSignature: ByteArray
    ) {
        require(stateSignature.size == STATE_SIGNATURE_BYTES)
        wipeState(committedState)
        committedState = state(
            revision = revision,
            envelope = envelope.clone(),
            identityPublicKey = identityPublicKey.clone(),
            prekeyId = prekeyId,
            stateSignature = stateSignature.clone()
        )
    }

    private fun state(
        revision: ULong,
        envelope: ByteArray,
        identityPublicKey: ByteArray,
        prekeyId: String,
        stateSignature: ByteArray
    ): IdentityStateSnapshot {
        require(stateSignature.size == STATE_SIGNATURE_BYTES)
        return IdentityStateSnapshot(
            revision = revision,
            envelope = envelope.clone(),
            identityPublicKey = identityPublicKey.clone(),
            prekeyId = prekeyId,
            stateSignature = stateSignature.clone()
        )
    }

    private fun copyState(value: IdentityStateSnapshot?): IdentityStateSnapshot? = value?.let {
        IdentityStateSnapshot(
            revision = it.revision,
            envelope = it.envelope.clone(),
            identityPublicKey = it.identityPublicKey.clone(),
            prekeyId = it.prekeyId,
            stateSignature = it.stateSignature.clone()
        )
    }

    private fun wipeState(value: IdentityStateSnapshot?) {
        value?.envelope?.fill(0)
        value?.identityPublicKey?.fill(0)
        value?.stateSignature?.fill(0)
    }

    private fun wipeNativePayload(value: uniffi.abyssal_core.E2eePayload) {
        value.nonce.fill(0)
        value.ciphertext.fill(0)
        value.identityEnvelope.fill(0)
        value.identityPublic.fill(0)
        value.stateSignature.fill(0)
        value.envelopes.forEach {
            it.wrappedKey.fill(0)
            it.signature.fill(0)
        }
    }

    data class IdentityMaterial(
        val publicKey: ByteArray,
        val prekeyId: String,
        val envelope: ByteArray
    )

    private companion object {
        const val PROTOCOL_VERSION = 8
        const val MESSAGE_NONCE_BYTES = 12
        const val MESSAGE_SIGNATURE_BYTES = 64
        const val STATE_SIGNATURE_BYTES = 64
        const val ACK_SIGNATURE_BYTES = 64
        const val IDENTITY_PUBLIC_KEY_BYTES = 128
        const val MAX_WRAPPED_KEY_BYTES = 4096
        const val MAX_METADATA_SERIALIZED_BYTES = 1 * 1024 * 1024
        const val MAX_METADATA_CIPHERTEXT_BYTES = 1_048_848
        const val MAX_RECIPIENT_ENVELOPES = 256
        val PREKEY_ID_REGEX = Regex("^[A-Za-z0-9_-]{1,32}$")

        fun isSafeIdentifier(value: String): Boolean =
            value.length in 1..128 && value.all { it.isLetterOrDigit() || it == '_' || it == '-' }

        fun encode(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

        fun decode(value: String): ByteArray = Base64.getUrlDecoder().decode(value)
    }
}

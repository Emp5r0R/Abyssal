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
            val publicKey = next.publicKey()
            try {
                require(publicKey.size == IDENTITY_PUBLIC_KEY_BYTES)
                require(PREKEY_ID_REGEX.matches(next.prekeyId()))
            } finally {
                publicKey.fill(0)
            }
            IdentityMaterial(
                publicKey = next.publicKey(),
                prekeyId = next.prekeyId(),
                envelope = next.sealIdentity(exportKey, context)
            )
        } catch (error: Exception) {
            session = null
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
        require(expectedPublicKey.size == IDENTITY_PUBLIC_KEY_BYTES)
        val recovered = E2eeSession.recover(exportKey, context, envelope, expectedPublicKey)
        try {
            val actual = recovered.publicKey()
            try {
                require(actual.size == IDENTITY_PUBLIC_KEY_BYTES)
                require(actual.contentEquals(expectedPublicKey))
                require(PREKEY_ID_REGEX.matches(recovered.prekeyId()))
            } finally {
                actual.fill(0)
            }
            session = recovered
        } catch (error: Exception) {
            recovered.close()
            throw error
        }
    }

    @Synchronized
    fun publicKey(): ByteArray {
        val publicKey = requireSession().publicKey()
        if (publicKey.size != IDENTITY_PUBLIC_KEY_BYTES) {
            publicKey.fill(0)
            throw IllegalStateException("Identity unavailable")
        }
        return publicKey
    }

    @Synchronized
    fun prekeyId(): String = requireSession().prekeyId().also {
        require(PREKEY_ID_REGEX.matches(it))
    }

    /**
     * Native ratchet policy decides whether this recipient needs a fresh
     * authenticated lease.  This must run before [encrypt] stages any state.
     */
    @Synchronized
    fun requiresPrekey(peerUsername: String): Boolean {
        require(isSafeUsername(peerUsername))
        return requireSession().requiresPrekey(peerUsername)
    }

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
        require(isSafeIdentifier(chatId) && isSafeIdentifier(messageId) && isSafeUsername(senderUsername))
        val uniqueRecipients = recipients
            .distinctBy { it.username.lowercase(Locale.ROOT) }
            .map {
                require(isSafeUsername(it.username))
                require(it.publicKey.size == IDENTITY_PUBLIC_KEY_BYTES)
                require(PREKEY_ID_REGEX.matches(it.prekeyId))
                RecipientPublicKey(it.username, it.publicKey, it.prekeyId)
            }
        require(uniqueRecipients.isNotEmpty())
        wipeState(pendingPreviousState)
        pendingPreviousState = copyState(committedState)
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
        require(
            isSafeIdentifier(payload.chatId) &&
                isSafeIdentifier(payload.messageId) &&
                isSafeUsername(payload.senderUsername) &&
                isSafeUsername(recipientUsername) &&
                payload.version == PROTOCOL_VERSION &&
                payload.senderPublicKey.size == IDENTITY_PUBLIC_KEY_BYTES &&
                payload.identityPublicKey.size == IDENTITY_PUBLIC_KEY_BYTES &&
                payload.nonce.size == MESSAGE_NONCE_BYTES &&
                payload.ciphertext.isNotEmpty() &&
                payload.ciphertext.size <= MAX_METADATA_CIPHERTEXT_BYTES &&
                payload.signature.size == MESSAGE_SIGNATURE_BYTES &&
                payload.wrappedKey.isNotEmpty() &&
                payload.wrappedKey.size <= MAX_WRAPPED_KEY_BYTES &&
                payload.prekeyId.isEmpty() == !payload.isPrekey &&
                (payload.prekeyId.isEmpty() || PREKEY_ID_REGEX.matches(payload.prekeyId))
        )
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
        require(
            isSafeIdentifier(chatId) &&
                isSafeIdentifier(messageId) &&
                isSafeUsername(senderUsername) &&
                (usedPrekeyId.isEmpty() || PREKEY_ID_REGEX.matches(usedPrekeyId))
        )
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
        require(
            payload.version == PROTOCOL_VERSION &&
                isSafeIdentifier(payload.messageId) &&
                payload.nonce.size == MESSAGE_NONCE_BYTES &&
                payload.ciphertext.isNotEmpty() &&
                payload.ciphertext.size <= MAX_METADATA_CIPHERTEXT_BYTES &&
                payload.identityEnvelope.isNotEmpty() &&
                payload.identityEnvelope.size <= MAX_IDENTITY_ENVELOPE_BYTES &&
                payload.envelopes.isNotEmpty() &&
                payload.envelopes.size <= MAX_RECIPIENT_ENVELOPES &&
                payload.envelopes.all { envelope ->
                    isSafeUsername(envelope.recipientUsername) &&
                        envelope.wrappedKey.isNotEmpty() &&
                        envelope.wrappedKey.size <= MAX_WRAPPED_KEY_BYTES &&
                        envelope.signature.size == MESSAGE_SIGNATURE_BYTES &&
                        envelope.prekeyId.isEmpty() == !envelope.isPrekey &&
                        (envelope.prekeyId.isEmpty() || PREKEY_ID_REGEX.matches(envelope.prekeyId))
                }
        )
        require(payload.stateSignature.size == STATE_SIGNATURE_BYTES)
        require(payload.identityPublicKey.size == IDENTITY_PUBLIC_KEY_BYTES)
        require(PREKEY_ID_REGEX.matches(payload.prekeyId))
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
        require(
            isSafeIdentifier(chatId) &&
                isSafeUsername(senderUsername) &&
                isSafeUsername(recipientUsername) &&
                senderPublicKey.size == IDENTITY_PUBLIC_KEY_BYTES
        )
        val json = JSONObject(String(bytes, StandardCharsets.UTF_8))
        require(json.keys().asSequence().toSet() == SERIALIZED_PAYLOAD_KEYS)
        require((json.get("version") as? Int) == PROTOCOL_VERSION)
        val messageId = json.getString("message_id")
            .takeIf { isSafeIdentifier(it) }
            ?: throw IllegalArgumentException("Invalid message id")
        val envelopes = json.getJSONArray("envelopes")
        require(envelopes.length() in 1..MAX_RECIPIENT_ENVELOPES)
        val parsedEnvelopes = (0 until envelopes.length())
            .map { envelopes.getJSONObject(it).also { value ->
                require(value.keys().asSequence().toSet() == SERIALIZED_ENVELOPE_KEYS)
                require(isSafeUsername(value.getString("recipient_username")))
            } }
        val envelope = parsedEnvelopes
            .asSequence()
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
            val decodedNonce = decodeCanonical(json.getString("nonce_b64"))
            nonce = decodedNonce
            val decodedCiphertext = decodeCanonical(json.getString("ciphertext_b64"))
            ciphertext = decodedCiphertext
            val decodedSignature = decodeCanonical(envelope.getString("signature_b64"))
            signature = decodedSignature
            val decodedWrappedKey = decodeCanonical(envelope.getString("wrapped_key_b64"))
            wrappedKey = decodedWrappedKey
            val decodedSenderKey = senderPublicKey.copyOf()
            senderKey = decodedSenderKey
            val decodedIdentityPublicKey = decodeCanonical(json.getString("identity_public_b64"))
            identityPublicKey = decodedIdentityPublicKey
            require(decodedNonce.size == MESSAGE_NONCE_BYTES)
            require(decodedCiphertext.isNotEmpty() && decodedCiphertext.size <= MAX_METADATA_CIPHERTEXT_BYTES)
            require(decodedSignature.size == MESSAGE_SIGNATURE_BYTES)
            require(decodedWrappedKey.isNotEmpty() && decodedWrappedKey.size <= MAX_WRAPPED_KEY_BYTES)
            require(decodedSenderKey.size == IDENTITY_PUBLIC_KEY_BYTES)
            require(decodedIdentityPublicKey.size == IDENTITY_PUBLIC_KEY_BYTES)
            val prekeyId = envelope.get("prekey_id") as? String
                ?: throw IllegalArgumentException("Invalid prekey id")
            val isPrekey = envelope.get("is_prekey") as? Boolean
                ?: throw IllegalArgumentException("Invalid prekey flag")
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
        require(identityPublicKey.size == IDENTITY_PUBLIC_KEY_BYTES)
        require(PREKEY_ID_REGEX.matches(prekeyId))
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
        require(identityPublicKey.size == IDENTITY_PUBLIC_KEY_BYTES)
        require(PREKEY_ID_REGEX.matches(prekeyId))
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
        const val PROTOCOL_VERSION = 9
        const val MESSAGE_NONCE_BYTES = 12
        const val MESSAGE_SIGNATURE_BYTES = 64
        const val STATE_SIGNATURE_BYTES = 64
        const val ACK_SIGNATURE_BYTES = 64
        const val IDENTITY_PUBLIC_KEY_BYTES = 608
        const val MAX_WRAPPED_KEY_BYTES = 4096
        const val MAX_METADATA_SERIALIZED_BYTES = 1 * 1024 * 1024
        const val MAX_METADATA_CIPHERTEXT_BYTES = 1_048_848
        const val MAX_IDENTITY_ENVELOPE_BYTES = 512 * 1024
        const val MAX_RECIPIENT_ENVELOPES = 256
        val PREKEY_ID_REGEX = Regex("^[A-Za-z0-9_-]{1,32}$")
        val SERIALIZED_PAYLOAD_KEYS = setOf(
            "version", "message_id", "identity_public_b64", "state_signature_b64",
            "nonce_b64", "ciphertext_b64", "envelopes"
        )
        val SERIALIZED_ENVELOPE_KEYS = setOf(
            "recipient_username", "wrapped_key_b64", "prekey_id", "is_prekey", "signature_b64"
        )

        fun isSafeIdentifier(value: String): Boolean =
            value.length in 1..128 && value.all { it.isLetterOrDigit() || it == '_' || it == '-' }

        fun isSafeUsername(value: String): Boolean =
            value.length in 1..80 && value.all { it.isLetterOrDigit() || it == '_' || it == '-' }

        fun encode(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

        fun decode(value: String): ByteArray = Base64.getUrlDecoder().decode(value)

        fun decodeCanonical(value: String): ByteArray {
            val decoded = decode(value)
            if (Base64.getUrlEncoder().withoutPadding().encodeToString(decoded) != value) {
                decoded.fill(0)
                throw IllegalArgumentException("Non-canonical base64")
            }
            return decoded
        }
    }
}

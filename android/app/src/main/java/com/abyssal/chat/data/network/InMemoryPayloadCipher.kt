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

class InMemoryPayloadCipher {
    private var session: E2eeSession? = null
    private var pendingState: IdentityStateSnapshot? = null

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
    fun stateSnapshot(): IdentityStateSnapshot? = pendingState?.let {
        IdentityStateSnapshot(
            revision = it.revision,
            envelope = it.envelope.clone(),
            identityPublicKey = it.identityPublicKey.clone(),
            prekeyId = it.prekeyId
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
        val uniqueRecipients = recipients
            .distinctBy { it.username.lowercase(Locale.ROOT) }
            .map { RecipientPublicKey(it.username, it.publicKey, it.prekeyId) }
        val encrypted = requireSession().encrypt(
            chatId,
            messageId,
            senderUsername,
            plainBytes,
            uniqueRecipients
        )
        rememberState(
            encrypted.stateRevision,
            encrypted.identityEnvelope,
            encrypted.identityPublic,
            encrypted.prekeyId
        )
        return EncryptedTransportPayload(
            version = encrypted.version.toInt(),
            messageId = encrypted.messageId,
            nonce = encrypted.nonce,
            ciphertext = encrypted.ciphertext,
            envelopes = encrypted.envelopes.map {
                RecipientEnvelope(it.username, it.wrappedKey, it.prekeyId, it.isPrekey, it.signature)
            },
            stateRevision = encrypted.stateRevision,
            identityEnvelope = encrypted.identityEnvelope,
            identityPublicKey = encrypted.identityPublic,
            prekeyId = encrypted.prekeyId
        )
    }

    @Synchronized
    fun decrypt(payload: IncomingTransportPayload, recipientUsername: String): ByteArray {
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
        rememberState(
            decrypted.stateRevision,
            decrypted.identityEnvelope,
            decrypted.identityPublic,
            decrypted.prekeyId
        )
        return try {
            decrypted.plaintext
        } finally {
            decrypted.identityEnvelope.fill(0)
            decrypted.identityPublic.fill(0)
        }
    }

    fun serialize(payload: EncryptedTransportPayload): ByteArray {
        val json = JSONObject()
            .put("version", payload.version)
            .put("message_id", payload.messageId)
            .put("identity_public_b64", encode(payload.identityPublicKey))
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
    fun clear() {
        pendingState?.envelope?.fill(0)
        pendingState?.identityPublicKey?.fill(0)
        pendingState = null
        session?.close()
        session = null
    }

    private fun requireSession(): E2eeSession =
        session ?: throw IllegalStateException("Identity unavailable")

    private fun rememberState(
        revision: ULong,
        envelope: ByteArray,
        identityPublicKey: ByteArray,
        prekeyId: String
    ) {
        pendingState?.envelope?.fill(0)
        pendingState?.identityPublicKey?.fill(0)
        pendingState = IdentityStateSnapshot(
            revision = revision,
            envelope = envelope.clone(),
            identityPublicKey = identityPublicKey.clone(),
            prekeyId = prekeyId
        )
    }

    data class IdentityMaterial(
        val publicKey: ByteArray,
        val prekeyId: String,
        val envelope: ByteArray
    )

    private companion object {
        const val PROTOCOL_VERSION = 6
        const val MESSAGE_NONCE_BYTES = 12
        const val MESSAGE_SIGNATURE_BYTES = 64
        const val IDENTITY_PUBLIC_KEY_BYTES = 128
        const val MAX_WRAPPED_KEY_BYTES = 4096
        const val MAX_METADATA_SERIALIZED_BYTES = 1 * 1024 * 1024
        const val MAX_METADATA_CIPHERTEXT_BYTES = 1 * 1024 * 1024
        const val MAX_RECIPIENT_ENVELOPES = 256
        val PREKEY_ID_REGEX = Regex("^[A-Za-z0-9_-]{1,32}$")

        fun isSafeIdentifier(value: String): Boolean =
            value.length in 1..128 && value.all { it.isLetterOrDigit() || it == '_' || it == '-' }

        fun encode(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

        fun decode(value: String): ByteArray = Base64.getUrlDecoder().decode(value)
    }
}

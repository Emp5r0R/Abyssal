package com.abyssal.chat.data.network

import com.abyssal.chat.domain.model.EncryptedTransportPayload
import com.abyssal.chat.domain.model.IncomingTransportPayload
import com.abyssal.chat.domain.model.IdentityStateSnapshot
import com.abyssal.chat.domain.model.RecipientEnvelope
import com.abyssal.chat.domain.model.RecipientIdentity
import java.nio.charset.StandardCharsets
import java.util.Base64
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
            .distinctBy { it.username.lowercase() }
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
            signature = encrypted.signature,
            envelopes = encrypted.envelopes.map {
                RecipientEnvelope(it.username, it.wrappedKey, it.prekeyId, it.isPrekey)
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
        decrypted.identityEnvelope.fill(0)
        return decrypted.plaintext
    }

    fun serialize(payload: EncryptedTransportPayload): ByteArray {
        val json = JSONObject()
            .put("version", payload.version)
            .put("message_id", payload.messageId)
            .put("nonce_b64", encode(payload.nonce))
            .put("ciphertext_b64", encode(payload.ciphertext))
            .put("signature_b64", encode(payload.signature))
            .put("envelopes", JSONArray().apply {
                payload.envelopes.forEach { envelope ->
                    put(
                        JSONObject()
                            .put("recipient_username", envelope.recipientUsername)
                            .put("wrapped_key_b64", encode(envelope.wrappedKey))
                            .put("prekey_id", envelope.prekeyId)
                            .put("is_prekey", envelope.isPrekey)
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
        val json = JSONObject(String(bytes, StandardCharsets.UTF_8))
        require(json.optInt("version") == PROTOCOL_VERSION)
        val envelopes = json.getJSONArray("envelopes")
        val envelope = (0 until envelopes.length())
            .asSequence()
            .map { envelopes.getJSONObject(it) }
            .firstOrNull { it.getString("recipient_username") == recipientUsername }
            ?: throw IllegalArgumentException("Recipient unavailable")
        val wrappedKey = envelope.getString("wrapped_key_b64").let(::decode)
        return IncomingTransportPayload(
            chatId = chatId,
            messageId = json.getString("message_id"),
            nonce = decode(json.getString("nonce_b64")),
            ciphertext = decode(json.getString("ciphertext_b64")),
            signature = decode(json.getString("signature_b64")),
            wrappedKey = wrappedKey,
            senderUsername = senderUsername,
            senderPublicKey = senderPublicKey,
            prekeyId = envelope.optString("prekey_id"),
            isPrekey = envelope.optBoolean("is_prekey", false)
        )
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
        const val PROTOCOL_VERSION = 5
        fun encode(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

        fun decode(value: String): ByteArray = Base64.getUrlDecoder().decode(value)
    }
}

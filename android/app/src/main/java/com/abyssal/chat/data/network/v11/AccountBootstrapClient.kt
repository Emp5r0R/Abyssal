package com.abyssal.chat.data.network.v11

import com.abyssal.chat.data.network.InMemoryPayloadCipher
import com.abyssal.chat.domain.model.TransportKeys
import java.nio.ByteBuffer
import java.util.UUID
import uniffi.abyssal_core.AccountBootstrapExchange
import uniffi.abyssal_core.AccountBootstrapRegistrationFinishInput
import uniffi.abyssal_core.AccountBootstrapResponse
import uniffi.abyssal_core.OpaqueClientStart
import uniffi.abyssal_core.OpaqueLoginFinish
import uniffi.abyssal_core.OpaqueRegistrationFinish
import uniffi.abyssal_core.opaqueClientFinishLogin
import uniffi.abyssal_core.opaqueClientFinishRegistration
import uniffi.abyssal_core.opaqueClientStart

/** OPAQUE client steps, injectable so the sign-in flow can be tested without a relay. */
internal interface OpaqueClient {
    fun start(password: ByteArray): OpaqueClientStart
    fun finishRegistration(password: ByteArray, state: ByteArray, response: ByteArray): OpaqueRegistrationFinish
    fun finishLogin(password: ByteArray, state: ByteArray, response: ByteArray): OpaqueLoginFinish
}

internal object UniffiOpaqueClient : OpaqueClient {
    override fun start(password: ByteArray) = opaqueClientStart(password)
    override fun finishRegistration(password: ByteArray, state: ByteArray, response: ByteArray) =
        opaqueClientFinishRegistration(password, state, response)
    override fun finishLogin(password: ByteArray, state: ByteArray, response: ByteArray) =
        opaqueClientFinishLogin(password, state, response)
}

/** One sealed bootstrap request; it keeps its exact bytes for a retry until a reply opens. */
internal interface BootstrapExchange : AutoCloseable {
    fun requestBytes(): ByteArray
    fun openResponse(reply: ByteArray): AccountBootstrapResponse
}

internal interface BootstrapExchanges {
    fun start(
        nodePublicKey: ByteArray,
        bootstrapPublicKey: ByteArray,
        capability: ByteArray,
        registrationRequest: ByteArray,
        credentialRequest: ByteArray
    ): BootstrapExchange

    fun finishRegistration(
        nodePublicKey: ByteArray,
        bootstrapPublicKey: ByteArray,
        input: AccountBootstrapRegistrationFinishInput
    ): BootstrapExchange

    fun finishLogin(
        nodePublicKey: ByteArray,
        bootstrapPublicKey: ByteArray,
        handshakeId: ByteArray,
        credentialFinalization: ByteArray
    ): BootstrapExchange
}

internal object UniffiBootstrapExchanges : BootstrapExchanges {
    private class Wrapped(private val exchange: AccountBootstrapExchange) : BootstrapExchange {
        override fun requestBytes() = exchange.requestBytes()
        override fun openResponse(reply: ByteArray) = exchange.openResponse(reply)
        override fun close() = exchange.close()
    }

    override fun start(
        nodePublicKey: ByteArray,
        bootstrapPublicKey: ByteArray,
        capability: ByteArray,
        registrationRequest: ByteArray,
        credentialRequest: ByteArray
    ): BootstrapExchange = Wrapped(
        AccountBootstrapExchange.start(nodePublicKey, bootstrapPublicKey, capability, registrationRequest, credentialRequest)
    )

    override fun finishRegistration(
        nodePublicKey: ByteArray,
        bootstrapPublicKey: ByteArray,
        input: AccountBootstrapRegistrationFinishInput
    ): BootstrapExchange = Wrapped(AccountBootstrapExchange.finishRegistration(nodePublicKey, bootstrapPublicKey, input))

    override fun finishLogin(
        nodePublicKey: ByteArray,
        bootstrapPublicKey: ByteArray,
        handshakeId: ByteArray,
        credentialFinalization: ByteArray
    ): BootstrapExchange = Wrapped(
        AccountBootstrapExchange.finishLogin(nodePublicKey, bootstrapPublicKey, handshakeId, credentialFinalization)
    )
}

/** The account identity operations sign-in needs from the in-memory cipher. */
internal interface BootstrapIdentity {
    fun createIdentity(exportKey: ByteArray, context: ByteArray): InMemoryPayloadCipher.IdentityMaterial
    fun recoverIdentity(exportKey: ByteArray, context: ByteArray, envelope: ByteArray, expectedPublicKey: ByteArray)
    fun signRegistrationIdentityProof(
        nodeId: String,
        handshakeId: String,
        challenge: ByteArray,
        registrationUpload: ByteArray,
        identityPublic: ByteArray,
        prekeyId: String,
        identityEnvelope: ByteArray
    ): ByteArray
}

internal fun InMemoryPayloadCipher.asBootstrapIdentity(): BootstrapIdentity {
    val cipher = this
    return object : BootstrapIdentity {
        override fun createIdentity(exportKey: ByteArray, context: ByteArray) = cipher.createIdentity(exportKey, context)
        override fun recoverIdentity(exportKey: ByteArray, context: ByteArray, envelope: ByteArray, expectedPublicKey: ByteArray) =
            cipher.recoverIdentity(exportKey, context, envelope, expectedPublicKey)
        override fun signRegistrationIdentityProof(
            nodeId: String,
            handshakeId: String,
            challenge: ByteArray,
            registrationUpload: ByteArray,
            identityPublic: ByteArray,
            prekeyId: String,
            identityEnvelope: ByteArray
        ) = cipher.signRegistrationIdentityProof(
            nodeId, handshakeId, challenge, registrationUpload, identityPublic, prekeyId, identityEnvelope
        )
    }
}

internal class BootstrapSignInInput(
    val apiBaseUrl: String,
    val nodeId: String,
    val nodePublicKey: ByteArray,
    val bootstrapPublicKey: ByteArray,
    val capability: ByteArray,
    val accountContext: ByteArray,
    val password: ByteArray,
    val identity: BootstrapIdentity
)

/** A completed v11 sign-in. The receiver owns and wipes every byte array. */
internal class BootstrapSignIn(
    /** True when the relay took the first-use path for this invite. */
    val registered: Boolean,
    val created: Boolean,
    val username: String,
    val maxRoomsPerUser: Int,
    val sessionInactivitySec: Int,
    val identityPublic: ByteArray,
    val identityPrekeyId: String,
    val deviceStorageShare: ByteArray?,
    val keys: TransportKeys
) {
    fun wipeExceptKeys() {
        identityPublic.fill(0)
        deviceStorageShare?.fill(0)
    }

    /** Whether the relay's created flag matches the path it took. */
    val consistent: Boolean get() = created == registered
}

internal class BootstrapRejected : Exception("Wrong information.")

/**
 * Signs in, or creates the account on the first use of an invite, over the
 * protocol-v11 sealed bootstrap: start, then either registration
 * (finishRegistration, then an OPAQUE login) or a direct login, ending in a
 * Session whose transport root comes from the OPAQUE login.
 */
internal class AccountBootstrapClient(
    private val post: suspend (url: String, record: ByteArray) -> ByteArray?,
    private val opaque: OpaqueClient = UniffiOpaqueClient,
    private val exchanges: BootstrapExchanges = UniffiBootstrapExchanges
) {
    suspend fun signIn(input: BootstrapSignInInput): BootstrapSignIn {
        val start = opaque.start(input.password)
        val opened = mutableListOf<BootstrapExchange>()
        fun <T : BootstrapExchange> track(exchange: T): T = exchange.also(opened::add)
        var transportRoot = ByteArray(0)
        var handedOver = false
        try {
            val first = run(input, track(exchanges.start(
                input.nodePublicKey,
                input.bootstrapPublicKey,
                input.capability,
                start.registrationRequest,
                start.credentialRequest
            )))
            return when (first) {
                is AccountBootstrapResponse.RegistrationStart -> {
                    val (handshake, credentialResponse) = register(input, start, first, ::track)
                    val login = try {
                        opaque.finishLogin(input.password, start.loginState, credentialResponse)
                    } finally {
                        credentialResponse.fill(0)
                    }
                    login.exportKey.fill(0)
                    transportRoot = login.transportRoot
                    finish(input, handshake, login.credentialFinalization, registered = true, transportRoot, ::track)
                }
                is AccountBootstrapResponse.LoginStart -> {
                    val login = try {
                        opaque.finishLogin(input.password, start.loginState, first.credentialResponse)
                    } finally {
                        first.credentialResponse.fill(0)
                    }
                    transportRoot = login.transportRoot
                    try {
                        input.identity.recoverIdentity(
                            login.exportKey,
                            input.accountContext,
                            first.identityEnvelope,
                            first.identityPublic
                        )
                    } finally {
                        login.exportKey.fill(0)
                        first.identityPublic.fill(0)
                        first.identityEnvelope.fill(0)
                    }
                    finish(input, first.handshakeId, login.credentialFinalization, registered = false, transportRoot, ::track)
                }
                else -> throw BootstrapRejected()
            }.also { handedOver = true }
        } finally {
            if (!handedOver) transportRoot.fill(0)
            start.registrationState.fill(0)
            start.registrationRequest.fill(0)
            start.loginState.fill(0)
            start.credentialRequest.fill(0)
            opened.forEach { runCatching { it.close() } }
        }
    }

    /** Runs the registration half; returns the login handshake and credential response. */
    private suspend fun register(
        input: BootstrapSignInInput,
        start: OpaqueClientStart,
        reply: AccountBootstrapResponse.RegistrationStart,
        track: (BootstrapExchange) -> BootstrapExchange
    ): Pair<ByteArray, ByteArray> {
        val registration = try {
            opaque.finishRegistration(input.password, start.registrationState, reply.registrationResponse)
        } finally {
            reply.registrationResponse.fill(0)
        }
        var identity: InMemoryPayloadCipher.IdentityMaterial? = null
        var proof = ByteArray(0)
        try {
            val created = input.identity.createIdentity(registration.exportKey, input.accountContext)
            identity = created
            proof = input.identity.signRegistrationIdentityProof(
                nodeId = input.nodeId,
                handshakeId = handshakeIdString(reply.handshakeId),
                challenge = reply.challenge,
                registrationUpload = registration.registrationUpload,
                identityPublic = created.publicKey,
                prekeyId = created.prekeyId,
                identityEnvelope = created.envelope
            )
            val continuation = run(input, track(exchanges.finishRegistration(
                input.nodePublicKey,
                input.bootstrapPublicKey,
                AccountBootstrapRegistrationFinishInput(
                    handshakeId = reply.handshakeId,
                    registrationUpload = registration.registrationUpload,
                    identityPublic = created.publicKey,
                    identityPrekeyId = created.prekeyId,
                    identityEnvelope = created.envelope,
                    identityProof = proof
                )
            ))) as? AccountBootstrapResponse.RegistrationContinuation ?: throw BootstrapRejected()
            return continuation.handshakeId to continuation.credentialResponse
        } finally {
            proof.fill(0)
            identity?.publicKey?.fill(0)
            identity?.envelope?.fill(0)
            registration.registrationUpload.fill(0)
            registration.exportKey.fill(0)
            reply.handshakeId.fill(0)
            reply.challenge.fill(0)
        }
    }

    private suspend fun finish(
        input: BootstrapSignInInput,
        handshakeId: ByteArray,
        credentialFinalization: ByteArray,
        registered: Boolean,
        transportRoot: ByteArray,
        track: (BootstrapExchange) -> BootstrapExchange
    ): BootstrapSignIn {
        val session = try {
            run(input, track(exchanges.finishLogin(
                input.nodePublicKey,
                input.bootstrapPublicKey,
                handshakeId,
                credentialFinalization
            ))) as? AccountBootstrapResponse.Session ?: throw BootstrapRejected()
        } finally {
            handshakeId.fill(0)
            credentialFinalization.fill(0)
        }
        session.identityEnvelope.fill(0)
        // The caller checks the session (including created == registered) and
        // logs it out with these keys if it refuses it.
        return BootstrapSignIn(
            registered = registered,
            created = session.created,
            username = session.username,
            maxRoomsPerUser = session.maxRoomsPerUser.toInt(),
            sessionInactivitySec = session.sessionInactivitySec.toInt(),
            identityPublic = session.identityPublic,
            identityPrekeyId = session.identityPrekeyId,
            deviceStorageShare = session.deviceStorageShare,
            keys = TransportKeys(input.nodePublicKey.copyOf(), session.sessionId, transportRoot)
        )
    }

    private suspend fun run(input: BootstrapSignInInput, exchange: BootstrapExchange): AccountBootstrapResponse {
        val request = exchange.requestBytes()
        val reply = try {
            post("${input.apiBaseUrl}${SealedRecordHttp.BOOTSTRAP_PATH}", request)
        } finally {
            request.fill(0)
        } ?: throw BootstrapRejected()
        return try {
            exchange.openResponse(reply)
        } catch (_: Exception) {
            throw BootstrapRejected()
        } finally {
            reply.fill(0)
        }
    }

    private companion object {
        fun handshakeIdString(bytes: ByteArray): String {
            if (bytes.size != 16) throw BootstrapRejected()
            val buffer = ByteBuffer.wrap(bytes)
            return UUID(buffer.long, buffer.long).toString()
        }
    }
}

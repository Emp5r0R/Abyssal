package com.abyssal.chat.data.network.v11

import uniffi.abyssal_core.AccountBootstrapRegistrationFinishInput
import uniffi.abyssal_core.AccountBootstrapResponse
import uniffi.abyssal_core.OpaqueClientStart
import uniffi.abyssal_core.OpaqueLoginFinish
import uniffi.abyssal_core.OpaqueRegistrationFinish

/** Deterministic OPAQUE steps that record what they were given. */
internal class FakeOpaque : OpaqueClient {
    val start = OpaqueClientStart(
        registrationState = ByteArray(4) { 1 },
        registrationRequest = ByteArray(4) { 2 },
        loginState = ByteArray(4) { 3 },
        credentialRequest = ByteArray(4) { 4 }
    )
    val registration = OpaqueRegistrationFinish(
        registrationUpload = ByteArray(8) { 5 },
        exportKey = ByteArray(64) { 6 }
    )
    val transportRoot = ByteArray(32) { 9 }
    val loginExportKey = ByteArray(64) { 8 }
    val loginFinalization = ByteArray(8) { 7 }
    val loginStatesSeen = mutableListOf<List<Byte>>()
    val loginResponsesSeen = mutableListOf<List<Byte>>()

    override fun start(password: ByteArray) = start

    override fun finishRegistration(password: ByteArray, state: ByteArray, response: ByteArray) = registration

    override fun finishLogin(password: ByteArray, state: ByteArray, response: ByteArray): OpaqueLoginFinish {
        loginStatesSeen += state.toList()
        loginResponsesSeen += response.toList()
        return OpaqueLoginFinish(loginFinalization, loginExportKey, transportRoot)
    }
}

/**
 * A scripted relay: each step's reply is produced from what the client sent,
 * so a registration can echo back the identity the client created.
 */
internal class FakeBootstrapExchanges(
    var startReply: () -> AccountBootstrapResponse = { AccountBootstrapResponse.Failure },
    var registrationReply: (AccountBootstrapRegistrationFinishInput) -> AccountBootstrapResponse = {
        AccountBootstrapResponse.Failure
    },
    var loginReply: (handshakeId: ByteArray, finalization: ByteArray) -> AccountBootstrapResponse = { _, _ ->
        AccountBootstrapResponse.Failure
    }
) : BootstrapExchanges {
    inner class Exchange(val step: String, val args: List<Any>, private val answer: () -> AccountBootstrapResponse) :
        BootstrapExchange {
        val request = ByteArray(16) { step.length.toByte() }
        var closed = false
        override fun requestBytes() = request
        override fun openResponse(reply: ByteArray): AccountBootstrapResponse {
            require(reply.isNotEmpty())
            return answer()
        }
        override fun close() {
            closed = true
        }
    }

    val opened = mutableListOf<Exchange>()

    private fun track(exchange: Exchange) = exchange.also(opened::add)

    override fun start(
        nodePublicKey: ByteArray,
        bootstrapPublicKey: ByteArray,
        capability: ByteArray,
        registrationRequest: ByteArray,
        credentialRequest: ByteArray
    ): BootstrapExchange = track(
        Exchange("start", listOf(nodePublicKey, bootstrapPublicKey, capability, registrationRequest, credentialRequest), startReply)
    )

    override fun finishRegistration(
        nodePublicKey: ByteArray,
        bootstrapPublicKey: ByteArray,
        input: AccountBootstrapRegistrationFinishInput
    ): BootstrapExchange {
        // Copy what the client sent now: it wipes its buffers once the request is sealed.
        val sent = input.copy(
            handshakeId = input.handshakeId.copyOf(),
            registrationUpload = input.registrationUpload.copyOf(),
            identityPublic = input.identityPublic.copyOf(),
            identityEnvelope = input.identityEnvelope.copyOf(),
            identityProof = input.identityProof.copyOf()
        )
        return track(Exchange("finishRegistration", listOf(sent)) { registrationReply(sent) })
    }

    override fun finishLogin(
        nodePublicKey: ByteArray,
        bootstrapPublicKey: ByteArray,
        handshakeId: ByteArray,
        credentialFinalization: ByteArray
    ): BootstrapExchange {
        val handshake = handshakeId.copyOf()
        val finalization = credentialFinalization.copyOf()
        return track(Exchange("finishLogin", listOf(handshakeId, credentialFinalization, handshake, finalization)) {
            loginReply(handshake, finalization)
        })
    }

    companion object {
        val HANDSHAKE: ByteArray get() = ByteArray(16) { it.toByte() }
        const val HANDSHAKE_ID = "00010203-0405-0607-0809-0a0b0c0d0e0f"

        fun session(
            created: Boolean,
            identityPublic: ByteArray,
            prekeyId: String,
            username: String = "Alice_1",
            share: ByteArray? = ByteArray(32) { 0x5a }
        ) = AccountBootstrapResponse.Session(
            sessionId = ByteArray(32) { 0x51 },
            created = created,
            maxRoomsPerUser = 3u,
            sessionInactivitySec = 900u,
            username = username,
            identityPublic = identityPublic,
            identityPrekeyId = prekeyId,
            identityEnvelope = ByteArray(8) { 0x0e },
            deviceStorageShare = share
        )

        /** A relay that registers the account and echoes the identity it was given. */
        fun registering(
            created: Boolean = true,
            username: String = "Alice_1",
            share: ByteArray? = ByteArray(32) { 0x5a }
        ): FakeBootstrapExchanges {
            var identity: AccountBootstrapRegistrationFinishInput? = null
            return FakeBootstrapExchanges(
                startReply = {
                    AccountBootstrapResponse.RegistrationStart(HANDSHAKE, ByteArray(8) { 0x0b }, ByteArray(32) { 0x0c })
                },
                registrationReply = { input ->
                    identity = input
                    AccountBootstrapResponse.RegistrationContinuation(HANDSHAKE, ByteArray(8) { 0x0d })
                },
                loginReply = { _, _ ->
                    val sent = requireNotNull(identity)
                    session(created, sent.identityPublic.copyOf(), sent.identityPrekeyId, username, share)
                }
            )
        }
    }
}

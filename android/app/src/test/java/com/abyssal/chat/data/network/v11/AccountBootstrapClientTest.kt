package com.abyssal.chat.data.network.v11

import com.abyssal.chat.data.network.InMemoryPayloadCipher
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import uniffi.abyssal_core.AccountBootstrapRegistrationFinishInput
import uniffi.abyssal_core.AccountBootstrapResponse

class AccountBootstrapClientTest {
    private class RecordingIdentity : BootstrapIdentity {
        val recovered = mutableListOf<List<ByteArray>>()
        val proofs = mutableListOf<List<Any>>()
        var created = 0

        override fun createIdentity(exportKey: ByteArray, context: ByteArray): InMemoryPayloadCipher.IdentityMaterial {
            created += 1
            return InMemoryPayloadCipher.IdentityMaterial(ByteArray(608) { 0x1d }, "prekey-1", ByteArray(8) { 0x0e })
        }

        override fun recoverIdentity(exportKey: ByteArray, context: ByteArray, envelope: ByteArray, expectedPublicKey: ByteArray) {
            recovered += listOf(exportKey, context, envelope, expectedPublicKey)
        }

        override fun signRegistrationIdentityProof(
            nodeId: String,
            handshakeId: String,
            challenge: ByteArray,
            registrationUpload: ByteArray,
            identityPublic: ByteArray,
            prekeyId: String,
            identityEnvelope: ByteArray
        ): ByteArray {
            proofs += listOf(nodeId, handshakeId, challenge.copyOf())
            return ByteArray(64) { 0x9f.toByte() }
        }
    }

    private val posted = mutableListOf<Pair<String, ByteArray>>()
    private var reply: ByteArray? = ByteArray(32) { 1 }

    private fun client(opaque: FakeOpaque, exchanges: FakeBootstrapExchanges) = AccountBootstrapClient(
        post = { url, record ->
            posted += url to record.copyOf()
            reply?.copyOf()
        },
        opaque = opaque,
        exchanges = exchanges
    )

    private fun input(identity: BootstrapIdentity) = BootstrapSignInInput(
        apiBaseUrl = "https://relay.test",
        nodeId = "node-1",
        nodePublicKey = ByteArray(32) { 0x0a },
        bootstrapPublicKey = ByteArray(32) { 0x0b },
        capability = ByteArray(32) { 0x0c },
        accountContext = ByteArray(32) { 0x0d },
        password = "correct horse battery staple".toByteArray(),
        identity = identity
    )

    private fun ByteArray.zeroed() = all { it == 0.toByte() }

    @Test
    fun returningAccountRecoversItsIdentityAndGetsTheLoginTransportKeys() = runBlocking {
        val opaque = FakeOpaque()
        val identityPublic = ByteArray(608) { 0x1d }
        val envelope = ByteArray(8) { 0x0e }
        val exchanges = FakeBootstrapExchanges(
            startReply = {
                AccountBootstrapResponse.LoginStart(FakeBootstrapExchanges.HANDSHAKE, ByteArray(8) { 0x0b }, identityPublic, "prekey-1", envelope)
            },
            loginReply = { _, _ -> FakeBootstrapExchanges.session(false, ByteArray(608) { 0x1d }, "prekey-1") }
        )
        val identity = RecordingIdentity()
        val signIn = input(identity)

        val result = client(opaque, exchanges).signIn(signIn)

        assertFalse(result.registered)
        assertTrue(result.consistent)
        assertEquals("Alice_1", result.username)
        assertEquals(3, result.maxRoomsPerUser)
        assertArrayEquals(ByteArray(32) { 9 }, result.keys.transportRoot)
        assertArrayEquals(ByteArray(32) { 0x51 }, result.keys.sessionId)
        assertArrayEquals(signIn.nodePublicKey, result.keys.nodePublicKey)
        assertNotSame(signIn.nodePublicKey, result.keys.nodePublicKey)
        assertEquals(listOf("start", "finishLogin"), exchanges.opened.map { it.step })
        assertTrue(posted.all { it.first == "https://relay.test/v1/bootstrap" })
        // The OPAQUE login used the original login state and the relay's credential response.
        assertEquals(listOf<Byte>(3, 3, 3, 3), opaque.loginStatesSeen.single())
        val (exportKey, context, recoveredEnvelope, recoveredPublic) = identity.recovered.single()
        assertTrue(context === signIn.accountContext)
        assertTrue(exportKey.zeroed() && recoveredEnvelope.zeroed() && recoveredPublic.zeroed())
        val login = exchanges.opened[1].args
        assertTrue((login[0] as ByteArray).zeroed() && (login[1] as ByteArray).zeroed())
        assertArrayEquals(ByteArray(8) { 7 }, login[3] as ByteArray)
        // Every sealed request was wiped after sending, every exchange closed.
        assertTrue(exchanges.opened.all { it.closed && it.request.zeroed() })
        assertTrue(opaque.start.loginState.zeroed() && opaque.start.credentialRequest.zeroed())
    }

    @Test
    fun firstUseRegistersThenLogsInWithTheKeptLoginState() = runBlocking {
        val opaque = FakeOpaque()
        val exchanges = FakeBootstrapExchanges.registering()
        val identity = RecordingIdentity()

        val result = client(opaque, exchanges).signIn(input(identity))

        assertTrue(result.registered && result.created && result.consistent)
        assertEquals(listOf("start", "finishRegistration", "finishLogin"), exchanges.opened.map { it.step })
        assertEquals(1, identity.created)
        assertEquals(listOf("node-1", FakeBootstrapExchanges.HANDSHAKE_ID), identity.proofs.single().take(2))
        val registration = exchanges.opened[1].args.single() as AccountBootstrapRegistrationFinishInput
        assertArrayEquals(FakeBootstrapExchanges.HANDSHAKE, registration.handshakeId)
        assertEquals("prekey-1", registration.identityPrekeyId)
        assertArrayEquals(ByteArray(64) { 0x9f.toByte() }, registration.identityProof)
        assertEquals(listOf<Byte>(3, 3, 3, 3), opaque.loginStatesSeen.single())
        assertEquals(List<Byte>(8) { 0x0d }, opaque.loginResponsesSeen.single())
        assertArrayEquals(ByteArray(32) { 0x5a }, result.deviceStorageShare)
        assertTrue(opaque.registration.exportKey.zeroed() && opaque.registration.registrationUpload.zeroed())
        assertTrue(opaque.loginExportKey.zeroed())
        assertTrue(exchanges.opened.all { it.closed })
    }

    @Test
    fun reportsACreatedFlagThatContradictsThePathTaken() = runBlocking {
        val result = client(FakeOpaque(), FakeBootstrapExchanges.registering(created = false))
            .signIn(input(RecordingIdentity()))
        assertTrue(result.registered)
        assertFalse(result.consistent)
    }

    @Test
    fun rejectsEveryOutOfOrderOrMissingReplyAndWipesWhatItHeld() = runBlocking {
        val cases: List<Pair<String, FakeBootstrapExchanges>> = listOf(
            "a failure at the start" to FakeBootstrapExchanges(),
            "a session where a continuation belongs" to FakeBootstrapExchanges.registering().apply {
                registrationReply = { FakeBootstrapExchanges.session(true, ByteArray(608), "prekey-1") }
            },
            "a failure in place of the session" to FakeBootstrapExchanges.registering().apply {
                loginReply = { _, _ -> AccountBootstrapResponse.Failure }
            }
        )
        for ((label, exchanges) in cases) {
            val opaque = FakeOpaque()
            try {
                client(opaque, exchanges).signIn(input(RecordingIdentity()))
                fail("accepted $label")
            } catch (_: BootstrapRejected) {
            }
            assertTrue(label, exchanges.opened.all { it.closed })
            assertTrue(label, opaque.start.registrationState.zeroed() && opaque.start.loginState.zeroed())
            // A transport root that was produced never outlives the failure.
            if (opaque.loginStatesSeen.isNotEmpty()) assertTrue(label, opaque.transportRoot.zeroed())
        }

        reply = null
        val exchanges = FakeBootstrapExchanges.registering()
        try {
            client(FakeOpaque(), exchanges).signIn(input(RecordingIdentity()))
            fail("accepted a missing reply")
        } catch (_: BootstrapRejected) {
        }
        assertEquals(listOf("start"), exchanges.opened.map { it.step })
        assertTrue(exchanges.opened.single().closed)
    }
}

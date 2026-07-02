package com.abyssal.chat.data.repository

import com.abyssal.chat.domain.model.IdentityValidationResult
import com.abyssal.chat.domain.model.IncomingTransportPayload
import com.abyssal.chat.domain.model.NodeEndpoint
import com.abyssal.chat.domain.model.ServerStatus
import com.abyssal.chat.domain.model.User
import com.abyssal.chat.domain.repository.ICryptoService
import com.abyssal.chat.domain.repository.IIdentityService
import com.abyssal.chat.domain.repository.IChatTransport
import com.abyssal.chat.domain.repository.IDisguiseManager
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import java.security.SecureRandom

class MockIdentityService : IIdentityService {
    private var currentUser: User? = null

    private val prefixes = listOf(
        "Silent", "Nebula", "Quantum", "Vortex", "Solar", "Cosmic", "Lunar", 
        "Alpha", "Shadow", "Ghost", "Starlight", "Obsidian", "Frozen", "Electric"
    )

    private val suffixes = listOf(
        "Wolf", "Tiger", "Fox", "Eagle", "Falcon", "Leopard", "Spectre", 
        "Titan", "Node", "Warp", "Core", "Entity", "Daemon", "Vector"
    )

    override suspend fun validateInviteCode(code: String, endpoint: NodeEndpoint): IdentityValidationResult {
        delay(800)
        val regex = Regex("^[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}$")
        val accepted = regex.matches(code) || code == "BIOM-ETRI-CAUT"
        return IdentityValidationResult(
            accepted = accepted,
            token = if (accepted) "mock-token" else null,
            nodeId = endpoint.displayHost,
            isAdmin = accepted,
            error = if (accepted) null else "Invalid invite code."
        )
    }

    override suspend fun generateRandomIdentity(): User {
        delay(500)
        val random = SecureRandom()
        val prefix = prefixes[random.nextInt(prefixes.size)]
        val suffix = suffixes[random.nextInt(suffixes.size)]
        val number = 100 + random.nextInt(900)
        
        val fakeKey = ByteArray(32)
        random.nextBytes(fakeKey)

        // Make every 2nd user an admin for easier testing of custom forum features
        val isAdmin = random.nextInt(2) == 0

        val user = User(
            username = "$prefix$suffix$number",
            publicKey = fakeKey,
            isAdmin = isAdmin
        )
        currentUser = user
        return user
    }

    override fun getCurrentUser(): User? = currentUser

    override fun logout() {
        currentUser = null
    }
}

class MockCryptoService : ICryptoService {
    override suspend fun generateKeyPair(): Pair<ByteArray, ByteArray> {
        val random = SecureRandom()
        val priv = ByteArray(32)
        val pub = ByteArray(32)
        random.nextBytes(priv)
        random.nextBytes(pub)
        return Pair(priv, pub)
    }

    override suspend fun encryptMessage(plainText: String, sessionKey: ByteArray): Pair<ByteArray, ByteArray> {
        val nonce = ByteArray(12)
        SecureRandom().nextBytes(nonce)
        val ciphertext = plainText.toByteArray(Charsets.UTF_8)
        return Pair(ciphertext, nonce)
    }

    override suspend fun decryptMessage(cipherText: ByteArray, nonce: ByteArray, sessionKey: ByteArray): String {
        return String(cipherText, Charsets.UTF_8)
    }
}

class MockChatTransport : IChatTransport {
    private val _wipeCommands = MutableSharedFlow<Unit>(extraBufferCapacity = 1)
    private val _incomingPayloads = MutableSharedFlow<IncomingTransportPayload>(extraBufferCapacity = 8)
    private val _serverStatus = MutableSharedFlow<ServerStatus>(replay = 1)

    init {
        _serverStatus.tryEmit(ServerStatus("CONNECTED", "MockNode", 0))
    }

    override fun connect() {
        _serverStatus.tryEmit(ServerStatus("CONNECTED", "MockNode", 0))
    }

    override fun disconnect() {
        _serverStatus.tryEmit(ServerStatus("DISCONNECTED", "MockNode", 0))
    }

    override fun getServerStatus(): Flow<ServerStatus> = _serverStatus.asSharedFlow()
    override fun getIncomingWipeCommands(): Flow<Unit> = _wipeCommands.asSharedFlow()
    override fun getIncomingPayloads(): Flow<IncomingTransportPayload> = _incomingPayloads.asSharedFlow()

    override suspend fun joinChat(chatId: String) {}
    override suspend fun sendEncryptedPayload(chatId: String, payload: ByteArray) {}
    override suspend fun broadcastGlobalWipe() {
        _wipeCommands.tryEmit(Unit)
    }

    fun triggerSimulatedGlobalWipe() {
        _wipeCommands.tryEmit(Unit)
    }
}

class MockDisguiseManager : IDisguiseManager {
    private var isDisguiseActive = false
    private var currentPin = "2026" // Default lock PIN

    override fun setDisguiseEnabled(enabled: Boolean) {
        isDisguiseActive = enabled
        // Mock print simulating Android PackageManager Component Enabled toggling
        println("PackageManager alias configuration toggled: LauncherCalculator=$enabled, LauncherAbyssal=${!enabled}")
    }

    override fun isDisguiseEnabled(): Boolean = isDisguiseActive

    override fun savePin(pin: String) {
        currentPin = pin
    }

    override fun verifyPin(pin: String): Boolean {
        return pin == currentPin
    }

    override fun getPin(): String = currentPin
}

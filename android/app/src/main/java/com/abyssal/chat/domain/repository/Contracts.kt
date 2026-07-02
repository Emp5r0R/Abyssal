package com.abyssal.chat.domain.repository

import com.abyssal.chat.domain.model.ChatSession
import com.abyssal.chat.domain.model.IdentityValidationResult
import com.abyssal.chat.domain.model.IncomingTransportPayload
import com.abyssal.chat.domain.model.Message
import com.abyssal.chat.domain.model.NodeEndpoint
import com.abyssal.chat.domain.model.NodeSession
import com.abyssal.chat.domain.model.ServerStatus
import com.abyssal.chat.domain.model.User
import com.abyssal.chat.domain.model.UserPresence
import kotlinx.coroutines.flow.Flow

interface IIdentityService {
    suspend fun createAccount(code: String, password: String, endpoint: NodeEndpoint): IdentityValidationResult
    suspend fun login(code: String, password: String, endpoint: NodeEndpoint): IdentityValidationResult
    fun setCurrentUser(user: User)
    fun getCurrentUser(): User?
    fun logout()
}

interface INodeConfigService {
    fun normalizeNodeUrl(input: String): Result<NodeEndpoint>
    fun setActiveSession(session: NodeSession)
    fun getActiveSession(): NodeSession?
    fun clear()
}

interface IMessageSender {
    suspend fun sendMessage(chatId: String, content: String, selfDestructSec: Int)
    suspend fun sendMediaMessage(chatId: String, mediaType: String, fileName: String, sizeMb: Int, selfDestructSec: Int)
}

interface IMessageRepository {
    fun getChatSessions(): Flow<List<ChatSession>>
    fun getMessages(chatId: String): Flow<List<Message>>
    suspend fun saveMessage(chatId: String, message: Message)
    suspend fun markAsRead(chatId: String, messageId: String)
    suspend fun createForumSession(session: ChatSession)
    suspend fun clearAllData()
}

interface ICryptoService {
    suspend fun generateKeyPair(): Pair<ByteArray, ByteArray>
    suspend fun encryptMessage(plainText: String, sessionKey: ByteArray): Pair<ByteArray, ByteArray>
    suspend fun decryptMessage(cipherText: ByteArray, nonce: ByteArray, sessionKey: ByteArray): String
}

interface IChatTransport {
    fun connect()
    fun disconnect()
    fun getServerStatus(): Flow<ServerStatus>
    fun getIncomingWipeCommands(): Flow<Unit>
    fun getIncomingPayloads(): Flow<IncomingTransportPayload>
    fun getPresence(): Flow<List<UserPresence>>
    suspend fun joinChat(chatId: String)
    suspend fun sendEncryptedPayload(chatId: String, payload: ByteArray)
    suspend fun broadcastGlobalWipe()
}

interface IDisguiseManager {
    fun setDisguiseEnabled(enabled: Boolean)
    fun isDisguiseEnabled(): Boolean
    fun savePin(pin: String)
    fun verifyPin(pin: String): Boolean
    fun getPin(): String
}

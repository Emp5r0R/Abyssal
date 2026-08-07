package com.abyssal.chat.domain.repository

import com.abyssal.chat.domain.model.ChatSession
import com.abyssal.chat.domain.model.AttachmentUploadResult
import com.abyssal.chat.domain.model.DecryptedAttachment
import com.abyssal.chat.domain.model.IdentityValidationResult
import com.abyssal.chat.domain.model.EncryptedTransportPayload
import com.abyssal.chat.domain.model.IncomingTransportPayload
import com.abyssal.chat.domain.model.IdentityStateSnapshot
import com.abyssal.chat.domain.model.Message
import com.abyssal.chat.domain.model.NodeEndpoint
import com.abyssal.chat.domain.model.NodeSession
import com.abyssal.chat.domain.model.RoomChange
import com.abyssal.chat.domain.model.ServerStatus
import com.abyssal.chat.domain.model.User
import com.abyssal.chat.domain.model.UserPresence
import kotlinx.coroutines.flow.Flow

interface IIdentityService {
    suspend fun enterAccount(code: String, password: String, endpoint: NodeEndpoint): IdentityValidationResult
    suspend fun createAccount(code: String, password: String, endpoint: NodeEndpoint): IdentityValidationResult
    suspend fun login(code: String, password: String, endpoint: NodeEndpoint): IdentityValidationResult
    fun setCurrentUser(user: User)
    fun getCurrentUser(): User?
    suspend fun revokeSession(session: NodeSession): Boolean
    fun logout()
}

interface INodeConfigService {
    fun normalizeNodeUrl(input: String): Result<NodeEndpoint>
    fun setActiveSession(session: NodeSession)
    fun getActiveSession(): NodeSession?
    fun clear()
}

interface IMessageSender {
    suspend fun sendMessage(
        chatId: String,
        content: String,
        selfDestructSec: Int,
        replyToMessageId: String? = null
    )
    suspend fun saveLocalAttachmentMessage(chatId: String, message: Message)
}

interface IMessageRepository {
    fun getChatSessions(): Flow<List<ChatSession>>
    fun getMessages(chatId: String): Flow<List<Message>>
    suspend fun saveMessage(chatId: String, message: Message)
    suspend fun markAsRead(chatId: String, messageId: String)
    suspend fun createForumSession(session: ChatSession)
    suspend fun deleteChatSession(chatId: String)
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
    fun getRoomChanges(): Flow<RoomChange>
    fun getPresence(): Flow<List<UserPresence>>
    suspend fun joinChat(chatId: String)
    suspend fun createForum(session: ChatSession)
    suspend fun deleteForum(chatId: String)
    suspend fun openDirect(peerUsername: String)
    suspend fun sendEncryptedPayload(chatId: String, payload: EncryptedTransportPayload): Boolean
    suspend fun acknowledgeMessage(
        chatId: String,
        messageId: String,
        senderUsername: String,
        state: IdentityStateSnapshot
    ): Boolean
    suspend fun syncIdentityState(state: IdentityStateSnapshot): Boolean
    suspend fun signalUserActivity(): Boolean
    suspend fun broadcastGlobalWipe()
}

interface IEncryptedAttachmentService {
    suspend fun uploadEncryptedAttachment(
        chatId: String,
        mediaType: String,
        encryptedBytes: ByteArray,
        oneTimeView: Boolean,
        deleteAfterDownload: Boolean,
        ttlSec: Int,
        onProgress: (sentBytes: Long, totalBytes: Long) -> Unit
    ): AttachmentUploadResult

    suspend fun downloadEncryptedAttachment(attachmentId: String): ByteArray?
    suspend fun saveDecryptedAttachment(attachment: DecryptedAttachment, outputUri: android.net.Uri): Boolean
}

interface IDisguiseManager {
    fun setDisguiseEnabled(enabled: Boolean)
    fun isDisguiseEnabled(): Boolean
    fun savePin(pin: String)
    fun saveDuressPin(pin: String)
    fun verifyPin(pin: String): Boolean
    fun verifyDuressPin(pin: String): Boolean
    fun getPin(): String
    fun getDuressPin(): String
}

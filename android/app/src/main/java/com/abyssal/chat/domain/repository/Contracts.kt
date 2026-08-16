package com.abyssal.chat.domain.repository

import com.abyssal.chat.domain.model.ChatSession
import com.abyssal.chat.domain.model.DirectoryStamp
import com.abyssal.chat.domain.model.DirectoryEvidenceStatus
import com.abyssal.chat.domain.model.AttachmentUploadResult
import com.abyssal.chat.domain.model.AvailableAppUpdate
import com.abyssal.chat.domain.model.DecryptedAttachment
import com.abyssal.chat.domain.model.IdentityValidationResult
import com.abyssal.chat.domain.model.EncryptedTransportPayload
import com.abyssal.chat.domain.model.EncryptedAttachmentDownload
import com.abyssal.chat.domain.model.IncomingTransportPayload
import com.abyssal.chat.domain.model.IdentityStateSnapshot
import com.abyssal.chat.domain.model.Message
import com.abyssal.chat.domain.model.NodeEndpoint
import com.abyssal.chat.domain.model.NodeSession
import com.abyssal.chat.domain.model.PrekeyLease
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
    /** Monotonic in-memory epoch advanced by every synchronous repository purge. */
    fun currentEpoch(): ULong = 0uL
    /** Synchronous RAM purge for ViewModel teardown; must not touch disk. */
    fun clearAllDataNow()
    suspend fun saveMessage(chatId: String, message: Message)
    fun saveMessageIfCurrent(epoch: ULong, chatId: String, message: Message): Boolean = false
    suspend fun markAsRead(chatId: String, messageId: String)
    fun markAsReadIfCurrent(epoch: ULong, chatId: String, messageId: String): Boolean = false
    suspend fun forgetAttachmentKey(chatId: String, messageId: String)
    suspend fun createForumSession(session: ChatSession)
    fun createForumSessionIfCurrent(epoch: ULong, session: ChatSession): Boolean = false
    suspend fun deleteChatSession(chatId: String)
    fun deleteChatSessionIfCurrent(epoch: ULong, chatId: String): Boolean = false
    suspend fun clearAllData()
    fun close()
}

/** Result of a message frame after the relay's admission decision. */
enum class OutboundSendResult {
    ACCEPTED,
    REJECTED,
    NOT_SENT,
    /** The frame may have reached the relay, but no authenticated result arrived. */
    AMBIGUOUS
}

interface IChatTransport {
    fun connect()
    fun disconnect()
    /** Epoch of the active connection; zero keeps simple test transports source-compatible. */
    fun currentConnectionGeneration(): Long = 0L
    /** Runs one synchronous mutation while the expected connection epoch cannot advance. */
    fun runIfConnectionCurrent(
        expectedConnectionGeneration: Long,
        mutation: () -> Boolean
    ): Boolean = currentConnectionGeneration() == expectedConnectionGeneration && mutation()
    fun getServerStatus(): Flow<ServerStatus>
    fun getIncomingWipeCommands(): Flow<Long>
    fun getIncomingPayloads(): Flow<IncomingTransportPayload>
    fun getRoomChanges(): Flow<RoomChange>
    fun getPresence(): Flow<List<UserPresence>>
    /** Latest authenticated directory evidence used to bind encrypted plaintext. */
    fun currentDirectoryStamp(): DirectoryStamp? = null
    fun directoryEvidenceStatus(stamp: DirectoryStamp): DirectoryEvidenceStatus {
        val current = currentDirectoryStamp() ?: return DirectoryEvidenceStatus.CONFLICT
        if (stamp == current) return DirectoryEvidenceStatus.KNOWN
        return if (stamp.nodeId == current.nodeId && stamp.revision < current.revision) {
            DirectoryEvidenceStatus.UNKNOWN_OLD
        } else {
            DirectoryEvidenceStatus.CONFLICT
        }
    }
    suspend fun joinChat(chatId: String)
    /**
     * Joins [chatId] only when the captured connection epoch is still active.
     * The default keeps lightweight test transports and older implementations
     * source-compatible; they retain the original join behavior.
     */
    suspend fun joinChat(chatId: String, expectedConnectionGeneration: Long) {
        joinChat(chatId)
    }
    suspend fun createForum(session: ChatSession)
    suspend fun createForum(session: ChatSession, expectedConnectionGeneration: Long) {
        createForum(session)
    }
    suspend fun deleteForum(chatId: String)
    suspend fun deleteForum(chatId: String, expectedConnectionGeneration: Long) {
        deleteForum(chatId)
    }
    suspend fun openDirect(peerUsername: String)
    suspend fun openDirect(peerUsername: String, expectedConnectionGeneration: Long) {
        openDirect(peerUsername)
    }
    suspend fun sendEncryptedPayload(chatId: String, payload: EncryptedTransportPayload): OutboundSendResult
    suspend fun sendEncryptedPayload(
        chatId: String,
        payload: EncryptedTransportPayload,
        expectedConnectionGeneration: Long
    ): OutboundSendResult = sendEncryptedPayload(chatId, payload)

    /** Requests one exact recipient-bound protocol-v9 prekey lease. */
    suspend fun requestPrekeyLease(
        chatId: String,
        messageId: String,
        recipientUsername: String
    ): PrekeyLease? = null

    /** Requests a lease only while the captured connection generation is live. */
    suspend fun requestPrekeyLease(
        chatId: String,
        messageId: String,
        recipientUsername: String,
        expectedConnectionGeneration: Long
    ): PrekeyLease? = requestPrekeyLease(chatId, messageId, recipientUsername)

    /** Releases an acquired but unused lease; relay failures are best effort. */
    suspend fun releasePrekeyLease(
        chatId: String,
        messageId: String,
        recipientUsername: String,
        prekeyId: String
    ): Boolean = false

    /** Releases a lease only while the captured connection generation is live. */
    suspend fun releasePrekeyLease(
        chatId: String,
        messageId: String,
        recipientUsername: String,
        prekeyId: String,
        expectedConnectionGeneration: Long
    ): Boolean = releasePrekeyLease(chatId, messageId, recipientUsername, prekeyId)
    suspend fun acknowledgeMessage(
        chatId: String,
        messageId: String,
        senderUsername: String,
        state: IdentityStateSnapshot,
        usedPrekeyId: String,
        ackSignature: ByteArray
    ): OutboundSendResult
    suspend fun acknowledgeMessage(
        chatId: String,
        messageId: String,
        senderUsername: String,
        state: IdentityStateSnapshot,
        usedPrekeyId: String,
        ackSignature: ByteArray,
        expectedConnectionGeneration: Long
    ): OutboundSendResult = acknowledgeMessage(
        chatId,
        messageId,
        senderUsername,
        state,
        usedPrekeyId,
        ackSignature
    )
    suspend fun syncIdentityState(state: IdentityStateSnapshot): Boolean
    suspend fun syncIdentityState(
        state: IdentityStateSnapshot,
        expectedConnectionGeneration: Long
    ): Boolean = syncIdentityState(state)
    suspend fun signalUserActivity(): Boolean
    suspend fun signalUserActivity(expectedConnectionGeneration: Long): Boolean = signalUserActivity()
    suspend fun broadcastGlobalWipe()
    suspend fun broadcastGlobalWipe(expectedConnectionGeneration: Long) {
        broadcastGlobalWipe()
    }
}

interface IEncryptedAttachmentService {
    suspend fun uploadEncryptedAttachment(
        session: NodeSession,
        chatId: String,
        mediaType: String,
        encryptedBytes: ByteArray,
        oneTimeView: Boolean,
        deleteAfterDownload: Boolean,
        ttlSec: Int,
        onProgress: (sentBytes: Long, totalBytes: Long) -> Unit
    ): AttachmentUploadResult

    suspend fun downloadEncryptedAttachment(
        session: NodeSession,
        attachmentId: String,
        mediaType: String,
        expectedPlaintextBytes: Long
    ): EncryptedAttachmentDownload?
    suspend fun deleteUploadedAttachment(session: NodeSession, attachmentId: String): Boolean
    suspend fun completeAttachmentDownload(
        session: NodeSession,
        attachmentId: String,
        claim: String
    ): Boolean
    suspend fun releaseAttachmentDownloadClaim(
        session: NodeSession,
        attachmentId: String,
        claim: String
    ): Boolean
    suspend fun saveDecryptedAttachment(attachment: DecryptedAttachment, outputUri: android.net.Uri): Boolean
}

interface IDisguiseManager {
    /** Atomically configures the in-RAM verifier and launcher alias state. */
    fun configure(enabled: Boolean, unlockPin: String = "", duressPin: String = ""): Boolean
    fun isDisguiseEnabled(): Boolean
    /** Wipes verifier material during ViewModel teardown without waiting on I/O. */
    fun clear()
    fun verifyPin(pin: String): Boolean
    fun verifyDuressPin(pin: String): Boolean
}

interface IAppUpdateService {
    suspend fun findAvailableUpdate(): AvailableAppUpdate?
}

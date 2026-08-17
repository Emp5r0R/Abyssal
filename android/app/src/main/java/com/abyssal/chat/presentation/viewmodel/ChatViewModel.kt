package com.abyssal.chat.presentation.viewmodel

import android.net.Uri
import androidx.compose.runtime.State
import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.abyssal.chat.data.network.ATTACHMENT_WIRE_OVERHEAD_BYTES
import com.abyssal.chat.data.network.attachmentSelectionLimitBytes
import com.abyssal.chat.data.network.decryptAndCompleteAttachment
import com.abyssal.chat.data.network.FatalPayloadCipherException
import com.abyssal.chat.data.network.normalizeAttachmentId
import com.abyssal.chat.data.network.InMemoryPayloadCipher
import com.abyssal.chat.data.network.protocolAttachmentLimitBytes
import com.abyssal.chat.data.repository.isValidCamouflageConfiguration
import com.abyssal.chat.domain.model.AttachmentUploadProgress
import com.abyssal.chat.domain.model.AttachmentSavePolicy
import com.abyssal.chat.domain.model.AvailableAppUpdate
import com.abyssal.chat.domain.model.ChatSession
import com.abyssal.chat.domain.model.DecryptedAttachment
import com.abyssal.chat.domain.model.DisguiseSettings
import com.abyssal.chat.domain.model.DirectoryEvidenceStatus
import com.abyssal.chat.domain.model.DirectoryStamp
import com.abyssal.chat.domain.model.DirectChatTrustStore
import com.abyssal.chat.domain.model.DirectTrustContext
import com.abyssal.chat.domain.model.DirectTrustStatus
import com.abyssal.chat.domain.model.EncryptedTransportPayload
import com.abyssal.chat.domain.model.IncomingTransportPayload
import com.abyssal.chat.domain.model.IdentityValidationResult
import com.abyssal.chat.domain.model.IdentityStateSnapshot
import com.abyssal.chat.domain.model.Message
import com.abyssal.chat.domain.model.MessageAttentionPolicy
import com.abyssal.chat.domain.model.MessageReplyPolicy
import com.abyssal.chat.domain.model.NodeSession
import com.abyssal.chat.domain.model.PrekeyLease
import com.abyssal.chat.domain.model.RecipientIdentity
import com.abyssal.chat.domain.model.RoomChange
import com.abyssal.chat.domain.model.ServerStatus
import com.abyssal.chat.domain.model.SessionInactivityPolicy
import com.abyssal.chat.domain.model.SessionSecurityState
import com.abyssal.chat.domain.model.User
import com.abyssal.chat.domain.model.UserPresence
import com.abyssal.chat.domain.model.UpdatePromptPolicy
import com.abyssal.chat.domain.repository.IAppUpdateService
import com.abyssal.chat.domain.repository.IChatTransport
import com.abyssal.chat.domain.repository.IDisguiseManager
import com.abyssal.chat.domain.repository.IEncryptedAttachmentService
import com.abyssal.chat.domain.repository.IIdentityService
import com.abyssal.chat.domain.repository.IMessageRepository
import com.abyssal.chat.domain.repository.IMessageSender
import com.abyssal.chat.domain.repository.INodeConfigService
import com.abyssal.chat.domain.repository.OutboundSendResult
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.Collections
import java.util.LinkedHashSet
import java.util.Locale
import java.util.UUID
import java.util.concurrent.CancellationException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONObject
import uniffi.abyssal_core.conversationSafetyNumber
import uniffi.abyssal_core.decryptAttachment as decryptAttachmentBlob
import uniffi.abyssal_core.encryptAttachment as encryptAttachmentBlob

sealed class Screen {
    object Entrance : Screen()
    object Dashboard : Screen()
    data class Chat(val sessionId: String) : Screen()
}

internal fun isLocalOnlyForum(
    chatId: String,
    remoteRecipients: List<RecipientIdentity>?
): Boolean = chatId.startsWith("forum_") && remoteRecipients != null && remoteRecipients.isEmpty()

internal fun canStartAccountEntry(activeJob: Job?): Boolean = activeJob?.isActive != true

internal fun canInstallAccountEntryResult(
    coroutineIsActive: Boolean,
    result: IdentityValidationResult
): Boolean = coroutineIsActive &&
    result.accepted &&
    result.token != null &&
    result.publicKey != null &&
    result.prekeyId != null

internal const val ACK_SIGNATURE_BYTES = 64

internal fun clearClientIdentity(
    currentUser: User?,
    logout: () -> Unit,
    clearNodeSession: () -> Unit
) {
    runCatching(logout)
    runCatching(clearNodeSession)
    currentUser?.publicKey?.fill(0)
}

/**
 * Send one acknowledgement with a fresh state snapshot and action proof.
 * Both native buffers are owned only for this call and are wiped on every
 * exit path, including cancellation after either buffer has been acquired.
 */
internal suspend fun acknowledgeWithEphemeralState(
    snapshot: suspend () -> IdentityStateSnapshot?,
    signAction: suspend () -> ByteArray,
    send: suspend (IdentityStateSnapshot, ByteArray) -> Boolean
): Boolean {
    var state: IdentityStateSnapshot? = null
    var signature: ByteArray? = null
    return try {
        state = snapshot() ?: return false
        val actionSignature = signAction()
        signature = actionSignature
        if (actionSignature.size != ACK_SIGNATURE_BYTES) return false
        send(requireNotNull(state), actionSignature)
    } catch (error: CancellationException) {
        throw error
    } catch (_: Exception) {
        false
    } finally {
        state?.envelope?.fill(0)
        state?.identityPublicKey?.fill(0)
        state?.stateSignature?.fill(0)
        signature?.fill(0)
    }
}

/**
 * Relay-result variant of [acknowledgeWithEphemeralState]. A result is required
 * here because an ACK is a ratchet boundary: only an authenticated acceptance
 * allows the decrypted frame to become observable.
 */
internal suspend fun acknowledgeWithEphemeralStateResult(
    snapshot: suspend () -> IdentityStateSnapshot?,
    signAction: suspend () -> ByteArray,
    send: suspend (IdentityStateSnapshot, ByteArray) -> OutboundSendResult
): OutboundSendResult {
    val state = try {
        snapshot() ?: return OutboundSendResult.NOT_SENT
    } catch (_: Exception) {
        return OutboundSendResult.NOT_SENT
    }
    var signature: ByteArray? = null
    return try {
        val actionSignature = try {
            signAction()
        } catch (_: Exception) {
            return OutboundSendResult.NOT_SENT
        }
        signature = actionSignature
        if (actionSignature.size != ACK_SIGNATURE_BYTES) return OutboundSendResult.NOT_SENT
        try {
            send(state, actionSignature)
        } catch (_: CancellationException) {
            OutboundSendResult.AMBIGUOUS
        } catch (_: Exception) {
            OutboundSendResult.AMBIGUOUS
        }
    } finally {
        state.envelope.fill(0)
        state.identityPublicKey.fill(0)
        state.stateSignature.fill(0)
        signature?.fill(0)
    }
}

/** Tracks attachment jobs and the sole progress owner across session teardown. */
internal class AttachmentOperationCoordinator {
    private val jobs = Collections.synchronizedSet(mutableSetOf<Job>())
    private val latestOperationId = AtomicLong(0L)

    fun beginOperation(): Long = latestOperationId.incrementAndGet()

    fun invalidateOperations(): Long = latestOperationId.incrementAndGet()

    fun ownsProgress(operationId: Long): Boolean = operationId == latestOperationId.get()

    fun launch(
        scope: CoroutineScope,
        onCancelledBeforeStart: (() -> Unit)? = null,
        startImmediately: Boolean = true,
        block: suspend () -> Unit
    ): Job {
        val started = AtomicBoolean(false)
        val job = scope.launch(start = CoroutineStart.LAZY) {
            started.set(true)
            block()
        }
        jobs += job
        job.invokeOnCompletion {
            jobs.remove(job)
            if (!started.get()) onCancelledBeforeStart?.invoke()
        }
        if (startImmediately) job.start()
        return job
    }

    fun cancelAll() {
        val pending = synchronized(jobs) { jobs.toList() }
        pending.forEach(Job::cancel)
    }
}

/** One token per external picker invocation; stale callbacks are rejected. */
internal class ExternalSystemUiTokenGate {
    private var nextToken = 0L
    private var activeToken: Long? = null

    @Synchronized
    fun begin(): Long {
        nextToken = if (nextToken == Long.MAX_VALUE) 1L else nextToken + 1L
        activeToken = nextToken
        return nextToken
    }

    @Synchronized
    fun end(token: Long): Boolean {
        if (activeToken != token) return false
        activeToken = null
        return true
    }

    @Synchronized
    fun expire(token: Long): Boolean = end(token)

    @Synchronized
    fun activeToken(): Long? = activeToken

    @Synchronized
    fun clear() {
        activeToken = null
    }
}

internal fun canApplyCalculatorEvaluation(
    resultGeneration: Long,
    currentGeneration: Long,
    coroutineIsActive: Boolean
): Boolean = coroutineIsActive && resultGeneration == currentGeneration

internal fun shouldDeleteUploadedAttachment(
    uploadedAttachmentId: String?,
    metadataAccepted: Boolean,
    metadataAmbiguous: Boolean = false
): Boolean = uploadedAttachmentId != null && !metadataAccepted && !metadataAmbiguous

/** Deletes only a confirmed-unaccepted upload, using the session it captured. */
internal suspend fun deleteUnacceptedUploadedAttachment(
    session: NodeSession,
    uploadedAttachmentId: String?,
    metadataAccepted: Boolean,
    metadataAmbiguous: Boolean,
    delete: suspend (NodeSession, String) -> Boolean
): Boolean {
    val attachmentId = uploadedAttachmentId
        ?.takeIf { shouldDeleteUploadedAttachment(it, metadataAccepted, metadataAmbiguous) }
        ?: return false
    return withContext(NonCancellable) {
        runCatching { delete(session, attachmentId) }.getOrDefault(false)
    }
}

/**
 * Publishes an attachment only while the captured session remains current.
 * The repository callback is responsible for enforcing its epoch guard; the
 * second validity check closes the window after that guarded write returns.
 */
internal suspend fun saveAcceptedAttachmentIfCurrent(
    isCurrent: () -> Boolean,
    save: suspend () -> Boolean,
    wipe: () -> Unit
): Boolean {
    var completed = false
    var failure: Throwable? = null
    return try {
        if (!isCurrent()) return false
        if (!save() || !isCurrent()) return false
        completed = true
        true
    } catch (error: Throwable) {
        failure = error
        throw error
    } finally {
        if (!completed) {
            try {
                wipe()
            } catch (cleanupError: Throwable) {
                failure?.addSuppressed(cleanupError) ?: throw cleanupError
            }
        }
    }
}

internal fun isDecryptedAttachmentSizeValid(
    actualBytes: Long,
    expectedBytes: Long,
    maxBytes: Long
): Boolean = actualBytes > 0L && expectedBytes > 0L && actualBytes == expectedBytes && actualBytes <= maxBytes

internal const val ATTACHMENT_CIPHER_VERSION = 1
internal const val ATTACHMENT_KEY_BYTES = 32
private val ATTACHMENT_KEY_B64_REGEX = Regex("^[A-Za-z0-9_-]{43}$")

internal fun attachmentMetadataJson(message: Message, senderUsername: String): JSONObject =
    JSONObject()
        .put("kind", "attachment")
        .put("id", message.id)
        .put("sender", senderUsername)
        .put("attachment_id", message.attachmentId)
        .put("attachment_cipher_version", message.attachmentCipherVersion)
        .put("attachment_key_b64", message.attachmentKey?.let(::encodeAttachmentKey))
        .put("name", message.attachmentName)
        .put("media_type", message.mediaType)
        .put("mime_type", message.attachmentMimeType)
        .put("size_bytes", message.attachmentSizeBytes)
        .put("self_destruct_sec", message.selfDestructDurationSec)
        .put("absolute_expiry_sec", message.absoluteExpirySec)
        .put("one_time", message.oneTimeView)
        .put("delete_after_download", message.deleteAfterDownload)
        .apply { message.reactionShortcode?.let { put("reaction_shortcode", it) } }
        .apply { message.replyToMessageId?.let { put("reply_to_id", it) } }

/** The inner authenticated message must be bound to the relay envelope id. */
internal fun matchesAuthoritativeMessageId(
    payload: JSONObject?,
    authoritativeMessageId: String
): Boolean = payload != null &&
    MessageReplyPolicy.sanitizeMessageId(payload.optString("id")) == authoritativeMessageId

private fun encodeAttachmentKey(value: ByteArray): String =
    Base64.getUrlEncoder().withoutPadding().encodeToString(value)

@OptIn(ExperimentalCoroutinesApi::class)
class ChatViewModel(
    private val identityService: IIdentityService,
    private val nodeConfigService: INodeConfigService,
    private val messageRepository: IMessageRepository,
    private val messageSender: IMessageSender,
    private val chatTransport: IChatTransport,
    private val attachmentService: IEncryptedAttachmentService,
    private val disguiseManager: IDisguiseManager,
    private val appUpdateService: IAppUpdateService,
    private val payloadCipher: InMemoryPayloadCipher = InMemoryPayloadCipher()
) : ViewModel() {

    private data class SessionStamp(
        val generation: Long,
        val username: String,
        val identityPublicKey: ByteArray,
        val repositoryEpoch: ULong,
        /** Connection epoch captured with the session so queued frames cannot
         * cross a transport invalidation/reconnect boundary. */
        val connectionGeneration: Long
    ) {
        fun wipe() = identityPublicKey.fill(0)
    }

    private data class LeasedPrekeyReference(
        val chatId: String,
        val messageId: String,
        val recipientUsername: String,
        val prekeyId: String
    )

    private data class PreparedEncryptedMessage(
        val payload: EncryptedTransportPayload,
        val leases: List<LeasedPrekeyReference>
    )

    private val _currentScreen = MutableStateFlow<Screen>(Screen.Entrance)
    val currentScreen: StateFlow<Screen> = _currentScreen.asStateFlow()

    private val _currentUser = MutableStateFlow<User?>(null)
    val currentUser: StateFlow<User?> = _currentUser.asStateFlow()

    val serverStatus: StateFlow<ServerStatus> = chatTransport.getServerStatus()
        .stateIn(viewModelScope, SharingStarted.Lazily, ServerStatus("DISCONNECTED", "No node", 0))

    val presence: StateFlow<List<UserPresence>> = chatTransport.getPresence()
        .stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    private val _inviteCodeError = mutableStateOf<String?>(null)
    val inviteCodeError: State<String?> = _inviteCodeError

    private val _isVerifyingCode = mutableStateOf(false)
    val isVerifyingCode: State<Boolean> = _isVerifyingCode

    private val _showCamouflagePinPrompt = mutableStateOf(false)
    val showCamouflagePinPrompt: State<Boolean> = _showCamouflagePinPrompt

    private val _attachmentPreview = MutableStateFlow<DecryptedAttachment?>(null)
    val attachmentPreview: StateFlow<DecryptedAttachment?> = _attachmentPreview.asStateFlow()

    private val _attachmentError = mutableStateOf<String?>(null)
    val attachmentError: State<String?> = _attachmentError

    private val _attachmentUploadProgress = MutableStateFlow(AttachmentUploadProgress())
    val attachmentUploadProgress: StateFlow<AttachmentUploadProgress> = _attachmentUploadProgress.asStateFlow()

    private val _isLocked = MutableStateFlow(false)
    val isLocked: StateFlow<Boolean> = _isLocked.asStateFlow()

    private val _disguiseSettings = MutableStateFlow(DisguiseSettings())
    val disguiseSettings: StateFlow<DisguiseSettings> = _disguiseSettings.asStateFlow()

    private val _calculatorDisplay = MutableStateFlow("0")
    val calculatorDisplay: StateFlow<String> = _calculatorDisplay.asStateFlow()

    private val _availableUpdate = MutableStateFlow<AvailableAppUpdate?>(null)
    val availableUpdate: StateFlow<AvailableAppUpdate?> = _availableUpdate.asStateFlow()
    private val updatePromptPolicy = UpdatePromptPolicy()
    private var updateCheckInFlight = false

    private val sessionInactivityPolicy = SessionInactivityPolicy()
    private val _sessionSecurity = MutableStateFlow(SessionSecurityState())
    val sessionSecurity: StateFlow<SessionSecurityState> = _sessionSecurity.asStateFlow()

    private val directTrustStore = DirectChatTrustStore()
    private val _directTrust = MutableStateFlow(DirectTrustStatus())
    val directTrust: StateFlow<DirectTrustStatus> = _directTrust.asStateFlow()

    private val _roomCreationLimit = MutableStateFlow(DEFAULT_MAX_ROOMS_PER_USER)
    val roomCreationLimit: StateFlow<Int> = _roomCreationLimit.asStateFlow()

    private var retainSessionInBackground = false
    private var sessionInactivityTimeoutSec = DEFAULT_SESSION_INACTIVITY_SEC
    private val externalSystemUiTokens = ExternalSystemUiTokenGate()
    private var externalSystemUiTimeoutJob: Job? = null
    private var externalSystemUiGraceJob: Job? = null
    private var lastRemoteActivitySignalMs = 0L
    private var requestedDirectUsername: String? = null
    private var accountEntryJob: Job? = null
    private val sessionGeneration = AtomicLong(0L)
    // This gate covers only short local state transitions. Network claims and
    // provider writes remain cancellable and never hold up a local purge.
    private val attachmentSessionGate = Mutex()
    /** Serializes ratchet state transitions with decrypt/ack processing. */
    private val cryptoGate = Mutex()
    private val attachmentOperations = AttachmentOperationCoordinator()
    private val messageSendJobs = Collections.synchronizedSet(mutableSetOf<Job>())
    @Volatile
    private var calculatorEvaluationJob: Job? = null
    private val calculatorInputGeneration = AtomicLong(0L)
    private val calculatorEvaluationGate = Mutex()
    private val ownMessageIds = LinkedHashSet<String>()
    private val receivedFrameIds = linkedMapOf<String, String>()
    // All accesses occur on viewModelScope/Main: UI entry points, attachment jobs,
    // logout, and teardown. Network callbacks never touch these collections directly.
    private val activeAttachmentViews = mutableSetOf<String>()
    private val consumedOneTimeAttachments = mutableSetOf<String>()

    private fun rememberOwnMessageId(messageId: String) {
        ownMessageIds.add(messageId)
        while (ownMessageIds.size > MAX_OWN_MESSAGE_IDS) {
            val iterator = ownMessageIds.iterator()
            if (!iterator.hasNext()) break
            iterator.next()
            iterator.remove()
        }
    }

    val sessions: StateFlow<List<ChatSession>> = messageRepository.getChatSessions()
        .stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    private val _activeChatId = MutableStateFlow<String?>(null)
    val activeMessages: StateFlow<List<Message>> = _activeChatId.flatMapLatest { id ->
        if (id != null) messageRepository.getMessages(id) else flowOf(emptyList())
    }.stateIn(viewModelScope, SharingStarted.Lazily, emptyList())

    private suspend fun acknowledgeIncoming(
        incoming: IncomingTransportPayload,
        stamp: SessionStamp
    ): OutboundSendResult {
        if (!isSessionStampValid(stamp)) {
            return OutboundSendResult.AMBIGUOUS
        }
        val result = acknowledgeWithEphemeralStateResult(
            snapshot = { payloadCipher.stateSnapshot() },
            signAction = {
                payloadCipher.signAcknowledgement(
                    incoming.chatId,
                    incoming.messageId,
                    incoming.senderUsername,
                    incoming.prekeyId
                )
            },
            send = { state, signature ->
                chatTransport.acknowledgeMessage(
                    incoming.chatId,
                    incoming.messageId,
                    incoming.senderUsername,
                    state,
                    incoming.prekeyId,
                    signature,
                    stamp.connectionGeneration
                )
            }
        )
        return if (result == OutboundSendResult.ACCEPTED &&
            !isSessionStampValid(stamp)
        ) {
            OutboundSendResult.AMBIGUOUS
        } else {
            result
        }
    }

    /** Decrypt, acknowledge, and publish one frame under the same ratchet gate. */
    private suspend fun processIncomingPayload(incoming: IncomingTransportPayload) {
        // Reject a payload from an invalidated socket before entering native
        // decrypt. The transport drains queued ciphertext on invalidation, but
        // a collector may already own a payload when that race occurs.
        if (incoming.connectionGeneration != chatTransport.currentConnectionGeneration()) {
            return
        }
        cryptoGate.withLock {
            val stamp = captureSessionStamp() ?: return@withLock
            if (incoming.connectionGeneration != stamp.connectionGeneration) {
                stamp.wipe()
                return@withLock
            }
            val replayKey = "${incoming.chatId}\u0000${incoming.senderUsername}\u0000${incoming.messageId}"
            val directoryEvidenceKey =
                "${incoming.directoryNodeId}\u0000${incoming.directoryRevision}\u0000${incoming.directoryDigest}"
            try {
                when (chatTransport.directoryEvidenceStatus(
                    DirectoryStamp(
                        incoming.directoryNodeId,
                        incoming.directoryRevision,
                        incoming.directoryDigest
                    )
                )) {
                    DirectoryEvidenceStatus.KNOWN -> Unit
                    DirectoryEvidenceStatus.UNKNOWN_OLD -> return@withLock
                    DirectoryEvidenceStatus.CONFLICT -> {
                        failClosedForIncomingAckFailure(stamp)
                        return@withLock
                    }
                }
                val processedDirectoryEvidence = receivedFrameIds[replayKey]
                if (processedDirectoryEvidence != null) {
                    if (processedDirectoryEvidence != directoryEvidenceKey) {
                        failClosedForIncomingAckFailure(stamp)
                        return@withLock
                    }
                    val acknowledgement = acknowledgeIncoming(incoming, stamp)
                    if (acknowledgement != OutboundSendResult.ACCEPTED) {
                        failClosedForIncomingAckFailure(stamp)
                    }
                    return@withLock
                }
                val decryption = try {
                    payloadCipher.decrypt(incoming, stamp.username)
                } catch (_: FatalPayloadCipherException) {
                    // Native decrypt succeeded but its JVM state wrapper could
                    // not be installed. The cipher has been cleared; revoke
                    // this session instead of treating the state loss as a
                    // routine unauthenticated/drop case.
                    failClosedForIncomingAckFailure(stamp)
                    return@withLock
                } catch (_: Exception) {
                    // Authentication/decryption rejection is an ordinary drop.
                    return@withLock
                }
                val plainBytes = decryption.plaintext
                try {
                    if (plainBytes.size > MAX_DECRYPTED_MESSAGE_BYTES) {
                        failClosedForIncomingAckFailure(stamp)
                        return@withLock
                    }
                    val decryptedContent = String(plainBytes, StandardCharsets.UTF_8)
                    val decryptedStamp = runCatching { JSONObject(decryptedContent) }.getOrNull()
                    if (decryptedStamp == null || !matchesDirectoryStamp(decryptedStamp, incoming)) {
                        failClosedForIncomingAckFailure(stamp)
                        return@withLock
                    }
                    val acknowledgement = acknowledgeIncoming(incoming, stamp)
                    if (acknowledgement != OutboundSendResult.ACCEPTED) {
                        failClosedForIncomingAckFailure(stamp)
                        return@withLock
                    }
                    if (!isSessionStampValid(stamp)) {
                        return@withLock
                    }
                    val control = runCatching { JSONObject(decryptedContent) }.getOrNull()
                    if (control?.optString("kind") == "read_receipt") {
                        if (!matchesAuthoritativeMessageId(control, incoming.messageId)) return@withLock
                        val targetId = MessageReplyPolicy.sanitizeMessageId(control.optString("message_id"))
                        if (targetId != null && targetId in ownMessageIds) {
                            if (!isSessionStampValid(stamp)) {
                                return@withLock
                            }
                            if (!mutateRepositoryIfCurrent(stamp) {
                                    messageRepository.markAsReadIfCurrent(
                                        stamp.repositoryEpoch,
                                        incoming.chatId,
                                        targetId
                                    )
                                }
                            ) {
                                return@withLock
                            }
                        }
                        if (!isSessionStampValid(stamp)) {
                            return@withLock
                        }
                        rememberReceivedFrame(replayKey, directoryEvidenceKey)
                        return@withLock
                    }
                    val message = parseIncomingMessage(
                        incoming.chatId,
                        incoming.messageId,
                        decryptedContent,
                        incoming.senderUsername,
                        incoming.senderPublicKey
                    ) ?: return@withLock
                    if (!isSessionStampValid(stamp)) {
                        wipeMessageSecrets(message)
                        return@withLock
                    }
                    if (!mutateRepositoryIfCurrent(stamp) {
                            messageRepository.saveMessageIfCurrent(
                                stamp.repositoryEpoch,
                                incoming.chatId,
                                message
                            )
                        }
                    ) {
                        wipeMessageSecrets(message)
                        return@withLock
                    }
                    rememberReceivedFrame(replayKey, directoryEvidenceKey)
                } finally {
                    plainBytes.fill(0)
                }
            } finally {
                stamp.wipe()
            }
        }
    }

    init {
        _disguiseSettings.value = DisguiseSettings(
            isDisguised = disguiseManager.isDisguiseEnabled()
        )
        _isLocked.value = disguiseManager.isDisguiseEnabled()

        viewModelScope.launch {
            chatTransport.getIncomingWipeCommands().collect { generation ->
                // A purge command is scoped to the transport generation that
                // produced it. A delayed command from a prior socket must not
                // wipe a newly authenticated session.
                if (generation == chatTransport.currentConnectionGeneration()) {
                    executeLocalMemoryPurge()
                }
            }
        }

        viewModelScope.launch {
            serverStatus.collect { status ->
                if (status.state != "CONNECTED") {
                    directTrustStore.clear()
                    cancelAttachmentOperations()
                    activeAttachmentViews.clear()
                    consumedOneTimeAttachments.clear()
                    replaceAttachmentPreview(null)
                }
                refreshDirectTrust()
            }
        }

        viewModelScope.launch {
            presence.collect { refreshDirectTrust() }
        }

        viewModelScope.launch {
            sessions.collect { refreshDirectTrust() }
        }

        viewModelScope.launch {
            chatTransport.getIncomingPayloads().collect { incoming ->
                try {
                    processIncomingPayload(incoming)
                } finally {
                    wipeIncomingPayload(incoming)
                }
            }
        }

        viewModelScope.launch {
            chatTransport.getRoomChanges().collect { change ->
                processRoomChange(change)
            }
        }

        viewModelScope.launch {
            while (isActive) {
                delay(SESSION_WATCHDOG_INTERVAL_MS)
                if (!expireSessionIfNeeded()) updateSessionSecurityState()
            }
        }
    }

    fun navigateTo(screen: Screen) {
        _currentScreen.value = screen
        if (screen is Screen.Chat) {
            _activeChatId.value = screen.sessionId
            refreshDirectTrust()
            val connectionGeneration = chatTransport.currentConnectionGeneration()
            viewModelScope.launch {
                chatTransport.joinChat(screen.sessionId, connectionGeneration)
            }
        } else {
            _activeChatId.value = null
        }
    }

    fun checkForAppUpdate() {
        val now = elapsedRealtimeMs()
        if (
            _isLocked.value ||
            _availableUpdate.value != null ||
            updateCheckInFlight ||
            !updatePromptPolicy.shouldCheck(now)
        ) {
            return
        }
        updateCheckInFlight = true
        viewModelScope.launch {
            try {
                val result = runCatching { appUpdateService.findAvailableUpdate() }
                val completedAt = elapsedRealtimeMs()
                result.onSuccess { update ->
                    updatePromptPolicy.markChecked(completedAt)
                    _availableUpdate.value = update
                }.onFailure {
                    updatePromptPolicy.markFailed(completedAt)
                }
            } finally {
                updateCheckInFlight = false
            }
        }
    }

    fun cancelAvailableUpdate() {
        updatePromptPolicy.cancelForProcess()
        _availableUpdate.value = null
    }

    fun remindAvailableUpdateLater() {
        updatePromptPolicy.remindLater(elapsedRealtimeMs())
        _availableUpdate.value = null
    }

    fun acceptAvailableUpdate() {
        updatePromptPolicy.cancelForProcess()
        _availableUpdate.value = null
    }

    fun clearAccountError() {
        _inviteCodeError.value = null
    }

    fun submitAccount(
        code: String,
        nodeUrl: String,
        password: String,
        rememberSession: Boolean
    ) {
        if (!canStartAccountEntry(accountEntryJob)) return
        val job = viewModelScope.launch(start = CoroutineStart.LAZY) {
            var validation: IdentityValidationResult? = null
            var installedSession = false
            try {
                _isVerifyingCode.value = true
                _inviteCodeError.value = null

                val endpoint = nodeConfigService.normalizeNodeUrl(nodeUrl).getOrElse {
                    _inviteCodeError.value = "Wrong information."
                    return@launch
                }

                ensureActive()
                validation = identityService.enterAccount(code, password, endpoint)
                // Do not install an identity returned by a request that was canceled while
                // its response was being delivered.
                ensureActive()
                val result = requireNotNull(validation)
                if (canInstallAccountEntryResult(currentCoroutineContext().isActive, result)) {
                    val publicKey = result.publicKey ?: run {
                        _inviteCodeError.value = "Wrong information."
                        payloadCipher.clear()
                        return@launch
                    }
                    val prekeyId = result.prekeyId ?: run {
                        publicKey.fill(0)
                        _inviteCodeError.value = "Wrong information."
                        payloadCipher.clear()
                        return@launch
                    }
                    val nodeId = result.nodeId ?: endpoint.displayHost
                    val token = requireNotNull(result.token)
                    val identity = User(
                        username = result.username ?: "AbyssalUser",
                        publicKey = publicKey,
                        prekeyId = prekeyId
                    )
                    ensureActive()
                    identityService.setCurrentUser(identity)
                    nodeConfigService.setActiveSession(
                        NodeSession(endpoint, token, nodeId, result.maxRoomsPerUser)
                    )
                    installedSession = true
                    _currentUser.value = identity
                    _roomCreationLimit.value = result.maxRoomsPerUser
                    retainSessionInBackground = rememberSession
                    sessionInactivityTimeoutSec = result.sessionInactivitySec
                    sessionInactivityPolicy.start(sessionInactivityTimeoutSec * 1000L)
                    updateSessionSecurityState()
                    _isLocked.value = false
                    if (result.created) {
                        // A new account has no camouflage verifier yet. Keep the
                        // normal launcher active until the mandatory prompt saves
                        // and verifies the PIN material atomically.
                        _disguiseSettings.value = DisguiseSettings(isDisguised = false)
                        _isLocked.value = false
                        _showCamouflagePinPrompt.value = true
                    }
                    chatTransport.connect()
                    val connectionGeneration = chatTransport.currentConnectionGeneration()
                    joinAvailableSessions(connectionGeneration)
                    ensureActive()
                    _currentScreen.value = Screen.Dashboard
                } else {
                    result.publicKey?.fill(0)
                    payloadCipher.clear()
                    _inviteCodeError.value = "Wrong information."
                }
            } catch (error: CancellationException) {
                // The logout path cancels account entry before redacting local state. If
                // no session was installed, wipe the returned native key here.
                if (!installedSession) {
                    validation?.publicKey?.fill(0)
                    payloadCipher.clear()
                }
                throw error
            } catch (_: Exception) {
                if (installedSession) {
                    try {
                        // Transport/session setup failed after installation. Roll back the
                        // session from this job; the self-job guard avoids cancel-and-join.
                        logoutLocal(revokeRemote = true)
                    } finally {
                        installedSession = false
                    }
                } else {
                    validation?.publicKey?.fill(0)
                    payloadCipher.clear()
                }
                _inviteCodeError.value = "Wrong information."
            } finally {
                if (!installedSession) validation?.publicKey?.fill(0)
                _isVerifyingCode.value = false
                if (accountEntryJob === currentCoroutineContext()[Job]) {
                    accountEntryJob = null
                }
            }
        }
        accountEntryJob = job
        job.start()
    }

    fun sendMessage(content: String, selfDestructSec: Int, replyToMessageId: String? = null) {
        val chatId = _activeChatId.value ?: return
        if (serverStatus.value.state != "CONNECTED") return
        if (content.isBlank() || content.length > MAX_TEXT_MESSAGE_CHARS) return
        if (!isDirectChatTrusted(chatId)) return
        val stamp = captureSessionStamp() ?: return
        launchMessageOperation(stamp) sendMessageOperation@{ capturedStamp ->
                if (!isSessionStampValid(capturedStamp)) return@sendMessageOperation
                val effectiveTimerSec = effectiveRetentionSec(chatId, selfDestructSec)
                val absoluteExpirySec = effectiveAbsoluteExpirySec(chatId, null)
                val message = Message(
                    id = UUID.randomUUID().toString(),
                    sender = "You",
                    receiver = if (chatId.startsWith("dm_")) chatId.removePrefix("dm_") else null,
                    content = content,
                    timestampMs = System.currentTimeMillis(),
                    selfDestructDurationSec = effectiveTimerSec,
                    absoluteExpirySec = absoluteExpirySec,
                    replyToMessageId = validReplyTarget(replyToMessageId)
                )
                if (!isSessionStampValid(capturedStamp)) return@sendMessageOperation
                val remoteRecipients = recipientIdentities(chatId, includeSelf = false)
                if (!isSessionStampValid(capturedStamp)) return@sendMessageOperation
                if (isLocalOnlyForum(chatId, remoteRecipients)) {
                    if (!mutateRepositoryIfCurrent(capturedStamp) {
                            messageRepository.saveMessageIfCurrent(
                                capturedStamp.repositoryEpoch,
                                chatId,
                                message
                            )
                        }
                    ) return@sendMessageOperation
                    rememberOwnMessageId(message.id)
                    return@sendMessageOperation
                }
                val result = sendEncryptedMetadata(
                    chatId = chatId,
                    messageId = message.id,
                    metadata = textMetadata(message, capturedStamp.username),
                    recipientsOverride = remoteRecipients,
                    sessionStamp = capturedStamp
                )
                if (result == OutboundSendResult.ACCEPTED && isSessionStampValid(capturedStamp)) {
                    if (!mutateRepositoryIfCurrent(capturedStamp) {
                            messageRepository.saveMessageIfCurrent(
                                capturedStamp.repositoryEpoch,
                                chatId,
                                message
                            )
                        }
                    ) return@sendMessageOperation
                    rememberOwnMessageId(message.id)
                }
        }
    }

    fun sendAttachment(
        mediaType: String,
        fileName: String,
        mimeType: String,
        bytes: ByteArray,
        selfDestructSec: Int,
        oneTimeView: Boolean,
        deleteAfterDownload: Boolean,
        replyToMessageId: String? = null,
        reactionShortcode: String? = null
    ) {
        val chatId = _activeChatId.value ?: run {
            bytes.fill(0)
            return
        }
        if (serverStatus.value.state != "CONNECTED") {
            _attachmentError.value = "Wrong information."
            bytes.fill(0)
            return
        }
        if (!isDirectChatTrusted(chatId)) {
            _attachmentError.value = "Verify this direct chat's safety number before sending."
            bytes.fill(0)
            return
        }
        val effectiveTimerSec = effectiveRetentionSec(chatId, selfDestructSec, mediaType)
        val absoluteExpirySec = effectiveAbsoluteExpirySec(chatId, mediaType)
        if (bytes.isEmpty() ||
            bytes.size.toLong() > attachmentSelectionLimitBytes(mediaType) ||
            !isMediaAllowed(chatId, mediaType)
        ) {
            _attachmentError.value = "Wrong information."
            bytes.fill(0)
            return
        }
        val remoteRecipients = recipientIdentities(chatId, includeSelf = false)
        if (isLocalOnlyForum(chatId, remoteRecipients)) {
            _attachmentError.value = "Wrong information."
            bytes.fill(0)
            return
        }
        val safeReactionShortcode = reactionShortcode?.let {
            MessageAttentionPolicy.validatedReactionShortcode(it, fileName, mimeType)
                ?: run {
                    _attachmentError.value = "Wrong information."
                    bytes.fill(0)
                    return
                }
        }
        val capturedSession = nodeConfigService.getActiveSession() ?: run {
            bytes.fill(0)
            return
        }
        val sessionStamp = captureSessionStamp() ?: run {
            bytes.fill(0)
            return
        }
        val operationId = attachmentOperations.beginOperation()
        val operationActive = AtomicBoolean(true)
        val wipeUploadState = {
            operationActive.set(false)
            bytes.fill(0)
            sessionStamp.wipe()
            if (attachmentOperations.ownsProgress(operationId)) {
                _attachmentUploadProgress.value = AttachmentUploadProgress()
            }
        }

        launchAttachmentOperation(
            onCancelledBeforeStart = wipeUploadState,
            block = uploadAttachmentOperation@{
            var attachmentKey: ByteArray? = null
            var encryptedBlob: ByteArray? = null
            var messageToWipe: Message? = null
            var uploadedAttachmentId: String? = null
            var metadataAccepted = false
            var metadataAmbiguous = false
            try {
                if (!isAttachmentSessionCurrent(
                        capturedSession,
                        sessionStamp,
                        operationActive
                    )
                ) return@uploadAttachmentOperation
                if (isAttachmentProgressCurrent(
                        operationId,
                        capturedSession,
                        sessionStamp,
                        operationActive
                    )
                ) {
                    _attachmentError.value = null
                    _attachmentUploadProgress.value = AttachmentUploadProgress(
                        active = true,
                        fileName = fileName.ifBlank { "attachment" },
                        mediaType = mediaType,
                        totalBytes = bytes.size.toLong()
                    )
                }
                val metadataRecipients = recipientIdentities(chatId, includeSelf = false)
                if (!isAttachmentSessionCurrent(
                        capturedSession,
                        sessionStamp,
                        operationActive
                    ) ||
                    metadataRecipients == null ||
                    isLocalOnlyForum(chatId, metadataRecipients)
                ) {
                    if (isAttachmentProgressCurrent(
                            operationId,
                            capturedSession,
                            sessionStamp,
                            operationActive
                        )
                    ) _attachmentError.value = "Wrong information."
                    return@uploadAttachmentOperation
                }
                val normalizedMediaType = mediaType.uppercase(Locale.ROOT)
                val messageId = UUID.randomUUID().toString()
                if (!isAttachmentSessionCurrent(
                        capturedSession,
                        sessionStamp,
                        operationActive
                    )
                ) return@uploadAttachmentOperation
                val attachmentPayload = try {
                    encryptAttachmentBlob(
                        chatId = chatId,
                        messageId = messageId,
                        senderUsername = sessionStamp.username,
                        mediaType = normalizedMediaType,
                        plaintext = bytes
                    )
                } catch (error: CancellationException) {
                    throw error
                } catch (_: Exception) {
                    if (isAttachmentProgressCurrent(
                            operationId,
                            capturedSession,
                            sessionStamp,
                            operationActive
                        )
                    ) _attachmentError.value = "Wrong information."
                    return@uploadAttachmentOperation
                }
                val key = attachmentPayload.key
                val blob = attachmentPayload.blob
                attachmentKey = key
                encryptedBlob = blob
                if (!isValidAttachmentCiphertext(
                        version = attachmentPayload.version.toInt(),
                        key = key,
                        blob = blob,
                        mediaType = normalizedMediaType
                    )
                ) {
                    if (isAttachmentProgressCurrent(
                            operationId,
                            capturedSession,
                            sessionStamp,
                            operationActive
                        )
                    ) _attachmentError.value = "Wrong information."
                    return@uploadAttachmentOperation
                }
                if (!isAttachmentSessionCurrent(
                        capturedSession,
                        sessionStamp,
                        operationActive
                    )
                ) return@uploadAttachmentOperation
                try {
                    val upload = attachmentService.uploadEncryptedAttachment(
                        session = capturedSession,
                        chatId = chatId,
                        mediaType = normalizedMediaType,
                        encryptedBytes = blob,
                        oneTimeView = oneTimeView,
                        deleteAfterDownload = deleteAfterDownload,
                        ttlSec = absoluteExpirySec,
                        onProgress = { sent, total ->
                            if (isAttachmentProgressCurrent(
                                    operationId,
                                    capturedSession,
                                    sessionStamp,
                                    operationActive
                                )
                            ) {
                                _attachmentUploadProgress.value = AttachmentUploadProgress(
                                    active = true,
                                    fileName = fileName.ifBlank { "attachment" },
                                    mediaType = normalizedMediaType,
                                    bytesSent = sent.coerceAtMost(total),
                                    totalBytes = total
                                )
                            }
                        }
                    )
                    val attachmentId = upload.attachmentId?.let(::normalizeAttachmentId)
                    uploadedAttachmentId = attachmentId
                    if (!upload.accepted || attachmentId == null) {
                        if (isAttachmentProgressCurrent(
                                operationId,
                                capturedSession,
                                sessionStamp,
                                operationActive
                            )
                        ) _attachmentError.value = "Wrong information."
                        return@uploadAttachmentOperation
                    }
                    if (!isAttachmentSessionCurrent(
                            capturedSession,
                            sessionStamp,
                            operationActive
                        )
                    ) return@uploadAttachmentOperation

                    val message = attachmentMessage(
                        messageId = messageId,
                        sender = "You",
                        receiver = if (chatId.startsWith("dm_")) chatId.removePrefix("dm_") else null,
                        attachmentId = attachmentId,
                        attachmentCipherVersion = attachmentPayload.version.toInt(),
                        attachmentKey = key,
                        mediaType = normalizedMediaType,
                        fileName = fileName,
                        mimeType = mimeType,
                        sizeBytes = bytes.size.toLong(),
                        selfDestructSec = effectiveTimerSec,
                        absoluteExpirySec = absoluteExpirySec,
                        oneTimeView = oneTimeView,
                        deleteAfterDownload = deleteAfterDownload,
                        replyToMessageId = validReplyTarget(replyToMessageId),
                        reactionShortcode = safeReactionShortcode,
                        senderPublicKey = sessionStamp.identityPublicKey.copyOf()
                    )
                    messageToWipe = message
                    val result = sendEncryptedMetadata(
                        chatId = chatId,
                        messageId = message.id,
                        metadata = attachmentMetadataJson(message, sessionStamp.username).toString(),
                        recipientsOverride = metadataRecipients,
                        sessionStamp = sessionStamp
                    )
                    metadataAmbiguous = result == OutboundSendResult.AMBIGUOUS
                    if (result == OutboundSendResult.ACCEPTED) {
                        metadataAccepted = true
                        if (!isAttachmentSessionCurrent(
                                capturedSession,
                                sessionStamp,
                                operationActive
                            )
                        ) {
                            wipeMessageSecrets(message)
                            return@uploadAttachmentOperation
                        }
                        if (!saveAcceptedAttachmentIfCurrent(
                                isCurrent = {
                                    isAttachmentSessionCurrent(
                                        capturedSession,
                                        sessionStamp,
                                        operationActive
                                    )
                                },
                                save = {
                                    mutateRepositoryIfCurrent(sessionStamp) {
                                        messageRepository.saveMessageIfCurrent(
                                            sessionStamp.repositoryEpoch,
                                            chatId,
                                            message
                                        )
                                    }
                                },
                                wipe = { wipeMessageSecrets(message) }
                            )
                        ) {
                            if (isAttachmentProgressCurrent(
                                    operationId,
                                    capturedSession,
                                    sessionStamp,
                                    operationActive
                                )
                            ) _attachmentError.value = "Wrong information."
                            return@uploadAttachmentOperation
                        }
                        rememberOwnMessageId(message.id)
                    } else {
                        wipeMessageSecrets(message)
                        if (isAttachmentProgressCurrent(
                                operationId,
                                capturedSession,
                                sessionStamp,
                                operationActive
                            )
                        ) _attachmentError.value = "Wrong information."
                    }
                } finally {
                    encryptedBlob.fill(0)
                }
            } finally {
                // Stop late OkHttp progress callbacks before any non-cancellable
                // remote cleanup begins.
                operationActive.set(false)
                deleteUnacceptedUploadedAttachment(
                    session = capturedSession,
                    uploadedAttachmentId = uploadedAttachmentId,
                    metadataAccepted = metadataAccepted,
                    metadataAmbiguous = metadataAmbiguous,
                    delete = { session, attachmentId ->
                        attachmentService.deleteUploadedAttachment(session, attachmentId)
                    }
                )
                messageToWipe?.let(::wipeMessageSecrets)
                attachmentKey?.fill(0)
                encryptedBlob?.fill(0)
                wipeUploadState()
            }
            }
        )
    }

    /** Session validity is independent of which upload currently owns progress. */
    private fun isAttachmentSessionCurrent(
        session: NodeSession,
        stamp: SessionStamp,
        operationActive: AtomicBoolean
    ): Boolean = operationActive.get() &&
        serverStatus.value.state == "CONNECTED" &&
        isSessionStampValid(stamp) &&
        nodeConfigService.getActiveSession() == session

    private fun isAttachmentProgressCurrent(
        operationId: Long,
        session: NodeSession,
        stamp: SessionStamp,
        operationActive: AtomicBoolean
    ): Boolean = attachmentOperations.ownsProgress(operationId) &&
        isAttachmentSessionCurrent(session, stamp, operationActive)

    private fun launchAttachmentOperation(
        onCancelledBeforeStart: (() -> Unit)? = null,
        block: suspend () -> Unit
    ): Job = attachmentOperations.launch(
        scope = viewModelScope,
        onCancelledBeforeStart = onCancelledBeforeStart,
        block = block
    )

    private fun cancelAttachmentOperations() = attachmentOperations.cancelAll()

    private fun cancelMessageSends() {
        val jobs = synchronized(messageSendJobs) {
            messageSendJobs.toList().also { messageSendJobs.clear() }
        }
        jobs.forEach(Job::cancel)
    }

    private fun launchMessageOperation(
        stamp: SessionStamp,
        block: suspend (SessionStamp) -> Unit
    ): Job? {
        val job = viewModelScope.launch(start = CoroutineStart.LAZY) {
            try {
                block(stamp)
            } finally {
                stamp.wipe()
            }
        }
        job.invokeOnCompletion { messageSendJobs.remove(job) }
        synchronized(messageSendJobs) {
            if (messageSendJobs.size >= MAX_MESSAGE_SEND_JOBS) {
                stamp.wipe()
                job.cancel()
                return null
            }
            messageSendJobs.add(job)
        }
        job.start()
        return job
    }

    fun viewAttachment(message: Message) {
        val chatId = _activeChatId.value ?: return
        val attachmentId = message.attachmentId ?: return
        if (activeMessages.value.none { it.id == message.id && it.attachmentId == attachmentId }) return
        if (!isDirectChatTrusted(chatId)) {
            _attachmentError.value = "Verify this direct chat's safety number before opening attachments."
            return
        }
        val capturedSession = nodeConfigService.getActiveSession() ?: return
        val generation = sessionGeneration.get()
        val connectionGeneration = chatTransport.currentConnectionGeneration()
        if (!activeAttachmentViews.add(attachmentId)) return
        if (message.oneTimeView && !consumedOneTimeAttachments.add(attachmentId)) {
            activeAttachmentViews.remove(attachmentId)
            return
        }
        launchAttachmentOperation viewAttachmentOperation@{
            var plaintext: ByteArray? = null
            var previewInstalled = false
            try {
                if (!isAttachmentGenerationCurrent(capturedSession, generation, connectionGeneration)) {
                    return@viewAttachmentOperation
                }
                _attachmentError.value = null
                val downloaded = attachmentService.downloadEncryptedAttachment(
                    session = capturedSession,
                    attachmentId = attachmentId,
                    mediaType = message.mediaType ?: "FILE",
                    expectedPlaintextBytes = message.attachmentSizeBytes
                )
                plaintext = downloaded?.let { encrypted ->
                    decryptAndCompleteAttachment(
                        downloaded = encrypted,
                        decrypt = {
                            if (!isAttachmentGenerationCurrent(capturedSession, generation, connectionGeneration)) null
                            else decryptAttachment(chatId, message, encrypted.bytes)
                        },
                        complete = { claim ->
                            if (!isAttachmentGenerationCurrent(capturedSession, generation, connectionGeneration)) false
                            else attachmentService.completeAttachmentDownload(
                                capturedSession,
                                attachmentId,
                                claim
                            )
                        },
                        release = { claim ->
                            attachmentService.releaseAttachmentDownloadClaim(
                                capturedSession,
                                attachmentId,
                                claim
                            )
                        }
                    )
                }
                if (plaintext == null) {
                    if (message.oneTimeView) consumedOneTimeAttachments.remove(attachmentId)
                    _attachmentError.value = "Wrong information."
                    return@viewAttachmentOperation
                }
                val installed = attachmentSessionGate.withLock {
                    if (!isAttachmentGenerationCurrent(capturedSession, generation, connectionGeneration)) {
                        false
                    } else {
                        replaceAttachmentPreview(
                            DecryptedAttachment(
                                messageId = message.id,
                                name = message.attachmentName ?: "attachment",
                                mediaType = message.mediaType ?: "FILE",
                                mimeType = message.attachmentMimeType ?: "application/octet-stream",
                                bytes = requireNotNull(plaintext),
                                oneTimeView = message.oneTimeView
                            )
                        )
                        plaintext = null
                        previewInstalled = true
                        markMessageAsRead(message.id)
                        if (message.oneTimeView) {
                            messageRepository.forgetAttachmentKey(chatId, message.id)
                        }
                        true
                    }
                }
                if (!installed) return@viewAttachmentOperation
            } finally {
                plaintext?.fill(0)
                if (message.oneTimeView && !previewInstalled) consumedOneTimeAttachments.remove(attachmentId)
                activeAttachmentViews.remove(attachmentId)
            }
        }
    }

    fun saveAttachment(message: Message, outputUri: Uri) {
        val chatId = _activeChatId.value ?: return
        val attachmentId = message.attachmentId ?: return
        if (activeMessages.value.none { it.id == message.id && it.attachmentId == attachmentId }) return
        if (!isDirectChatTrusted(chatId)) {
            _attachmentError.value = "Verify this direct chat's safety number before exporting attachments."
            return
        }
        if (!AttachmentSavePolicy.canSave(message)) return
        val capturedSession = nodeConfigService.getActiveSession() ?: return
        val generation = sessionGeneration.get()
        val connectionGeneration = chatTransport.currentConnectionGeneration()
        launchAttachmentOperation saveAttachmentOperation@{
            _attachmentError.value = null
            var temporaryBytes: ByteArray? = null
            try {
                if (!isAttachmentGenerationCurrent(capturedSession, generation, connectionGeneration)) {
                    return@saveAttachmentOperation
                }
                val cachedAttachment = _attachmentPreview.value?.takeIf { it.messageId == message.id }
                val attachment = cachedAttachment ?: run {
                    val downloaded = attachmentService.downloadEncryptedAttachment(
                        session = capturedSession,
                        attachmentId = attachmentId,
                        mediaType = message.mediaType ?: "FILE",
                        expectedPlaintextBytes = message.attachmentSizeBytes
                    )
                    val bytes = downloaded?.let { encrypted ->
                        decryptAndCompleteAttachment(
                            downloaded = encrypted,
                            decrypt = {
                                if (!isAttachmentGenerationCurrent(capturedSession, generation, connectionGeneration)) null
                                else decryptAttachment(chatId, message, encrypted.bytes)
                            },
                            complete = { claim ->
                                if (!isAttachmentGenerationCurrent(capturedSession, generation, connectionGeneration)) false
                                else attachmentService.completeAttachmentDownload(
                                    capturedSession,
                                    attachmentId,
                                    claim
                                )
                            },
                            release = { claim ->
                                attachmentService.releaseAttachmentDownloadClaim(
                                    capturedSession,
                                    attachmentId,
                                    claim
                                )
                            }
                        )
                    }
                    if (bytes == null) {
                        _attachmentError.value = "Wrong information."
                        return@saveAttachmentOperation
                    }
                    DecryptedAttachment(
                        messageId = message.id,
                        name = message.attachmentName ?: "attachment",
                        mediaType = message.mediaType ?: "FILE",
                        mimeType = message.attachmentMimeType ?: "application/octet-stream",
                        bytes = bytes,
                        oneTimeView = false
                    )
                }
                if (attachment.bytes.isEmpty()) {
                    _attachmentError.value = "Wrong information."
                    return@saveAttachmentOperation
                }
                if (cachedAttachment == null) temporaryBytes = attachment.bytes
                if (!isAttachmentGenerationCurrent(capturedSession, generation, connectionGeneration)) {
                    return@saveAttachmentOperation
                }
                val saved = attachmentService.saveDecryptedAttachment(attachment, outputUri)
                if (!saved) {
                    _attachmentError.value = "Wrong information."
                    return@saveAttachmentOperation
                }
                if (cachedAttachment != null) replaceAttachmentPreview(null)
                markMessageAsRead(message.id)
            } finally {
                temporaryBytes?.fill(0)
            }
        }
    }

    fun dismissAttachmentPreview() {
        replaceAttachmentPreview(null)
    }

    fun markMessageAsRead(messageId: String) {
        val chatId = _activeChatId.value ?: return
        if (sessions.value.none { it.id == chatId }) return
        val trusted = isDirectChatTrusted(chatId)
        val stamp = captureSessionStamp() ?: return
        launchMessageOperation(stamp) markReadOperation@{ capturedStamp ->
            if (!isSessionStampValid(capturedStamp)) return@markReadOperation
            val message = activeMessages.value.firstOrNull { it.id == messageId }
            if (!mutateRepositoryIfCurrent(capturedStamp) {
                    messageRepository.markAsReadIfCurrent(
                        capturedStamp.repositoryEpoch,
                        chatId,
                        messageId
                    )
                }
            ) return@markReadOperation
            if (trusted && isDirectChatTrusted(chatId) && message != null &&
                message.sender != "You" && serverStatus.value.state == "CONNECTED"
            ) {
                val receiptId = UUID.randomUUID().toString()
                val metadata = JSONObject()
                    .put("kind", "read_receipt")
                    .put("id", receiptId)
                    .put("message_id", messageId)
                    .toString()
                sendEncryptedMetadata(
                    chatId = chatId,
                    messageId = receiptId,
                    metadata = metadata,
                    sessionStamp = capturedStamp
                )
            }
        }
    }

    fun executeClearAll() {
        val stamp = captureSessionStamp() ?: return
        launchMessageOperation(stamp) clearAllOperation@{ capturedStamp ->
            if (!isSessionStampValid(capturedStamp)) return@clearAllOperation
            chatTransport.broadcastGlobalWipe(capturedStamp.connectionGeneration)
            // A successful global wipe can close the socket before this
            // continuation resumes. Preserve the local wipe only for the same
            // app account, never for a replacement login.
            if (!isAccountSessionStampValid(capturedStamp)) return@clearAllOperation
            executeLocalMemoryPurge()
        }
    }

    fun createForum(
        name: String,
        readExpirySec: Int,
        overallExpirySec: Int,
        enforceTextAbsoluteExpiry: Boolean,
        allowImages: Boolean,
        allowVideos: Boolean,
        allowFiles: Boolean,
        imageReadTimerSec: Int,
        imageOverallExpirySec: Int,
        enforceImageAbsoluteExpiry: Boolean,
        videoReadTimerSec: Int,
        videoOverallExpirySec: Int,
        enforceVideoAbsoluteExpiry: Boolean,
        fileReadTimerSec: Int,
        fileOverallExpirySec: Int,
        enforceFileAbsoluteExpiry: Boolean
    ) {
        val connectionGeneration = chatTransport.currentConnectionGeneration()
        viewModelScope.launch {
            val forumId = "forum_" + UUID.randomUUID().toString().take(8)
            val session = ChatSession(
                id = forumId,
                name = name,
                isForum = true,
                lastMessage = null,
                unreadCount = 0,
                selfDestructTimerSec = readExpirySec,
                overallExpirySec = overallExpirySec,
                allowImages = allowImages,
                allowVideos = allowVideos,
                allowFiles = allowFiles,
                enforceTextAbsoluteExpiry = enforceTextAbsoluteExpiry,
                imageReadTimerSec = imageReadTimerSec,
                imageOverallExpirySec = imageOverallExpirySec,
                enforceImageAbsoluteExpiry = enforceImageAbsoluteExpiry,
                videoReadTimerSec = videoReadTimerSec,
                videoOverallExpirySec = videoOverallExpirySec,
                enforceVideoAbsoluteExpiry = enforceVideoAbsoluteExpiry,
                fileReadTimerSec = fileReadTimerSec,
                fileOverallExpirySec = fileOverallExpirySec,
                enforceFileAbsoluteExpiry = enforceFileAbsoluteExpiry,
                ownerUsername = currentUser.value?.username
            )
            chatTransport.createForum(session, connectionGeneration)
        }
    }

    fun deleteForum(chatId: String) {
        val connectionGeneration = chatTransport.currentConnectionGeneration()
        viewModelScope.launch {
            chatTransport.deleteForum(chatId, connectionGeneration)
        }
    }

    fun openDirect(peerUsername: String) {
        val peer = peerUsername.trim()
        val currentUsername = currentUser.value?.username ?: return
        if (peer.isEmpty() || peer.length > 80 || peer.equals(currentUsername, ignoreCase = true)) return
        val existing = sessions.value.firstOrNull {
            !it.isForum && it.name.equals(peer, ignoreCase = true)
        }
        if (existing != null) {
            navigateTo(Screen.Chat(existing.id))
            return
        }
        requestedDirectUsername = peer
        val connectionGeneration = chatTransport.currentConnectionGeneration()
        viewModelScope.launch { chatTransport.openDirect(peer, connectionGeneration) }
    }

    private suspend fun joinAvailableSessions(expectedConnectionGeneration: Long) {
        sessions.value.forEach { session ->
            chatTransport.joinChat(session.id, expectedConnectionGeneration)
        }
    }

    fun updateDisguiseSettings(enabled: Boolean, pin: String, duressPin: String) {
        val normalizedPin = pin.trim()
        val normalizedDuressPin = duressPin.trim()
        if (!isValidCamouflageConfiguration(enabled, normalizedPin, normalizedDuressPin)) return
        cancelCalculatorEvaluation()
        if (!disguiseManager.configure(enabled, normalizedPin, normalizedDuressPin)) return
        _disguiseSettings.value = DisguiseSettings(enabled)
        if (!enabled) _isLocked.value = false
    }

    fun completeCamouflagePinSetup(pin: String, duressPin: String) {
        val safePin = pin.trim()
        val safeDuressPin = duressPin.trim()
        if (!isValidCamouflageConfiguration(true, safePin, safeDuressPin)) return
        cancelCalculatorEvaluation()
        if (!disguiseManager.configure(true, safePin, safeDuressPin)) return
        _disguiseSettings.value = DisguiseSettings(
            isDisguised = true
        )
        _isLocked.value = false
        _showCamouflagePinPrompt.value = false
    }

    fun lockApp() {
        if (disguiseSettings.value.isDisguised) _isLocked.value = true
    }

    fun beginExternalSystemUi(): Long {
        externalSystemUiTimeoutJob?.cancel()
        externalSystemUiGraceJob?.cancel()
        val token = externalSystemUiTokens.begin()
        recordUserActivity()
        externalSystemUiTimeoutJob = viewModelScope.launch {
            delay(EXTERNAL_SYSTEM_UI_TIMEOUT_MS)
            if (externalSystemUiTokens.expire(token)) {
                externalSystemUiGraceJob?.cancel()
                externalSystemUiGraceJob = null
                lockForLifecycleExit()
            }
        }
        return token
    }

    fun endExternalSystemUi(token: Long): Boolean {
        if (!externalSystemUiTokens.end(token)) return false
        externalSystemUiTimeoutJob?.cancel()
        externalSystemUiGraceJob?.cancel()
        externalSystemUiTimeoutJob = null
        externalSystemUiGraceJob = null
        recordUserActivity()
        return true
    }

    fun lockForLifecycleExit() {
        // A picker may pause the activity, but its window is already outside this
        // process. Clear decrypted preview before allowing the short picker grace
        // period; a lost callback is closed by the timeout above.
        replaceAttachmentPreview(null)
        _calculatorDisplay.value = "0"
        if (externalSystemUiTokens.activeToken() != null) return
        if (!sessionInactivityPolicy.isActive()) return
        if (disguiseSettings.value.isDisguised) _isLocked.value = true
        if (!retainSessionInBackground) endSession(lockBehindDisguise = true)
    }

    fun onHostTrimMemory(level: Int) {
        replaceAttachmentPreview(null)
        _calculatorDisplay.value = "0"
        if (externalSystemUiTokens.activeToken() != null) return
        if (level >= android.content.ComponentCallbacks2.TRIM_MEMORY_UI_HIDDEN) {
            lockForLifecycleExit()
        }
    }

    fun onHostResumed() {
        val pickerToken = externalSystemUiTokens.activeToken()
        if (pickerToken != null) {
            // ActivityResult callbacks normally follow onResume. Give that callback
            // one event-loop window, then close a lost picker transition instead of
            // keeping an authenticated session open indefinitely.
            externalSystemUiGraceJob?.cancel()
            externalSystemUiGraceJob = viewModelScope.launch {
                delay(EXTERNAL_SYSTEM_UI_RESULT_GRACE_MS)
                if (externalSystemUiTokens.expire(pickerToken)) {
                    externalSystemUiTimeoutJob?.cancel()
                    externalSystemUiTimeoutJob = null
                    lockForLifecycleExit()
                }
            }
        }
        if (expireSessionIfNeeded()) return
        if (sessionInactivityPolicy.isActive()) chatTransport.connect()
        checkForAppUpdate()
    }

    fun recordUserActivity() {
        if (_isLocked.value || !sessionInactivityPolicy.isActive()) return
        if (!sessionInactivityPolicy.touch()) {
            expireSessionIfNeeded()
            return
        }
        updateSessionSecurityState()

        val now = elapsedRealtimeMs()
        if (
            serverStatus.value.state == "CONNECTED" &&
            now - lastRemoteActivitySignalMs >= REMOTE_ACTIVITY_SIGNAL_INTERVAL_MS
        ) {
            lastRemoteActivitySignalMs = now
            val connectionGeneration = chatTransport.currentConnectionGeneration()
            viewModelScope.launch {
                chatTransport.signalUserActivity(connectionGeneration)
            }
        }
    }

    fun endSession() {
        endSession(lockBehindDisguise = false)
    }

    private fun endSession(lockBehindDisguise: Boolean) {
        if (!sessionInactivityPolicy.isActive()) return
        val remoteSession = prepareLocalLogout()
        if (lockBehindDisguise && disguiseSettings.value.isDisguised) {
            _isLocked.value = true
        } else {
            _isLocked.value = false
        }
        if (remoteSession != null) {
            viewModelScope.launch { identityService.revokeSession(remoteSession) }
        }
    }

    fun onCalculatorInput(input: String) {
        val current = _calculatorDisplay.value
        when (input) {
            "C" -> {
                cancelCalculatorEvaluation()
                _calculatorDisplay.value = "0"
            }
            "⌫" -> {
                cancelCalculatorEvaluation()
                _calculatorDisplay.value = current.dropLast(1).ifBlank { "0" }
            }
            "=" -> startCalculatorEvaluation(current)
            "+", "-", "*", "/", "(", ")" -> {
                cancelCalculatorEvaluation()
                _calculatorDisplay.value = if (current == "0" || current == "Error") input else current + input
            }
            else -> {
                cancelCalculatorEvaluation()
                _calculatorDisplay.value = if (current == "0" || current == "Error") input else current + input
            }
        }
    }

    private data class CalculatorEvaluation(
        val duressMatched: Boolean,
        val unlockMatched: Boolean,
        val display: String
    )

    private fun startCalculatorEvaluation(expression: String) {
        val generation = calculatorInputGeneration.incrementAndGet()
        val accountGeneration = sessionGeneration.get()
        val duressSessionStamp = captureSessionStamp()
        calculatorEvaluationJob?.cancel()
        val job = viewModelScope.launch(Dispatchers.Default) {
            try {
                val evaluation = calculatorEvaluationGate.withLock {
                    ensureActive()
                    val cleanExpr = expression.replace(" ", "")
                    val duressMatched = disguiseManager.verifyDuressPin(cleanExpr)
                    ensureActive()
                    val unlockMatched = !duressMatched && disguiseManager.verifyPin(cleanExpr)
                    ensureActive()
                    CalculatorEvaluation(
                        duressMatched = duressMatched,
                        unlockMatched = unlockMatched,
                        display = if (duressMatched || unlockMatched) "0" else evaluateCalculatorOnly(cleanExpr)
                    )
                }
                withContext(kotlinx.coroutines.Dispatchers.Main.immediate) {
                    if (!canApplyCalculatorEvaluation(
                            resultGeneration = generation,
                            currentGeneration = calculatorInputGeneration.get(),
                            coroutineIsActive = isActive
                        )) return@withContext
                    when {
                        evaluation.duressMatched -> {
                            when {
                                duressSessionStamp != null -> executeDuressWipe(duressSessionStamp)
                                accountGeneration == sessionGeneration.get() && currentUser.value == null -> {
                                    _isLocked.value = true
                                    _calculatorDisplay.value = "0"
                                }
                            }
                        }
                        evaluation.unlockMatched -> {
                            if (!expireSessionIfNeeded()) {
                                _isLocked.value = false
                                checkForAppUpdate()
                                if (sessionInactivityPolicy.isActive()) {
                                    sessionInactivityPolicy.touch()
                                    updateSessionSecurityState()
                                }
                                _calculatorDisplay.value = "0"
                            }
                        }
                        else -> _calculatorDisplay.value = evaluation.display
                    }
                }
            } finally {
                duressSessionStamp?.wipe()
            }
        }
        calculatorEvaluationJob = job
        job.invokeOnCompletion {
            duressSessionStamp?.wipe()
            if (calculatorEvaluationJob === job) calculatorEvaluationJob = null
        }
    }

    private fun cancelCalculatorEvaluation() {
        calculatorInputGeneration.incrementAndGet()
        calculatorEvaluationJob?.cancel()
        calculatorEvaluationJob = null
    }

    private fun evaluateCalculatorOnly(expr: String): String {
        val cleanExpr = expr.replace(" ", "")
        return runCatching {
            val parser = CalculatorParser(cleanExpr)
            val value = parser.parse()
            if (!value.isFinite()) "Error" else {
                if (value % 1.0 == 0.0) value.toLong().toString() else "%.8f".format(value).trimEnd('0').trimEnd('.')
            }
        }.getOrElse { "Error" }
    }

    private suspend fun executeLocalMemoryPurge() {
        logoutLocal()
        _isLocked.value = false
    }

    private suspend fun executeDuressWipe(stamp: SessionStamp) {
        if (!isSessionStampValid(stamp)) return
        runCatching { chatTransport.broadcastGlobalWipe(stamp.connectionGeneration) }
        // A successful wipe can close the socket. Keep the local purge bound to
        // the captured account even when its connection generation advances.
        if (!isAccountSessionStampValid(stamp)) return
        logoutLocal()
        _isLocked.value = true
        _calculatorDisplay.value = "0"
    }

    /**
     * Redacts all local session state synchronously. Network revocation stays outside
     * this boundary so lifecycle/logout never leaves a renderable authenticated frame.
     */
    private fun prepareLocalLogout(): NodeSession? {
        // Invalidate first so cancellation/finally paths cannot act on a newly
        // installed identity even if a provider ignores coroutine cancellation.
        sessionGeneration.incrementAndGet()
        // Cancel before clearing state. Account-entry continuations also check their
        // coroutine activity before installing returned identity material.
        accountEntryJob?.cancel()
        accountEntryJob = null
        cancelMessageSends()
        attachmentOperations.invalidateOperations()
        cancelAttachmentOperations()
        // Settle relay waiters before clearing native ratchet state. Otherwise a
        // late message_result can finalize a cleared or newly installed identity.
        chatTransport.disconnect()
        cancelCalculatorEvaluation()
        externalSystemUiTimeoutJob?.cancel()
        externalSystemUiGraceJob?.cancel()
        externalSystemUiTimeoutJob = null
        externalSystemUiGraceJob = null
        externalSystemUiTokens.clear()
        val remoteSession = nodeConfigService.getActiveSession()
        sessionInactivityPolicy.clear()
        retainSessionInBackground = false
        lastRemoteActivitySignalMs = 0L
        requestedDirectUsername = null
        directTrustStore.clear()
        _directTrust.value = DirectTrustStatus()
        _roomCreationLimit.value = DEFAULT_MAX_ROOMS_PER_USER
        updateSessionSecurityState()
        messageRepository.clearAllDataNow()
        clearClientIdentity(
            currentUser = _currentUser.value,
            logout = identityService::logout,
            clearNodeSession = nodeConfigService::clear
        )
        payloadCipher.clear()
        _currentUser.value = null
        _currentScreen.value = Screen.Entrance
        _showCamouflagePinPrompt.value = false
        replaceAttachmentPreview(null)
        _attachmentError.value = null
        _attachmentUploadProgress.value = AttachmentUploadProgress()
        ownMessageIds.clear()
        receivedFrameIds.clear()
        activeAttachmentViews.clear()
        consumedOneTimeAttachments.clear()
        return remoteSession
    }

    private suspend fun logoutLocal(revokeRemote: Boolean = false) {
        val remoteSession = prepareLocalLogout()
        if (revokeRemote && remoteSession != null) {
            identityService.revokeSession(remoteSession)
        }
    }

    fun verifyDirectSafetyNumber(displayedSafetyNumber: String): Boolean {
        val context = currentDirectTrustContext() ?: return false
        val accepted = directTrustStore.markVerified(context, displayedSafetyNumber)
        wipeDirectTrustContext(context)
        refreshDirectTrust()
        return accepted
    }

    private fun expireSessionIfNeeded(): Boolean {
        if (!sessionInactivityPolicy.isExpired()) return false
        val remoteSession = prepareLocalLogout()
        if (disguiseSettings.value.isDisguised) _isLocked.value = true
        if (remoteSession != null) {
            viewModelScope.launch { identityService.revokeSession(remoteSession) }
        }
        return true
    }

    private fun updateSessionSecurityState() {
        val active = sessionInactivityPolicy.isActive()
        val remainingSec = if (active) {
            ((sessionInactivityPolicy.remainingMs() + 999L) / 1000L).toInt()
        } else {
            0
        }
        _sessionSecurity.value = SessionSecurityState(
            active = active,
            retainedInBackground = active && retainSessionInBackground,
            inactivityTimeoutSec = sessionInactivityTimeoutSec,
            remainingSec = remainingSec
        )
    }

    private fun currentDirectTrustContext(chatId: String? = _activeChatId.value): DirectTrustContext? {
        val activeChatId = _activeChatId.value
        val currentUser = currentUser.value
        if (chatId == null || chatId != activeChatId || currentUser == null ||
            serverStatus.value.state != "CONNECTED") return null
        val session = sessions.value.firstOrNull { it.id == chatId } ?: return null
        if (session.isForum) return null
        val peer = presence.value.firstOrNull { it.username.equals(session.name, ignoreCase = true) } ?: return null
        val safetyNumber = runCatching {
            conversationSafetyNumber(currentUser.publicKey, peer.publicKey)
        }.getOrNull() ?: return null
        return DirectTrustContext(
            chatId = session.id,
            peerUsername = session.name,
            safetyNumber = safetyNumber,
            sessionGeneration = sessionGeneration.get(),
            connectionGeneration = chatTransport.currentConnectionGeneration(),
            localIdentity = currentUser.publicKey.copyOf(),
            peerIdentity = peer.publicKey.copyOf()
        )
    }

    private fun refreshDirectTrust() {
        val context = currentDirectTrustContext()
        directTrustStore.invalidateIfIdentityChanged(context)
        _directTrust.value = directTrustStore.status(context)
        wipeDirectTrustContext(context)
    }

    private fun isDirectChatTrusted(chatId: String): Boolean {
        val session = sessions.value.firstOrNull { it.id == chatId } ?: return false
        if (session.isForum) return true
        val context = currentDirectTrustContext(chatId)
        directTrustStore.invalidateIfIdentityChanged(context)
        val trusted = directTrustStore.isVerified(context)
        wipeDirectTrustContext(context)
        return trusted
    }

    private fun wipeDirectTrustContext(context: DirectTrustContext?) {
        context?.localIdentity?.fill(0)
        context?.peerIdentity?.fill(0)
    }

    private fun isSessionGenerationValid(generation: Long): Boolean =
        generation == sessionGeneration.get() &&
            currentUser.value != null &&
            sessionInactivityPolicy.isActive()

    private fun isAttachmentGenerationCurrent(
        session: NodeSession,
        generation: Long,
        connectionGeneration: Long
    ): Boolean = isSessionGenerationValid(generation) &&
        serverStatus.value.state == "CONNECTED" &&
        chatTransport.currentConnectionGeneration() == connectionGeneration &&
        nodeConfigService.getActiveSession() == session

    private fun captureSessionStamp(): SessionStamp? {
        val generation = sessionGeneration.get()
        val user = currentUser.value ?: return null
        val connectionGeneration = chatTransport.currentConnectionGeneration()
        val stamp = SessionStamp(
            generation = generation,
            username = user.username,
            identityPublicKey = user.publicKey.copyOf(),
            repositoryEpoch = messageRepository.currentEpoch(),
            connectionGeneration = connectionGeneration
        )
        if (isSessionStampValid(stamp)) return stamp
        stamp.wipe()
        return null
    }

    private fun isAccountSessionStampValid(stamp: SessionStamp): Boolean {
        val user = currentUser.value ?: return false
        return isSessionGenerationValid(stamp.generation) &&
            user.username == stamp.username &&
            user.publicKey.contentEquals(stamp.identityPublicKey) &&
            messageRepository.currentEpoch() == stamp.repositoryEpoch
    }

    private fun isSessionStampValid(stamp: SessionStamp): Boolean =
        isAccountSessionStampValid(stamp) &&
            chatTransport.currentConnectionGeneration() == stamp.connectionGeneration

    /**
     * Linearizes one RAM-repository publication with transport invalidation.
     * RealChatTransport holds its connection lock while [mutation] executes, so
     * the captured epoch cannot become stale between validation and publication.
     */
    private fun mutateRepositoryIfCurrent(
        stamp: SessionStamp,
        mutation: () -> Boolean
    ): Boolean {
        if (!isAccountSessionStampValid(stamp)) return false
        return chatTransport.runIfConnectionCurrent(stamp.connectionGeneration) {
            isAccountSessionStampValid(stamp) && mutation()
        }
    }

    private fun isRoomChangeCurrent(change: RoomChange, stamp: SessionStamp): Boolean =
        isSessionStampValid(stamp) &&
            change.connectionGeneration == chatTransport.currentConnectionGeneration()

    private suspend fun processRoomChange(change: RoomChange) {
        val stamp = captureSessionStamp() ?: return
        try {
            if (!isRoomChangeCurrent(change, stamp)) return
            when (change.action) {
                "upsert" -> change.session?.let { session ->
                    if (!mutateRepositoryIfCurrent(stamp) {
                            messageRepository.createForumSessionIfCurrent(
                                stamp.repositoryEpoch,
                                session
                            )
                        } || !isRoomChangeCurrent(change, stamp)
                    ) return
                    chatTransport.joinChat(session.id, change.connectionGeneration)
                    if (!isRoomChangeCurrent(change, stamp)) return
                    if (!session.isForum &&
                        requestedDirectUsername.equals(session.name, ignoreCase = true)
                    ) {
                        requestedDirectUsername = null
                        _activeChatId.value = session.id
                        _currentScreen.value = Screen.Chat(session.id)
                    }
                }
                "delete" -> change.chatId?.let { chatId ->
                    if (!mutateRepositoryIfCurrent(stamp) {
                            messageRepository.deleteChatSessionIfCurrent(
                                stamp.repositoryEpoch,
                                chatId
                            )
                        } || !isRoomChangeCurrent(change, stamp)
                    ) return
                    if (_activeChatId.value == chatId) {
                        _activeChatId.value = null
                        _currentScreen.value = Screen.Dashboard
                    }
                }
            }
        } finally {
            stamp.wipe()
        }
    }

    private fun rememberReceivedFrame(replayKey: String, directoryEvidenceKey: String) {
        receivedFrameIds[replayKey] = directoryEvidenceKey
        if (receivedFrameIds.size > MAX_RECEIVED_FRAME_IDS) {
            receivedFrameIds.entries.iterator().run {
                if (hasNext()) {
                    next()
                    remove()
                }
            }
        }
    }

    private suspend fun failClosedForIncomingAckFailure(
        stamp: SessionStamp
    ) {
        // A socket failure makes the connection component stale, but the
        // already-advanced recipient ratchet still belongs to this account and
        // must be cleared. An app-session change protects a replacement login.
        if (!isAccountSessionStampValid(stamp)) return
        failClosedAfterAmbiguous()
    }

    private fun elapsedRealtimeMs(): Long = System.nanoTime() / 1_000_000L

    /**
     * One ratchet transaction for text, attachment metadata, and receipts.
     * Publication happens only after native commit. An ambiguous relay result
     * never rolls state back because the server may already have accepted it.
     */
    private suspend fun sendEncryptedMetadata(
        chatId: String,
        messageId: String,
        metadata: String,
        recipientsOverride: List<RecipientIdentity>? = null,
        sessionStamp: SessionStamp? = null
    ): OutboundSendResult? = cryptoGate.withLock {
        if (sessionStamp != null && !isSessionStampValid(sessionStamp)) {
            return@withLock OutboundSendResult.NOT_SENT
        }
        val sessionGenerationSnapshot = sessionStamp?.generation ?: sessionGeneration.get()
        val connectionGeneration = sessionStamp?.connectionGeneration
            ?: chatTransport.currentConnectionGeneration()
        val directoryStamp = chatTransport.currentDirectoryStamp()
            ?: return@withLock OutboundSendResult.NOT_SENT
        val stampedMetadata = runCatching {
            JSONObject(metadata).apply {
                put("directory_node_id", directoryStamp.nodeId)
                put("directory_revision", directoryStamp.revision.toLong())
                put("directory_digest", directoryStamp.digest)
            }.toString()
        }.getOrElse { return@withLock OutboundSendResult.NOT_SENT }
        val prepared = try {
            encryptMetadata(
                chatId = chatId,
                messageId = messageId,
                metadata = stampedMetadata,
                recipientsOverride = recipientsOverride,
                expectedConnectionGeneration = connectionGeneration,
                directoryStamp = directoryStamp
            )
        } catch (_: FatalPayloadCipherException) {
            failClosedAfterAmbiguous()
            return@withLock OutboundSendResult.AMBIGUOUS
        } ?: return@withLock null
        val encrypted = prepared.payload
        try {
            if (sessionStamp != null && !isSessionStampValid(sessionStamp)) {
                return@withLock try {
                    payloadCipher.rollbackOutbound(encrypted.messageId, encrypted.stateRevision)
                    releasePrekeyLeases(prepared.leases, connectionGeneration)
                    OutboundSendResult.NOT_SENT
                } catch (_: Exception) {
                    failClosedAfterAmbiguous()
                    OutboundSendResult.AMBIGUOUS
                }
            }
            val result = runCatching {
                chatTransport.sendEncryptedPayload(
                    chatId,
                    encrypted,
                    expectedConnectionGeneration = connectionGeneration
                )
            }.getOrElse { OutboundSendResult.AMBIGUOUS }
            if (sessionGenerationSnapshot != sessionGeneration.get() ||
                (sessionStamp != null && !isAccountSessionStampValid(sessionStamp))
            ) return@withLock OutboundSendResult.AMBIGUOUS
            if (connectionGeneration != chatTransport.currentConnectionGeneration()) {
                // The relay may have accepted the staged frame before the
                // connection result was lost. Do not leave staged ratchet state
                // installed or reuse it on a replacement connection.
                failClosedAfterAmbiguous()
                return@withLock OutboundSendResult.AMBIGUOUS
            }
            when (result) {
                OutboundSendResult.ACCEPTED -> {
                    try {
                        payloadCipher.commitOutbound(encrypted.messageId, encrypted.stateRevision)
                    } catch (_: Exception) {
                        failClosedAfterAmbiguous()
                        return@withLock OutboundSendResult.AMBIGUOUS
                    }
                }
                OutboundSendResult.REJECTED,
                OutboundSendResult.NOT_SENT -> {
                    try {
                        payloadCipher.rollbackOutbound(encrypted.messageId, encrypted.stateRevision)
                        releasePrekeyLeases(prepared.leases, connectionGeneration)
                    } catch (_: Exception) {
                        failClosedAfterAmbiguous()
                        return@withLock OutboundSendResult.AMBIGUOUS
                    }
                }
                OutboundSendResult.AMBIGUOUS -> failClosedAfterAmbiguous()
            }
            result
        } finally {
            wipeEncryptedPayload(encrypted)
        }
    }

    /** Clear local state first, then make a bounded best-effort remote revoke. */
    private suspend fun failClosedAfterAmbiguous() {
        withContext(NonCancellable) {
            val remoteSession = nodeConfigService.getActiveSession()
            runCatching { logoutLocal() }
            if (remoteSession != null) {
                withTimeoutOrNull(3_000L) {
                    runCatching { identityService.revokeSession(remoteSession) }
                }
            }
        }
    }

    private suspend fun encryptMetadata(
        chatId: String,
        messageId: String,
        metadata: String,
        recipientsOverride: List<RecipientIdentity>? = null,
        expectedConnectionGeneration: Long = chatTransport.currentConnectionGeneration(),
        directoryStamp: DirectoryStamp
    ): PreparedEncryptedMessage? {
        val sender = currentUser.value ?: return null
        val recipients = recipientsOverride ?: recipientIdentities(chatId, includeSelf = false) ?: return null
        val plainBytes = metadata.toByteArray(StandardCharsets.UTF_8)
        val acquiredLeases = ArrayList<PrekeyLease>()
        val leaseReferences = ArrayList<LeasedPrekeyReference>()
        val leasedRecipientKeys = ArrayList<ByteArray>()
        return try {
            val leasedRecipients = recipients
                .distinctBy { it.username.lowercase(Locale.ROOT) }
                .map { recipient ->
                    if (!payloadCipher.requiresPrekey(recipient.username)) {
                        recipient
                    } else {
                        val lease = chatTransport.requestPrekeyLease(
                            chatId = chatId,
                            messageId = messageId,
                            recipientUsername = recipient.username,
                            expectedConnectionGeneration = expectedConnectionGeneration
                        ) ?: throw IllegalStateException("Prekey lease unavailable")
                        if (lease.chatId != chatId ||
                            lease.messageId != messageId ||
                            lease.recipientUsername != recipient.username ||
                            lease.recipientPublicKey.size != IDENTITY_PUBLIC_KEY_BYTES ||
                            !PREKEY_ID_REGEX.matches(lease.prekeyId) ||
                            lease.expiresAtMs <= 0L ||
                            (lease.connectionGeneration != 0L &&
                                lease.connectionGeneration != expectedConnectionGeneration)
                        ) throw IllegalStateException("Prekey lease mismatch")
                        acquiredLeases += lease
                        leaseReferences += LeasedPrekeyReference(
                            chatId = chatId,
                            messageId = messageId,
                            recipientUsername = lease.recipientUsername,
                            prekeyId = lease.prekeyId
                        )
                        val leasedPublicKey = lease.recipientPublicKey.copyOf()
                        leasedRecipientKeys += leasedPublicKey
                        RecipientIdentity(
                            username = lease.recipientUsername,
                            publicKey = leasedPublicKey,
                            prekeyId = lease.prekeyId
                        )
                    }
                }
            val encrypted = payloadCipher.encrypt(
                    chatId = chatId,
                    messageId = messageId,
                    senderUsername = sender.username,
                    plainBytes = plainBytes,
                    recipients = leasedRecipients
                ).copy(
                    directoryNodeId = directoryStamp.nodeId,
                    directoryRevision = directoryStamp.revision,
                    directoryDigest = directoryStamp.digest
                )
            PreparedEncryptedMessage(
                payload = encrypted,
                leases = leaseReferences.toList()
            )
        } catch (error: FatalPayloadCipherException) {
            // Native encryption happens before relay admission, so every lease
            // acquired in this preparation phase is definitely unused even if
            // native rollback failed. Release only the exact known tuples,
            // then preserve the fatal identity transition for fail-closed
            // handling by the caller.
            releasePrekeyLeases(leaseReferences, expectedConnectionGeneration)
            throw error
        } catch (error: CancellationException) {
            releasePrekeyLeases(leaseReferences, expectedConnectionGeneration)
            throw error
        } catch (_: Exception) {
            releasePrekeyLeases(leaseReferences, expectedConnectionGeneration)
            null
        } finally {
            plainBytes.fill(0)
            acquiredLeases.forEach { it.recipientPublicKey.fill(0) }
            leasedRecipientKeys.forEach { it.fill(0) }
        }
    }

    private suspend fun releasePrekeyLeases(
        leases: List<LeasedPrekeyReference>,
        expectedConnectionGeneration: Long
    ) {
        if (leases.isEmpty()) return
        withContext(NonCancellable) {
            leases.forEach { lease ->
                runCatching {
                    chatTransport.releasePrekeyLease(
                        chatId = lease.chatId,
                        messageId = lease.messageId,
                        recipientUsername = lease.recipientUsername,
                        prekeyId = lease.prekeyId,
                        expectedConnectionGeneration = expectedConnectionGeneration
                    )
                }
            }
        }
    }

    private fun wipeEncryptedPayload(payload: EncryptedTransportPayload) {
        payload.nonce.fill(0)
        payload.ciphertext.fill(0)
        payload.identityEnvelope.fill(0)
        payload.identityPublicKey.fill(0)
        payload.stateSignature.fill(0)
        payload.envelopes.forEach {
            it.wrappedKey.fill(0)
            it.signature.fill(0)
        }
    }

    private fun wipeIncomingPayload(payload: IncomingTransportPayload) {
        payload.nonce.fill(0)
        payload.ciphertext.fill(0)
        payload.signature.fill(0)
        payload.wrappedKey.fill(0)
        payload.senderPublicKey.fill(0)
        payload.identityPublicKey.fill(0)
    }

    private fun recipientIdentities(chatId: String, includeSelf: Boolean): List<RecipientIdentity>? {
        val self = currentUser.value ?: return null
        val known = presence.value
            .filter { it.publicKey.size == IDENTITY_PUBLIC_KEY_BYTES }
            .associateBy { it.username.lowercase() }
        val recipients = if (chatId.startsWith("dm_")) {
            val peer = sessions.value.firstOrNull { it.id == chatId && !it.isForum }?.name
                ?: return null
            listOfNotNull(known[peer.lowercase()])
                .takeIf { it.isNotEmpty() }
                ?: return null
        } else {
            known.values.filterNot { it.username.equals(self.username, ignoreCase = true) }
        }.map { RecipientIdentity(it.username, it.publicKey, it.prekeyId) }.toMutableList()

        if (includeSelf && recipients.none { it.username.equals(self.username, ignoreCase = true) }) {
            recipients += RecipientIdentity(self.username, self.publicKey, self.prekeyId)
        }
        return recipients
    }

    private suspend fun decryptAttachment(chatId: String, message: Message, encrypted: ByteArray): ByteArray? {
        var key: ByteArray? = null
        return try {
            val self = currentUser.value ?: return null
            val senderUsername = if (message.sender == "You") self.username else message.sender
            val mediaType = message.mediaType
                ?.uppercase(Locale.ROOT)
                ?.takeIf { it in SUPPORTED_MEDIA_TYPES }
                ?: return null
            val attachmentKey = message.attachmentKey?.copyOf() ?: return null
            key = attachmentKey
            if (!isValidAttachmentCiphertext(
                    version = message.attachmentCipherVersion,
                    key = key,
                    blob = encrypted,
                    mediaType = mediaType
                )
            ) return null
            val plain = runCatching {
                decryptAttachmentBlob(
                    chatId = chatId,
                    messageId = message.id,
                    senderUsername = senderUsername,
                    mediaType = mediaType,
                    key = attachmentKey,
                    blob = encrypted
                )
            }.getOrNull() ?: return null
            if (!isDecryptedAttachmentSizeValid(
                    actualBytes = plain.size.toLong(),
                    expectedBytes = message.attachmentSizeBytes,
                    maxBytes = attachmentSelectionLimitBytes(mediaType)
                )
            ) {
                plain.fill(0)
                return null
            }
            plain
        } finally {
            key?.fill(0)
            encrypted.fill(0)
        }
    }

    private fun replaceAttachmentPreview(next: DecryptedAttachment?) {
        val previous = _attachmentPreview.value
        if (previous !== next) previous?.bytes?.fill(0)
        _attachmentPreview.value = next
    }

    private fun parseIncomingMessage(
        chatId: String,
        authoritativeMessageId: String,
        decryptedContent: String,
        authoritativeSender: String,
        senderPublicKey: ByteArray
    ): Message? {
        val json = runCatching { JSONObject(decryptedContent) }.getOrNull() ?: return null
        if (authoritativeSender.isBlank() ||
            !matchesAuthoritativeMessageId(json, authoritativeMessageId)
        ) return null
        val sender = authoritativeSender
        if (sender.equals(currentUser.value?.username, ignoreCase = true)) return null
        val replyToMessageId = json.replyToMessageId()
        val repliesToCurrentUser = MessageAttentionPolicy.replyTargetsCurrentUser(
            senderUsername = sender,
            currentUsername = currentUser.value?.username,
            replyToMessageId = replyToMessageId,
            ownMessageIds = ownMessageIds
        )

        if (json.optString("kind") == "attachment") {
            val mediaType = json.optString("media_type", "FILE")
                .uppercase(Locale.ROOT)
                .takeIf { it in SUPPORTED_MEDIA_TYPES }
                ?: return null
            val attachmentId = normalizeAttachmentId(json.optString("attachment_id")) ?: return null
            val attachmentCipherVersion = json.optInt("attachment_cipher_version", -1)
            if (attachmentCipherVersion != ATTACHMENT_CIPHER_VERSION) return null
            val sizeBytes = json.optLong("size_bytes", -1L)
            if (sizeBytes !in 1L..attachmentSelectionLimitBytes(mediaType)) return null
            val attachmentKey = decodeAttachmentKey(json.optString("attachment_key_b64")) ?: return null
            val fileName = AttachmentSavePolicy.sanitizedFileName(json.optString("name", "attachment"))
            val mimeType = safeMimeType(json.optString("mime_type", "application/octet-stream"))
            val messageId = authoritativeMessageId
            var ownershipTransferred = false
            var retainedSenderPublicKey: ByteArray? = null
            return try {
                retainedSenderPublicKey = senderPublicKey.copyOf()
                attachmentMessage(
                    messageId = messageId,
                    sender = sender,
                    receiver = if (chatId.startsWith("dm_")) "You" else null,
                    attachmentId = attachmentId,
                    attachmentCipherVersion = attachmentCipherVersion,
                    attachmentKey = attachmentKey,
                    mediaType = mediaType,
                    fileName = fileName,
                    mimeType = mimeType,
                    sizeBytes = sizeBytes,
                    selfDestructSec = effectiveRetentionSec(chatId, json.optInt("self_destruct_sec", 10), mediaType),
                    absoluteExpirySec = effectiveAbsoluteExpirySec(chatId, mediaType),
                    oneTimeView = json.optBoolean("one_time", false),
                    deleteAfterDownload = json.optBoolean("delete_after_download", false),
                    replyToMessageId = replyToMessageId,
                    reactionShortcode = MessageAttentionPolicy.validatedReactionShortcode(
                        json.optString("reaction_shortcode").takeIf { it.isNotBlank() },
                        fileName,
                        mimeType
                    ),
                    repliesToCurrentUser = repliesToCurrentUser,
                    senderPublicKey = retainedSenderPublicKey
                ).also { ownershipTransferred = true }
            } finally {
                if (!ownershipTransferred) {
                    attachmentKey.fill(0)
                    retainedSenderPublicKey?.fill(0)
                }
            }
        }

        if (json.optString("kind") == "text") {
            val content = json.optString("content")
                .takeIf { it.isNotBlank() && it.length <= MAX_TEXT_MESSAGE_CHARS }
                ?: return null
            val messageId = authoritativeMessageId
            val retainedSenderPublicKey = senderPublicKey.copyOf()
            return Message(
                id = messageId,
                sender = sender,
                receiver = if (chatId.startsWith("dm_")) "You" else null,
                content = content,
                timestampMs = System.currentTimeMillis(),
                selfDestructDurationSec = effectiveRetentionSec(chatId, json.optInt("self_destruct_sec", 10)),
                absoluteExpirySec = effectiveAbsoluteExpirySec(chatId, null),
                replyToMessageId = replyToMessageId,
                mentionsCurrentUser = MessageAttentionPolicy.mentionsUsername(
                    content,
                    currentUser.value?.username
                ),
                repliesToCurrentUser = repliesToCurrentUser,
                senderPublicKey = retainedSenderPublicKey
            )
        }

        return null
    }

    private fun matchesDirectoryStamp(
        json: JSONObject,
        incoming: IncomingTransportPayload
    ): Boolean {
        if (incoming.directoryNodeId.isEmpty() || incoming.directoryRevision == 0uL ||
            incoming.directoryDigest.isEmpty() ||
            !json.has("directory_node_id") || !json.has("directory_revision") ||
            !json.has("directory_digest")
        ) return false
        val revision = (json.opt("directory_revision") as? Number)
            ?.toLong()?.takeIf { it > 0L }?.toULong() ?: return false
        return json.optString("directory_node_id", "") == incoming.directoryNodeId &&
            revision == incoming.directoryRevision &&
            json.optString("directory_digest", "") == incoming.directoryDigest
    }

    private fun effectiveRetentionSec(chatId: String, requestedSec: Int, mediaType: String? = null): Int {
        val session = sessions.value.find { it.id == chatId }
        if (session?.isForum != true) return requestedSec.coerceIn(0, 86_400)
        return when (mediaType?.uppercase()) {
            "IMAGE" -> session.imageReadTimerSec
            "VIDEO" -> session.videoReadTimerSec
            "FILE" -> session.fileReadTimerSec
            else -> session.selfDestructTimerSec
        }.coerceIn(0, 86_400)
    }

    private fun effectiveAbsoluteExpirySec(chatId: String, mediaType: String?): Int {
        val session = sessions.value.find { it.id == chatId }
        if (session?.isForum != true) return 0
        val roomAbsolute = if (session.enforceTextAbsoluteExpiry) session.overallExpirySec else 0
        val mediaAbsolute = when (mediaType?.uppercase()) {
            "IMAGE" -> if (session.enforceImageAbsoluteExpiry) session.imageOverallExpirySec else 0
            "VIDEO" -> if (session.enforceVideoAbsoluteExpiry) session.videoOverallExpirySec else 0
            "FILE" -> if (session.enforceFileAbsoluteExpiry) session.fileOverallExpirySec else 0
            else -> roomAbsolute
        }
        return listOf(roomAbsolute, mediaAbsolute).filter { it > 0 }.minOrNull() ?: 0
    }

    private fun isMediaAllowed(chatId: String, mediaType: String): Boolean {
        val session = sessions.value.find { it.id == chatId }
        if (session?.isForum != true) return true
        return when (mediaType.uppercase()) {
            "IMAGE" -> session.allowImages
            "VIDEO" -> session.allowVideos
            "FILE" -> session.allowFiles
            else -> false
        }
    }

    private fun attachmentMessage(
        messageId: String = UUID.randomUUID().toString(),
        sender: String,
        receiver: String?,
        attachmentId: String,
        attachmentCipherVersion: Int,
        attachmentKey: ByteArray?,
        mediaType: String,
        fileName: String,
        mimeType: String,
        sizeBytes: Long,
        selfDestructSec: Int,
        absoluteExpirySec: Int,
        oneTimeView: Boolean,
        deleteAfterDownload: Boolean,
        replyToMessageId: String? = null,
        reactionShortcode: String? = null,
        repliesToCurrentUser: Boolean = false,
        senderPublicKey: ByteArray? = null
    ): Message {
        val safeName = AttachmentSavePolicy.sanitizedFileName(fileName)
        val safeMediaType = mediaType.uppercase(Locale.ROOT).takeIf { it in SUPPORTED_MEDIA_TYPES } ?: "FILE"
        val safeMimeType = safeMimeType(mimeType)
        return Message(
            id = messageId,
            sender = sender,
            receiver = receiver,
            content = safeName,
            timestampMs = System.currentTimeMillis(),
            selfDestructDurationSec = selfDestructSec,
            isMedia = true,
            mediaType = safeMediaType,
            mediaSizeMb = ((sizeBytes + 1024 * 1024 - 1) / (1024 * 1024)).toInt().coerceAtLeast(1),
            attachmentId = attachmentId,
            attachmentCipherVersion = attachmentCipherVersion,
            attachmentKey = attachmentKey,
            attachmentName = safeName,
            attachmentMimeType = safeMimeType,
            attachmentSizeBytes = sizeBytes,
            oneTimeView = oneTimeView,
            saveAllowed = !oneTimeView,
            deleteAfterDownload = deleteAfterDownload,
            absoluteExpirySec = absoluteExpirySec,
            replyToMessageId = replyToMessageId,
            reactionShortcode = reactionShortcode,
            repliesToCurrentUser = repliesToCurrentUser,
            senderPublicKey = senderPublicKey
        )
    }

    private fun attachmentMetadata(message: Message): String =
        attachmentMetadataJson(message, currentUser.value?.username.orEmpty()).toString()

    private fun textMetadata(message: Message, senderUsername: String): String {
        return JSONObject()
            .put("kind", "text")
            .put("id", message.id)
            .put("sender", senderUsername)
            .put("content", message.content)
            .put("self_destruct_sec", message.selfDestructDurationSec)
            .put("absolute_expiry_sec", message.absoluteExpirySec)
            .apply { message.replyToMessageId?.let { put("reply_to_id", it) } }
            .toString()
    }

    private fun validReplyTarget(messageId: String?): String? {
        return MessageReplyPolicy.findAvailableTargetId(messageId, activeMessages.value)
    }

    private fun JSONObject.replyToMessageId(): String? {
        return MessageReplyPolicy.sanitizeMessageId(optString("reply_to_id"))
    }

    private fun safeMimeType(value: String): String {
        val candidate = value.trim()
        return candidate.takeIf {
            it.length in 1..128 && it.all { character -> character.code in 0x20..0x7e }
        } ?: "application/octet-stream"
    }

    private fun isValidAttachmentCiphertext(
        version: Int,
        key: ByteArray,
        blob: ByteArray,
        mediaType: String
    ): Boolean {
        val blobSize = blob.size.toLong()
        return version == ATTACHMENT_CIPHER_VERSION &&
            key.size == ATTACHMENT_KEY_BYTES &&
            blobSize in ATTACHMENT_WIRE_OVERHEAD_BYTES..(
                protocolAttachmentLimitBytes(mediaType) + ATTACHMENT_WIRE_OVERHEAD_BYTES
            ) &&
            blob.firstOrNull()?.toInt() == ATTACHMENT_CIPHER_VERSION
    }

    private fun decodeAttachmentKey(value: String): ByteArray? {
        if (!ATTACHMENT_KEY_B64_REGEX.matches(value)) return null
        val decoded = runCatching { Base64.getUrlDecoder().decode(value) }.getOrNull() ?: return null
        if (decoded.size != ATTACHMENT_KEY_BYTES) {
            decoded.fill(0)
            return null
        }
        return decoded
    }

    private fun wipeMessageSecrets(message: Message) {
        message.senderPublicKey?.fill(0)
        message.attachmentKey?.fill(0)
    }

    override fun onCleared() {
        // ViewModelStore teardown is a hard local boundary. Do not join network or
        // provider jobs here; invalidate their generations and let cancellation cleanup
        // release claims best-effort while memory is synchronously purged.
        sessionGeneration.incrementAndGet()
        cancelMessageSends()
        attachmentOperations.invalidateOperations()
        cancelAttachmentOperations()
        cancelCalculatorEvaluation()
        activeAttachmentViews.clear()
        consumedOneTimeAttachments.clear()
        ownMessageIds.clear()
        receivedFrameIds.clear()
        directTrustStore.clear()
        _directTrust.value = DirectTrustStatus()
        replaceAttachmentPreview(null)
        messageRepository.clearAllDataNow()
        messageRepository.close()
        disguiseManager.clear()
        clearClientIdentity(
            currentUser = _currentUser.value,
            logout = identityService::logout,
            clearNodeSession = nodeConfigService::clear
        )
        _currentUser.value = null
        accountEntryJob?.cancel()
        accountEntryJob = null
        payloadCipher.clear()
        chatTransport.disconnect()
        super.onCleared()
    }

    private class CalculatorParser(private val input: String) {
        private var index = 0

        fun parse(): Double {
            val result = expression()
            if (index != input.length) error("trailing input")
            return result
        }

        private fun expression(): Double {
            var value = term()
            while (index < input.length) {
                value = when (input[index]) {
                    '+' -> {
                        index++
                        value + term()
                    }
                    '-' -> {
                        index++
                        value - term()
                    }
                    else -> return value
                }
            }
            return value
        }

        private fun term(): Double {
            var value = factor()
            while (index < input.length) {
                value = when (input[index]) {
                    '*' -> {
                        index++
                        value * factor()
                    }
                    '/' -> {
                        index++
                        value / factor()
                    }
                    else -> return value
                }
            }
            return value
        }

        private fun factor(): Double {
            if (index >= input.length) error("missing value")
            if (input[index] == '-') {
                index++
                return -factor()
            }
            if (input[index] == '(') {
                index++
                val value = expression()
                if (index >= input.length || input[index] != ')') error("missing close")
                index++
                return value
            }
            val start = index
            while (index < input.length && (input[index].isDigit() || input[index] == '.')) index++
            if (start == index) error("missing number")
            return input.substring(start, index).toDouble()
        }
    }

    companion object {
        const val MAX_TEXT_MESSAGE_CHARS = 64 * 1024
        private const val MAX_DECRYPTED_MESSAGE_BYTES = 64 * 1024
        private val SUPPORTED_MEDIA_TYPES = setOf("IMAGE", "VIDEO", "FILE")
        private const val DEFAULT_SESSION_INACTIVITY_SEC = 15 * 60
        private const val SESSION_WATCHDOG_INTERVAL_MS = 1_000L
        private const val REMOTE_ACTIVITY_SIGNAL_INTERVAL_MS = 15_000L
        private const val DEFAULT_MAX_ROOMS_PER_USER = 5
        private const val IDENTITY_PUBLIC_KEY_BYTES = 608
        private val PREKEY_ID_REGEX = Regex("^[A-Za-z0-9_-]{1,32}$")
        private const val MAX_RECEIVED_FRAME_IDS = 10_000
        private const val MAX_OWN_MESSAGE_IDS = 10_000
        private const val MAX_MESSAGE_SEND_JOBS = 64
        private const val EXTERNAL_SYSTEM_UI_TIMEOUT_MS = 5 * 60 * 1_000L
        private const val EXTERNAL_SYSTEM_UI_RESULT_GRACE_MS = 2_000L
    }
}

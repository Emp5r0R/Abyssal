package com.abyssal.chat.presentation.viewmodel

import android.net.Uri
import androidx.compose.runtime.State
import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.abyssal.chat.data.network.ATTACHMENT_WIRE_OVERHEAD_BYTES
import com.abyssal.chat.data.network.decryptAndCompleteAttachment
import com.abyssal.chat.data.network.normalizeAttachmentId
import com.abyssal.chat.data.network.InMemoryPayloadCipher
import com.abyssal.chat.data.repository.isValidCamouflageConfiguration
import com.abyssal.chat.domain.model.AttachmentUploadProgress
import com.abyssal.chat.domain.model.AttachmentSavePolicy
import com.abyssal.chat.domain.model.AvailableAppUpdate
import com.abyssal.chat.domain.model.ChatSession
import com.abyssal.chat.domain.model.DecryptedAttachment
import com.abyssal.chat.domain.model.DisguiseSettings
import com.abyssal.chat.domain.model.EncryptedTransportPayload
import com.abyssal.chat.domain.model.IncomingTransportPayload
import com.abyssal.chat.domain.model.IdentityValidationResult
import com.abyssal.chat.domain.model.IdentityStateSnapshot
import com.abyssal.chat.domain.model.Message
import com.abyssal.chat.domain.model.MessageAttentionPolicy
import com.abyssal.chat.domain.model.MessageReplyPolicy
import com.abyssal.chat.domain.model.NodeSession
import com.abyssal.chat.domain.model.RecipientIdentity
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
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.Collections
import java.util.LinkedHashSet
import java.util.Locale
import java.util.UUID
import java.util.concurrent.CancellationException
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.CoroutineStart
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
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONObject
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
    metadataAccepted: Boolean
): Boolean = uploadedAttachmentId != null && !metadataAccepted

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
    private var attachmentUploadJob: Job? = null
    private val sessionGeneration = AtomicLong(0L)
    // This gate covers only short local state transitions. Network claims and
    // provider writes remain cancellable and never hold up a local purge.
    private val attachmentSessionGate = Mutex()
    private val attachmentJobs = Collections.synchronizedSet(mutableSetOf<Job>())
    @Volatile
    private var calculatorEvaluationJob: Job? = null
    private val calculatorInputGeneration = AtomicLong(0L)
    private val calculatorEvaluationGate = Mutex()
    private val ownMessageIds = LinkedHashSet<String>()
    private val receivedFrameIds = linkedSetOf<String>()
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

    private suspend fun acknowledgeIncoming(incoming: IncomingTransportPayload): Boolean {
        return acknowledgeWithEphemeralState(
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
                    signature
                )
            }
        )
    }

    init {
        _disguiseSettings.value = DisguiseSettings(
            isDisguised = disguiseManager.isDisguiseEnabled()
        )
        _isLocked.value = disguiseManager.isDisguiseEnabled()

        viewModelScope.launch {
            chatTransport.getIncomingWipeCommands().collect {
                executeLocalMemoryPurge()
            }
        }

        viewModelScope.launch {
            chatTransport.getIncomingPayloads().collect { incoming ->
                try {
                    val username = currentUser.value?.username ?: return@collect
                    val replayKey = "${incoming.chatId}\u0000${incoming.senderUsername}\u0000${incoming.messageId}"
                    if (replayKey in receivedFrameIds) {
                        if (!acknowledgeIncoming(incoming)) logoutLocal()
                        return@collect
                    }
                    val decryption = runCatching { payloadCipher.decrypt(incoming, username) }
                        .getOrNull() ?: return@collect
                    val plainBytes = decryption.plaintext
                    try {
                        if (plainBytes.size > MAX_DECRYPTED_MESSAGE_BYTES) return@collect
                        if (!acknowledgeIncoming(incoming)) {
                            logoutLocal()
                            return@collect
                        }
                        receivedFrameIds.add(replayKey)
                        if (receivedFrameIds.size > MAX_RECEIVED_FRAME_IDS) {
                            receivedFrameIds.iterator().run {
                                if (hasNext()) {
                                    next()
                                    remove()
                                }
                            }
                        }
                        val decryptedContent = String(plainBytes, StandardCharsets.UTF_8)
                        val control = runCatching { JSONObject(decryptedContent) }.getOrNull()
                        if (control?.optString("kind") == "read_receipt") {
                            val targetId = MessageReplyPolicy.sanitizeMessageId(
                                control.optString("message_id")
                            )
                            if (targetId != null && targetId in ownMessageIds) {
                                messageRepository.markAsRead(incoming.chatId, targetId)
                            }
                            return@collect
                        }
                        val message = parseIncomingMessage(
                            incoming.chatId,
                            decryptedContent,
                            incoming.senderUsername,
                            incoming.senderPublicKey
                        ) ?: return@collect
                        messageRepository.saveMessage(incoming.chatId, message)
                    } finally {
                        plainBytes.fill(0)
                    }
                } finally {
                    wipeIncomingPayload(incoming)
                }
            }
        }

        viewModelScope.launch {
            chatTransport.getRoomChanges().collect { change ->
                when (change.action) {
                    "upsert" -> change.session?.let { session ->
                        messageRepository.createForumSession(session)
                        chatTransport.joinChat(session.id)
                        if (!session.isForum && requestedDirectUsername.equals(session.name, ignoreCase = true)) {
                            requestedDirectUsername = null
                            _activeChatId.value = session.id
                            _currentScreen.value = Screen.Chat(session.id)
                        }
                    }
                    "delete" -> change.chatId?.let { chatId ->
                        messageRepository.deleteChatSession(chatId)
                        if (_activeChatId.value == chatId) {
                            _activeChatId.value = null
                            _currentScreen.value = Screen.Dashboard
                        }
                    }
                }
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
            viewModelScope.launch { chatTransport.joinChat(screen.sessionId) }
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
                    joinAvailableSessions()
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
        viewModelScope.launch {
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
            val remoteRecipients = recipientIdentities(chatId, includeSelf = false)
            if (isLocalOnlyForum(chatId, remoteRecipients)) {
                rememberOwnMessageId(message.id)
                messageRepository.saveMessage(chatId, message)
                return@launch
            }
            val encrypted = encryptMetadata(
                chatId = chatId,
                messageId = message.id,
                metadata = textMetadata(message),
                recipientsOverride = remoteRecipients
            ) ?: return@launch
            val accepted = try {
                chatTransport.sendEncryptedPayload(chatId, encrypted)
            } finally {
                wipeEncryptedPayload(encrypted)
            }
            if (accepted) {
                rememberOwnMessageId(message.id)
                messageRepository.saveMessage(chatId, message)
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
        val effectiveTimerSec = effectiveRetentionSec(chatId, selfDestructSec, mediaType)
        val absoluteExpirySec = effectiveAbsoluteExpirySec(chatId, mediaType)
        if (bytes.isEmpty() || bytes.size > attachmentLimitBytes(mediaType) || !isMediaAllowed(chatId, mediaType)) {
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

        val uploadJob = viewModelScope.launch {
            _attachmentError.value = null
            _attachmentUploadProgress.value = AttachmentUploadProgress(
                active = true,
                fileName = fileName.ifBlank { "attachment" },
                mediaType = mediaType,
                totalBytes = bytes.size.toLong()
            )
            var attachmentKey: ByteArray? = null
            var messageToWipe: Message? = null
            var uploadedAttachmentId: String? = null
            var metadataAccepted = false
            try {
                val sender = currentUser.value ?: return@launch
                val metadataRecipients = recipientIdentities(chatId, includeSelf = false)
                if (metadataRecipients == null || isLocalOnlyForum(chatId, metadataRecipients)) {
                    _attachmentError.value = "Wrong information."
                    return@launch
                }
                val normalizedMediaType = mediaType.uppercase(Locale.ROOT)
                val messageId = UUID.randomUUID().toString()
                val attachmentPayload = runCatching {
                    encryptAttachmentBlob(
                        chatId = chatId,
                        messageId = messageId,
                        senderUsername = sender.username,
                        mediaType = normalizedMediaType,
                        plaintext = bytes
                    )
                }.getOrElse {
                    _attachmentError.value = "Wrong information."
                    return@launch
                }
                val key = attachmentPayload.key
                val blob = attachmentPayload.blob
                attachmentKey = key
                if (!isValidAttachmentCiphertext(
                        version = attachmentPayload.version.toInt(),
                        key = key,
                        blob = blob,
                        mediaType = normalizedMediaType
                    )
                ) {
                    _attachmentError.value = "Wrong information."
                    return@launch
                }
                try {
                    val upload = attachmentService.uploadEncryptedAttachment(
                        chatId = chatId,
                        mediaType = normalizedMediaType,
                        encryptedBytes = blob,
                        oneTimeView = oneTimeView,
                        deleteAfterDownload = deleteAfterDownload,
                        ttlSec = absoluteExpirySec,
                        onProgress = { sent, total ->
                            _attachmentUploadProgress.value = AttachmentUploadProgress(
                                active = true,
                                fileName = fileName.ifBlank { "attachment" },
                                mediaType = normalizedMediaType,
                                bytesSent = sent.coerceAtMost(total),
                                totalBytes = total
                            )
                        }
                    )
                    val attachmentId = upload.attachmentId?.let(::normalizeAttachmentId)
                    uploadedAttachmentId = attachmentId
                    if (!upload.accepted || attachmentId == null) {
                        _attachmentError.value = "Wrong information."
                        return@launch
                    }

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
                        senderPublicKey = sender.publicKey.copyOf()
                    )
                    messageToWipe = message
                    val encryptedMetadata = encryptMetadata(
                        chatId = chatId,
                        messageId = message.id,
                        metadata = attachmentMetadata(message),
                        recipientsOverride = metadataRecipients
                    ) ?: run {
                        wipeMessageSecrets(message)
                        _attachmentError.value = "Wrong information."
                        return@launch
                    }
                    val accepted = try {
                        chatTransport.sendEncryptedPayload(chatId, encryptedMetadata)
                    } finally {
                        wipeEncryptedPayload(encryptedMetadata)
                    }
                    if (accepted) {
                        metadataAccepted = true
                        rememberOwnMessageId(message.id)
                        messageSender.saveLocalAttachmentMessage(chatId, message)
                    } else {
                        wipeMessageSecrets(message)
                        _attachmentError.value = "Wrong information."
                    }
                } finally {
                    blob.fill(0)
                }
            } finally {
                if (shouldDeleteUploadedAttachment(uploadedAttachmentId, metadataAccepted)) {
                    withContext(NonCancellable) {
                        runCatching {
                            attachmentService.deleteUploadedAttachment(requireNotNull(uploadedAttachmentId))
                        }
                    }
                }
                messageToWipe?.let(::wipeMessageSecrets)
                attachmentKey?.fill(0)
                bytes.fill(0)
                _attachmentUploadProgress.value = AttachmentUploadProgress()
            }
        }
        attachmentUploadJob = uploadJob
        uploadJob.invokeOnCompletion {
            if (attachmentUploadJob === uploadJob) attachmentUploadJob = null
        }
    }

    private fun launchAttachmentOperation(block: suspend () -> Unit): Job {
        val job = viewModelScope.launch(start = CoroutineStart.LAZY) { block() }
        attachmentJobs += job
        job.invokeOnCompletion { attachmentJobs.remove(job) }
        job.start()
        return job
    }

    private fun cancelAttachmentOperations() {
        val jobs = synchronized(attachmentJobs) { attachmentJobs.toList() }
        jobs.forEach(Job::cancel)
    }

    fun viewAttachment(message: Message) {
        val chatId = _activeChatId.value ?: return
        val attachmentId = message.attachmentId ?: return
        val generation = sessionGeneration.get()
        if (!activeAttachmentViews.add(attachmentId)) return
        if (message.oneTimeView && !consumedOneTimeAttachments.add(attachmentId)) {
            activeAttachmentViews.remove(attachmentId)
            return
        }
        launchAttachmentOperation viewAttachmentOperation@{
            var plaintext: ByteArray? = null
            var previewInstalled = false
            try {
                _attachmentError.value = null
                val downloaded = attachmentService.downloadEncryptedAttachment(attachmentId)
                plaintext = downloaded?.let { encrypted ->
                    decryptAndCompleteAttachment(
                        downloaded = encrypted,
                        decrypt = {
                            if (!isSessionGenerationValid(generation)) null
                            else decryptAttachment(chatId, message, encrypted.bytes)
                        },
                        complete = { claim ->
                            if (!isSessionGenerationValid(generation)) false
                            else attachmentService.completeAttachmentDownload(attachmentId, claim)
                        },
                        release = { claim ->
                            attachmentService.releaseAttachmentDownloadClaim(attachmentId, claim)
                        }
                    )
                }
                if (plaintext == null) {
                    if (message.oneTimeView) consumedOneTimeAttachments.remove(attachmentId)
                    _attachmentError.value = "Wrong information."
                    return@viewAttachmentOperation
                }
                val installed = attachmentSessionGate.withLock {
                    if (!isSessionGenerationValid(generation)) {
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
        if (!AttachmentSavePolicy.canSave(message)) return
        val chatId = _activeChatId.value ?: return
        val attachmentId = message.attachmentId ?: return
        val generation = sessionGeneration.get()
        launchAttachmentOperation saveAttachmentOperation@{
            _attachmentError.value = null
            var temporaryBytes: ByteArray? = null
            try {
                val cachedAttachment = _attachmentPreview.value?.takeIf { it.messageId == message.id }
                val attachment = cachedAttachment ?: run {
                    val downloaded = attachmentService.downloadEncryptedAttachment(attachmentId)
                    val bytes = downloaded?.let { encrypted ->
                        decryptAndCompleteAttachment(
                            downloaded = encrypted,
                            decrypt = {
                                if (!isSessionGenerationValid(generation)) null
                                else decryptAttachment(chatId, message, encrypted.bytes)
                            },
                            complete = { claim ->
                                if (!isSessionGenerationValid(generation)) false
                                else attachmentService.completeAttachmentDownload(attachmentId, claim)
                            },
                            release = { claim ->
                                attachmentService.releaseAttachmentDownloadClaim(attachmentId, claim)
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
                if (!isSessionGenerationValid(generation)) return@saveAttachmentOperation
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
        viewModelScope.launch {
            val message = activeMessages.value.firstOrNull { it.id == messageId }
            messageRepository.markAsRead(chatId, messageId)
            if (message != null && message.sender != "You" && serverStatus.value.state == "CONNECTED") {
                val receiptId = UUID.randomUUID().toString()
                val metadata = JSONObject()
                    .put("kind", "read_receipt")
                    .put("message_id", messageId)
                    .toString()
                encryptMetadata(chatId, receiptId, metadata)?.let { encrypted ->
                    try {
                        chatTransport.sendEncryptedPayload(chatId, encrypted)
                    } finally {
                        wipeEncryptedPayload(encrypted)
                    }
                }
            }
        }
    }

    fun executeClearAll() {
        viewModelScope.launch {
            chatTransport.broadcastGlobalWipe()
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
            chatTransport.createForum(session)
        }
    }

    fun deleteForum(chatId: String) {
        viewModelScope.launch {
            chatTransport.deleteForum(chatId)
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
        viewModelScope.launch { chatTransport.openDirect(peer) }
    }

    private suspend fun joinAvailableSessions() {
        sessions.value.forEach { session -> chatTransport.joinChat(session.id) }
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
            viewModelScope.launch { chatTransport.signalUserActivity() }
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
        calculatorEvaluationJob?.cancel()
        val job = viewModelScope.launch(Dispatchers.Default) {
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
                        _calculatorDisplay.value = "0"
                        viewModelScope.launch { executeDuressWipe() }
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
        }
        calculatorEvaluationJob = job
        job.invokeOnCompletion {
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

    private suspend fun executeDuressWipe() {
        runCatching { chatTransport.broadcastGlobalWipe() }
        logoutLocal()
        _isLocked.value = true
        _calculatorDisplay.value = "0"
    }

    /**
     * Redacts all local session state synchronously. Network revocation stays outside
     * this boundary so lifecycle/logout never leaves a renderable authenticated frame.
     */
    private fun prepareLocalLogout(): NodeSession? {
        // Cancel before clearing state. Account-entry continuations also check their
        // coroutine activity before installing returned identity material.
        accountEntryJob?.cancel()
        accountEntryJob = null
        cancelAttachmentOperations()
        attachmentUploadJob?.cancel()
        attachmentUploadJob = null
        sessionGeneration.incrementAndGet()
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
        _roomCreationLimit.value = DEFAULT_MAX_ROOMS_PER_USER
        updateSessionSecurityState()
        messageRepository.clearAllDataNow()
        identityService.logout()
        nodeConfigService.clear()
        payloadCipher.clear()
        chatTransport.disconnect()
        _currentUser.value?.publicKey?.fill(0)
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

    private fun isSessionGenerationValid(generation: Long): Boolean =
        generation == sessionGeneration.get() &&
            currentUser.value != null &&
            sessionInactivityPolicy.isActive()

    private fun elapsedRealtimeMs(): Long = System.nanoTime() / 1_000_000L

    private fun encryptMetadata(
        chatId: String,
        messageId: String,
        metadata: String,
        recipientsOverride: List<RecipientIdentity>? = null
    ): EncryptedTransportPayload? {
        val sender = currentUser.value ?: return null
        val recipients = recipientsOverride ?: recipientIdentities(chatId, includeSelf = false) ?: return null
        val plainBytes = metadata.toByteArray(StandardCharsets.UTF_8)
        return try {
            payloadCipher.encrypt(
                chatId = chatId,
                messageId = messageId,
                senderUsername = sender.username,
                plainBytes = plainBytes,
                recipients = recipients
            )
        } catch (_: Exception) {
            null
        } finally {
            plainBytes.fill(0)
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
                    maxBytes = attachmentLimitBytes(mediaType)
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
        decryptedContent: String,
        authoritativeSender: String,
        senderPublicKey: ByteArray
    ): Message? {
        val json = runCatching { JSONObject(decryptedContent) }.getOrNull()
        val sender = authoritativeSender
            .takeIf { it.isNotBlank() }
            ?: json?.optString("sender")?.takeIf { it.isNotBlank() }
            ?: "Remote node"
        if (sender == currentUser.value?.username) return null
        val replyToMessageId = json?.replyToMessageId()
        val repliesToCurrentUser = MessageAttentionPolicy.replyTargetsCurrentUser(
            senderUsername = sender,
            currentUsername = currentUser.value?.username,
            replyToMessageId = replyToMessageId,
            ownMessageIds = ownMessageIds
        )

        if (json?.optString("kind") == "attachment") {
            val mediaType = json.optString("media_type", "FILE")
                .uppercase(Locale.ROOT)
                .takeIf { it in SUPPORTED_MEDIA_TYPES }
                ?: return null
            val attachmentId = normalizeAttachmentId(json.optString("attachment_id")) ?: return null
            val attachmentCipherVersion = json.optInt("attachment_cipher_version", -1)
            if (attachmentCipherVersion != ATTACHMENT_CIPHER_VERSION) return null
            val sizeBytes = json.optLong("size_bytes", -1L)
            if (sizeBytes !in 1L..attachmentLimitBytes(mediaType)) return null
            val attachmentKey = decodeAttachmentKey(json.optString("attachment_key_b64")) ?: return null
            val fileName = AttachmentSavePolicy.sanitizedFileName(json.optString("name", "attachment"))
            val mimeType = safeMimeType(json.optString("mime_type", "application/octet-stream"))
            val messageId = MessageReplyPolicy.sanitizeMessageId(json.optString("id"))
                ?: return null
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

        if (json?.optString("kind") == "text") {
            val content = json.optString("content")
                .takeIf { it.isNotBlank() && it.length <= MAX_TEXT_MESSAGE_CHARS }
                ?: return null
            val messageId = MessageReplyPolicy.sanitizeMessageId(json.optString("id")) ?: return null
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

        if (decryptedContent.length > MAX_TEXT_MESSAGE_CHARS) return null
        val retainedSenderPublicKey = senderPublicKey.copyOf()
        return Message(
            id = UUID.randomUUID().toString(),
                sender = sender,
            receiver = if (chatId.startsWith("dm_")) "You" else null,
            content = decryptedContent,
            timestampMs = System.currentTimeMillis(),
            selfDestructDurationSec = effectiveRetentionSec(chatId, 10),
            absoluteExpirySec = effectiveAbsoluteExpirySec(chatId, null),
            mentionsCurrentUser = MessageAttentionPolicy.mentionsUsername(
                decryptedContent,
                currentUser.value?.username
            ),
            senderPublicKey = retainedSenderPublicKey
        )
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

    private fun attachmentLimitBytes(mediaType: String): Long {
        return when (mediaType.uppercase()) {
            "IMAGE" -> IMAGE_ATTACHMENT_BYTES
            "VIDEO" -> VIDEO_ATTACHMENT_BYTES
            else -> FILE_ATTACHMENT_BYTES
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

    private fun textMetadata(message: Message): String {
        return JSONObject()
            .put("kind", "text")
            .put("id", message.id)
            .put("sender", currentUser.value?.username.orEmpty())
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
            blobSize in ATTACHMENT_WIRE_OVERHEAD_BYTES..(attachmentLimitBytes(mediaType) + ATTACHMENT_WIRE_OVERHEAD_BYTES) &&
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
        cancelAttachmentOperations()
        attachmentUploadJob?.cancel()
        attachmentUploadJob = null
        cancelCalculatorEvaluation()
        activeAttachmentViews.clear()
        consumedOneTimeAttachments.clear()
        ownMessageIds.clear()
        receivedFrameIds.clear()
        replaceAttachmentPreview(null)
        messageRepository.clearAllDataNow()
        messageRepository.close()
        disguiseManager.clear()
        _currentUser.value?.publicKey?.fill(0)
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
        const val IMAGE_ATTACHMENT_BYTES = 20L * 1024L * 1024L
        const val VIDEO_ATTACHMENT_BYTES = 100L * 1024L * 1024L
        const val FILE_ATTACHMENT_BYTES = 200L * 1024L * 1024L
        const val MAX_TEXT_MESSAGE_CHARS = 64 * 1024
        private const val MAX_DECRYPTED_MESSAGE_BYTES = 64 * 1024
        private val SUPPORTED_MEDIA_TYPES = setOf("IMAGE", "VIDEO", "FILE")
        private const val DEFAULT_SESSION_INACTIVITY_SEC = 15 * 60
        private const val SESSION_WATCHDOG_INTERVAL_MS = 1_000L
        private const val REMOTE_ACTIVITY_SIGNAL_INTERVAL_MS = 15_000L
        private const val DEFAULT_MAX_ROOMS_PER_USER = 5
        private const val IDENTITY_PUBLIC_KEY_BYTES = 128
        private const val MAX_RECEIVED_FRAME_IDS = 10_000
        private const val MAX_OWN_MESSAGE_IDS = 10_000
        private const val EXTERNAL_SYSTEM_UI_TIMEOUT_MS = 5 * 60 * 1_000L
        private const val EXTERNAL_SYSTEM_UI_RESULT_GRACE_MS = 2_000L
    }
}

package com.abyssal.chat.presentation.viewmodel

import android.net.Uri
import androidx.compose.runtime.State
import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.abyssal.chat.data.network.InMemoryPayloadCipher
import com.abyssal.chat.domain.model.AttachmentUploadProgress
import com.abyssal.chat.domain.model.ChatSession
import com.abyssal.chat.domain.model.DecryptedAttachment
import com.abyssal.chat.domain.model.DisguiseSettings
import com.abyssal.chat.domain.model.Message
import com.abyssal.chat.domain.model.MessageAttentionPolicy
import com.abyssal.chat.domain.model.MessageReplyPolicy
import com.abyssal.chat.domain.model.NodeSession
import com.abyssal.chat.domain.model.ServerStatus
import com.abyssal.chat.domain.model.SessionInactivityPolicy
import com.abyssal.chat.domain.model.SessionSecurityState
import com.abyssal.chat.domain.model.User
import com.abyssal.chat.domain.model.UserPresence
import com.abyssal.chat.domain.repository.IChatTransport
import com.abyssal.chat.domain.repository.IDisguiseManager
import com.abyssal.chat.domain.repository.IEncryptedAttachmentService
import com.abyssal.chat.domain.repository.IIdentityService
import com.abyssal.chat.domain.repository.IMessageRepository
import com.abyssal.chat.domain.repository.IMessageSender
import com.abyssal.chat.domain.repository.INodeConfigService
import java.security.SecureRandom
import java.util.UUID
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONObject

sealed class Screen {
    object Entrance : Screen()
    object Dashboard : Screen()
    data class Chat(val sessionId: String) : Screen()
}

@OptIn(ExperimentalCoroutinesApi::class)
class ChatViewModel(
    private val identityService: IIdentityService,
    private val nodeConfigService: INodeConfigService,
    private val messageRepository: IMessageRepository,
    private val messageSender: IMessageSender,
    private val chatTransport: IChatTransport,
    private val attachmentService: IEncryptedAttachmentService,
    private val disguiseManager: IDisguiseManager,
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

    private val sessionInactivityPolicy = SessionInactivityPolicy()
    private val _sessionSecurity = MutableStateFlow(SessionSecurityState())
    val sessionSecurity: StateFlow<SessionSecurityState> = _sessionSecurity.asStateFlow()

    private val _roomCreationLimit = MutableStateFlow(DEFAULT_MAX_ROOMS_PER_USER)
    val roomCreationLimit: StateFlow<Int> = _roomCreationLimit.asStateFlow()

    private var retainSessionInBackground = false
    private var sessionInactivityTimeoutSec = DEFAULT_SESSION_INACTIVITY_SEC
    private var externalSystemUiOpen = false
    private var lastRemoteActivitySignalMs = 0L
    private val ownMessageIds = mutableSetOf<String>()

    val sessions: StateFlow<List<ChatSession>> = messageRepository.getChatSessions()
        .stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    private val _activeChatId = MutableStateFlow<String?>(null)
    val activeMessages: StateFlow<List<Message>> = _activeChatId.flatMapLatest { id ->
        if (id != null) messageRepository.getMessages(id) else flowOf(emptyList())
    }.stateIn(viewModelScope, SharingStarted.Lazily, emptyList())

    init {
        _disguiseSettings.value = DisguiseSettings(
            isDisguised = disguiseManager.isDisguiseEnabled(),
            pin = disguiseManager.getPin(),
            duressPin = disguiseManager.getDuressPin()
        )
        _isLocked.value = disguiseManager.isDisguiseEnabled()

        viewModelScope.launch {
            chatTransport.getIncomingWipeCommands().collect {
                executeLocalMemoryPurge()
            }
        }

        viewModelScope.launch {
            chatTransport.getIncomingPayloads().collect { incoming ->
                val decryptedContent = runCatching { payloadCipher.decrypt(incoming.payload) }
                    .getOrElse { "Encrypted payload received." }
                val message = parseIncomingMessage(
                    incoming.chatId,
                    decryptedContent,
                    incoming.senderUsername
                ) ?: return@collect
                messageRepository.saveMessage(incoming.chatId, message)
            }
        }

        viewModelScope.launch {
            chatTransport.getRoomChanges().collect { change ->
                when (change.action) {
                    "upsert" -> change.session?.let { session ->
                        messageRepository.createForumSession(session)
                        chatTransport.joinChat(session.id)
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

    fun clearAccountError() {
        _inviteCodeError.value = null
    }

    fun submitAccount(
        code: String,
        nodeUrl: String,
        password: String,
        rememberSession: Boolean
    ) {
        viewModelScope.launch {
            _isVerifyingCode.value = true
            _inviteCodeError.value = null

            val endpoint = nodeConfigService.normalizeNodeUrl(nodeUrl).getOrElse {
                _inviteCodeError.value = "Wrong information."
                _isVerifyingCode.value = false
                return@launch
            }

            val validation = identityService.enterAccount(code, password, endpoint)
            if (validation.accepted && validation.token != null) {
                val nodeId = validation.nodeId ?: endpoint.displayHost
                val identity = User(
                    username = validation.username ?: "AbyssalUser",
                    publicKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
                )
                identityService.setCurrentUser(identity)
                payloadCipher.deriveSessionKey(nodeId)
                nodeConfigService.setActiveSession(
                    NodeSession(endpoint, validation.token, nodeId, validation.maxRoomsPerUser)
                )
                _currentUser.value = identity
                _roomCreationLimit.value = validation.maxRoomsPerUser
                retainSessionInBackground = rememberSession
                sessionInactivityTimeoutSec = validation.sessionInactivitySec
                sessionInactivityPolicy.start(sessionInactivityTimeoutSec * 1000L)
                updateSessionSecurityState()
                _isLocked.value = false
                if (validation.created) {
                    disguiseManager.setDisguiseEnabled(true)
                    _disguiseSettings.value = DisguiseSettings(isDisguised = true, pin = "")
                    _isLocked.value = false
                    _showCamouflagePinPrompt.value = true
                }
                chatTransport.connect()
                joinAvailableSessions()
                _currentScreen.value = Screen.Dashboard
            } else {
                _inviteCodeError.value = "Wrong information."
            }
            _isVerifyingCode.value = false
        }
    }

    fun sendMessage(content: String, selfDestructSec: Int, replyToMessageId: String? = null) {
        val chatId = _activeChatId.value ?: return
        if (serverStatus.value.state != "CONNECTED") return
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
            val accepted = chatTransport.sendEncryptedPayload(
                chatId,
                payloadCipher.encrypt(textMetadata(message))
            )
            if (accepted) {
                ownMessageIds += message.id
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
        val chatId = _activeChatId.value ?: return
        if (serverStatus.value.state != "CONNECTED") {
            _attachmentError.value = "Wrong information."
            return
        }
        val effectiveTimerSec = effectiveRetentionSec(chatId, selfDestructSec, mediaType)
        val absoluteExpirySec = effectiveAbsoluteExpirySec(chatId, mediaType)
        if (bytes.isEmpty() || bytes.size > attachmentLimitBytes(mediaType) || !isMediaAllowed(chatId, mediaType)) {
            _attachmentError.value = "Wrong information."
            return
        }
        val safeReactionShortcode = reactionShortcode?.let {
            MessageAttentionPolicy.validatedReactionShortcode(it, fileName, mimeType)
                ?: run {
                    _attachmentError.value = "Wrong information."
                    return
                }
        }

        viewModelScope.launch {
            _attachmentError.value = null
            _attachmentUploadProgress.value = AttachmentUploadProgress(
                active = true,
                fileName = fileName.ifBlank { "attachment" },
                mediaType = mediaType,
                totalBytes = bytes.size.toLong()
            )
            val encryptedBytes = payloadCipher.encryptBytes(bytes)
            val upload = attachmentService.uploadEncryptedAttachment(
                chatId = chatId,
                mediaType = mediaType,
                encryptedBytes = encryptedBytes,
                oneTimeView = oneTimeView,
                deleteAfterDownload = deleteAfterDownload,
                ttlSec = absoluteExpirySec,
                onProgress = { sent, total ->
                    _attachmentUploadProgress.value = AttachmentUploadProgress(
                        active = true,
                        fileName = fileName.ifBlank { "attachment" },
                        mediaType = mediaType,
                        bytesSent = sent.coerceAtMost(total),
                        totalBytes = total
                    )
                }
            )
            val attachmentId = upload.attachmentId
            if (!upload.accepted || attachmentId == null) {
                _attachmentError.value = "Wrong information."
                _attachmentUploadProgress.value = AttachmentUploadProgress()
                return@launch
            }

            val message = attachmentMessage(
                sender = "You",
                receiver = if (chatId.startsWith("dm_")) chatId.removePrefix("dm_") else null,
                attachmentId = attachmentId,
                mediaType = mediaType,
                fileName = fileName,
                mimeType = mimeType,
                sizeBytes = bytes.size.toLong(),
                selfDestructSec = effectiveTimerSec,
                absoluteExpirySec = absoluteExpirySec,
                oneTimeView = oneTimeView,
                deleteAfterDownload = deleteAfterDownload,
                replyToMessageId = validReplyTarget(replyToMessageId),
                reactionShortcode = safeReactionShortcode
            )
            val accepted = chatTransport.sendEncryptedPayload(
                chatId,
                payloadCipher.encrypt(attachmentMetadata(message))
            )
            if (accepted) {
                ownMessageIds += message.id
                messageSender.saveLocalAttachmentMessage(chatId, message)
            } else {
                _attachmentError.value = "Wrong information."
            }
            _attachmentUploadProgress.value = AttachmentUploadProgress()
        }
    }

    fun viewAttachment(message: Message) {
        val attachmentId = message.attachmentId ?: return
        viewModelScope.launch {
            _attachmentError.value = null
            val encrypted = attachmentService.downloadEncryptedAttachment(attachmentId)
            val bytes = encrypted?.let { runCatching { payloadCipher.decryptBytes(it) }.getOrNull() }
            if (bytes == null) {
                _attachmentError.value = "Wrong information."
                return@launch
            }
            _attachmentPreview.value = DecryptedAttachment(
                messageId = message.id,
                name = message.attachmentName ?: "attachment",
                mediaType = message.mediaType ?: "FILE",
                mimeType = message.attachmentMimeType ?: "application/octet-stream",
                bytes = bytes,
                oneTimeView = message.oneTimeView
            )
            markMessageAsRead(message.id)
        }
    }

    fun saveAttachment(message: Message, outputUri: Uri) {
        if (!message.saveAllowed || message.oneTimeView) return
        val attachmentId = message.attachmentId ?: return
        viewModelScope.launch {
            _attachmentError.value = null
            val cached = attachmentPreview.value?.takeIf { it.messageId == message.id }
            val attachment = cached ?: run {
                val encrypted = attachmentService.downloadEncryptedAttachment(attachmentId)
                val bytes = encrypted?.let { runCatching { payloadCipher.decryptBytes(it) }.getOrNull() }
                if (bytes == null) {
                    _attachmentError.value = "Wrong information."
                    return@launch
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
            if (!attachmentService.saveDecryptedAttachment(attachment, outputUri)) {
                _attachmentError.value = "Wrong information."
            }
            markMessageAsRead(message.id)
        }
    }

    fun dismissAttachmentPreview() {
        _attachmentPreview.value = null
    }

    fun markMessageAsRead(messageId: String) {
        val chatId = _activeChatId.value ?: return
        viewModelScope.launch {
            messageRepository.markAsRead(chatId, messageId)
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

    private suspend fun joinAvailableSessions() {
        sessions.value.forEach { session -> chatTransport.joinChat(session.id) }
    }

    fun updateDisguiseSettings(enabled: Boolean, pin: String, duressPin: String) {
        disguiseManager.setDisguiseEnabled(enabled)
        disguiseManager.savePin(pin)
        disguiseManager.saveDuressPin(duressPin)
        _disguiseSettings.value = DisguiseSettings(enabled, pin, duressPin)
    }

    fun completeCamouflagePinSetup(pin: String, duressPin: String) {
        val safePin = pin.ifBlank { "2026" }
        disguiseManager.setDisguiseEnabled(true)
        disguiseManager.savePin(safePin)
        disguiseManager.saveDuressPin(duressPin)
        _disguiseSettings.value = DisguiseSettings(isDisguised = true, pin = safePin, duressPin = duressPin)
        _showCamouflagePinPrompt.value = false
    }

    fun lockApp() {
        if (disguiseSettings.value.isDisguised) _isLocked.value = true
    }

    fun beginExternalSystemUi() {
        externalSystemUiOpen = true
        recordUserActivity()
    }

    fun endExternalSystemUi() {
        externalSystemUiOpen = false
        recordUserActivity()
    }

    fun lockForLifecycleExit() {
        if (externalSystemUiOpen || !sessionInactivityPolicy.isActive()) return
        if (disguiseSettings.value.isDisguised) _isLocked.value = true
        if (!retainSessionInBackground) endSession(lockBehindDisguise = true)
    }

    fun onHostResumed() {
        if (expireSessionIfNeeded()) return
        if (sessionInactivityPolicy.isActive()) chatTransport.connect()
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
        sessionInactivityPolicy.clear()
        updateSessionSecurityState()
        if (lockBehindDisguise && disguiseSettings.value.isDisguised) {
            _isLocked.value = true
        } else {
            _isLocked.value = false
        }
        viewModelScope.launch { logoutLocal(revokeRemote = true) }
    }

    fun onCalculatorInput(input: String) {
        val current = _calculatorDisplay.value
        when (input) {
            "C" -> _calculatorDisplay.value = "0"
            "⌫" -> _calculatorDisplay.value = current.dropLast(1).ifBlank { "0" }
            "=" -> _calculatorDisplay.value = evaluateExpression(current)
            "+", "-", "*", "/", "(", ")" -> {
                _calculatorDisplay.value = if (current == "0" || current == "Error") input else current + input
            }
            else -> _calculatorDisplay.value = if (current == "0" || current == "Error") input else current + input
        }
    }

    private fun evaluateExpression(expr: String): String {
        val cleanExpr = expr.replace(" ", "")
        if (disguiseManager.verifyDuressPin(cleanExpr)) {
            viewModelScope.launch {
                executeDuressWipe()
            }
            return "0"
        }
        if (disguiseManager.verifyPin(cleanExpr)) {
            if (expireSessionIfNeeded()) return "0"
            _isLocked.value = false
            if (sessionInactivityPolicy.isActive()) {
                sessionInactivityPolicy.touch()
                updateSessionSecurityState()
            }
            return "0"
        }
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

    private suspend fun logoutLocal(revokeRemote: Boolean = false) {
        val remoteSession = nodeConfigService.getActiveSession()
        sessionInactivityPolicy.clear()
        retainSessionInBackground = false
        lastRemoteActivitySignalMs = 0L
        _roomCreationLimit.value = DEFAULT_MAX_ROOMS_PER_USER
        updateSessionSecurityState()
        messageRepository.clearAllData()
        identityService.logout()
        nodeConfigService.clear()
        payloadCipher.clear()
        chatTransport.disconnect()
        _currentUser.value = null
        _currentScreen.value = Screen.Entrance
        _showCamouflagePinPrompt.value = false
        _attachmentPreview.value = null
        _attachmentError.value = null
        _attachmentUploadProgress.value = AttachmentUploadProgress()
        ownMessageIds.clear()
        if (revokeRemote && remoteSession != null) {
            identityService.revokeSession(remoteSession)
        }
    }

    private fun expireSessionIfNeeded(): Boolean {
        if (!sessionInactivityPolicy.isExpired()) return false
        sessionInactivityPolicy.clear()
        updateSessionSecurityState()
        if (disguiseSettings.value.isDisguised) _isLocked.value = true
        viewModelScope.launch { logoutLocal(revokeRemote = true) }
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

    private fun elapsedRealtimeMs(): Long = System.nanoTime() / 1_000_000L

    private fun parseIncomingMessage(
        chatId: String,
        decryptedContent: String,
        authoritativeSender: String?
    ): Message? {
        val json = runCatching { JSONObject(decryptedContent) }.getOrNull()
        val sender = authoritativeSender
            ?.takeIf { it.isNotBlank() }
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
            val fileName = json.optString("name", "attachment")
            val mimeType = json.optString("mime_type", "application/octet-stream")
            return attachmentMessage(
                messageId = json.optString("id").takeIf { it.isNotBlank() } ?: UUID.randomUUID().toString(),
                sender = sender,
                receiver = if (chatId.startsWith("dm_")) "You" else null,
                attachmentId = json.optString("attachment_id"),
                mediaType = json.optString("media_type", "FILE"),
                fileName = fileName,
                mimeType = mimeType,
                sizeBytes = json.optLong("size_bytes", 0L),
                selfDestructSec = effectiveRetentionSec(chatId, json.optInt("self_destruct_sec", 10), json.optString("media_type", "FILE")),
                absoluteExpirySec = effectiveAbsoluteExpirySec(chatId, json.optString("media_type", "FILE")),
                oneTimeView = json.optBoolean("one_time", false),
                deleteAfterDownload = json.optBoolean("delete_after_download", false),
                replyToMessageId = replyToMessageId,
                reactionShortcode = MessageAttentionPolicy.validatedReactionShortcode(
                    json.optString("reaction_shortcode").takeIf { it.isNotBlank() },
                    fileName,
                    mimeType
                ),
                repliesToCurrentUser = repliesToCurrentUser
            )
        }

        if (json?.optString("kind") == "text") {
            val content = json.optString("content").takeIf { it.isNotBlank() } ?: return null
            return Message(
                id = json.optString("id").takeIf { it.isNotBlank() } ?: UUID.randomUUID().toString(),
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
                repliesToCurrentUser = repliesToCurrentUser
            )
        }

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
            )
        )
    }

    private fun effectiveRetentionSec(chatId: String, requestedSec: Int, mediaType: String? = null): Int {
        val session = sessions.value.find { it.id == chatId }
        if (session?.isForum != true) return requestedSec.coerceAtLeast(1)
        return when (mediaType?.uppercase()) {
            "IMAGE" -> session.imageReadTimerSec
            "VIDEO" -> session.videoReadTimerSec
            "FILE" -> session.fileReadTimerSec
            else -> session.selfDestructTimerSec
        }.coerceAtLeast(1)
    }

    private fun effectiveAbsoluteExpirySec(chatId: String, mediaType: String?): Int {
        val session = sessions.value.find { it.id == chatId }
        if (session?.isForum != true) return 0
        return when (mediaType?.uppercase()) {
            "IMAGE" -> if (session.enforceImageAbsoluteExpiry) session.imageOverallExpirySec else 0
            "VIDEO" -> if (session.enforceVideoAbsoluteExpiry) session.videoOverallExpirySec else 0
            "FILE" -> if (session.enforceFileAbsoluteExpiry) session.fileOverallExpirySec else 0
            else -> if (session.enforceTextAbsoluteExpiry) session.overallExpirySec else 0
        }.coerceAtLeast(0)
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
        repliesToCurrentUser: Boolean = false
    ): Message {
        val safeName = fileName.ifBlank { "attachment" }
        return Message(
            id = messageId,
            sender = sender,
            receiver = receiver,
            content = safeName,
            timestampMs = System.currentTimeMillis(),
            selfDestructDurationSec = selfDestructSec,
            isMedia = true,
            mediaType = mediaType,
            mediaSizeMb = ((sizeBytes + 1024 * 1024 - 1) / (1024 * 1024)).toInt().coerceAtLeast(1),
            attachmentId = attachmentId,
            attachmentName = safeName,
            attachmentMimeType = mimeType.ifBlank { "application/octet-stream" },
            attachmentSizeBytes = sizeBytes,
            oneTimeView = oneTimeView,
            saveAllowed = !oneTimeView,
            deleteAfterDownload = deleteAfterDownload,
            absoluteExpirySec = absoluteExpirySec,
            replyToMessageId = replyToMessageId,
            reactionShortcode = reactionShortcode,
            repliesToCurrentUser = repliesToCurrentUser
        )
    }

    private fun attachmentMetadata(message: Message): String {
        return JSONObject()
            .put("kind", "attachment")
            .put("id", message.id)
            .put("sender", currentUser.value?.username.orEmpty())
            .put("attachment_id", message.attachmentId)
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
            .toString()
    }

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

    override fun onCleared() {
        ownMessageIds.clear()
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
        private const val DEFAULT_SESSION_INACTIVITY_SEC = 15 * 60
        private const val SESSION_WATCHDOG_INTERVAL_MS = 1_000L
        private const val REMOTE_ACTIVITY_SIGNAL_INTERVAL_MS = 15_000L
        private const val DEFAULT_MAX_ROOMS_PER_USER = 5
    }
}

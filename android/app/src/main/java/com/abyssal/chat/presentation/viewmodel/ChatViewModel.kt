package com.abyssal.chat.presentation.viewmodel

import android.net.Uri
import androidx.compose.runtime.State
import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.abyssal.chat.data.network.InMemoryPayloadCipher
import com.abyssal.chat.domain.model.ChatSession
import com.abyssal.chat.domain.model.DecryptedAttachment
import com.abyssal.chat.domain.model.DisguiseSettings
import com.abyssal.chat.domain.model.Message
import com.abyssal.chat.domain.model.NodeSession
import com.abyssal.chat.domain.model.ServerStatus
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
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.stateIn
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

    private val _isLocked = MutableStateFlow(false)
    val isLocked: StateFlow<Boolean> = _isLocked.asStateFlow()

    private val _disguiseSettings = MutableStateFlow(DisguiseSettings())
    val disguiseSettings: StateFlow<DisguiseSettings> = _disguiseSettings.asStateFlow()

    private val _calculatorDisplay = MutableStateFlow("0")
    val calculatorDisplay: StateFlow<String> = _calculatorDisplay.asStateFlow()

    val sessions: StateFlow<List<ChatSession>> = messageRepository.getChatSessions()
        .stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    private val _activeChatId = MutableStateFlow<String?>(null)
    val activeMessages: StateFlow<List<Message>> = _activeChatId.flatMapLatest { id ->
        if (id != null) messageRepository.getMessages(id) else flowOf(emptyList())
    }.stateIn(viewModelScope, SharingStarted.Lazily, emptyList())

    init {
        _disguiseSettings.value = DisguiseSettings(
            isDisguised = disguiseManager.isDisguiseEnabled(),
            pin = disguiseManager.getPin()
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
                messageRepository.saveMessage(
                    incoming.chatId,
                    parseIncomingMessage(incoming.chatId, decryptedContent)
                )
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

    fun submitAccount(code: String, nodeUrl: String, password: String) {
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
                    publicKey = ByteArray(32).also { SecureRandom().nextBytes(it) },
                    isAdmin = validation.isAdmin
                )
                identityService.setCurrentUser(identity)
                payloadCipher.deriveSessionKey(nodeId)
                nodeConfigService.setActiveSession(
                    NodeSession(endpoint, validation.token, nodeId, validation.isAdmin)
                )
                _currentUser.value = identity
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

    fun sendMessage(content: String, selfDestructSec: Int) {
        val chatId = _activeChatId.value ?: return
        viewModelScope.launch {
            messageSender.sendMessage(chatId, content, selfDestructSec)
            chatTransport.sendEncryptedPayload(chatId, payloadCipher.encrypt(content))
        }
    }

    fun sendAttachment(
        mediaType: String,
        fileName: String,
        mimeType: String,
        bytes: ByteArray,
        selfDestructSec: Int,
        oneTimeView: Boolean,
        deleteAfterDownload: Boolean
    ) {
        val chatId = _activeChatId.value ?: return
        if (bytes.isEmpty() || bytes.size > MAX_ATTACHMENT_BYTES) {
            _attachmentError.value = "Wrong information."
            return
        }

        viewModelScope.launch {
            _attachmentError.value = null
            val encryptedBytes = payloadCipher.encryptBytes(bytes)
            val upload = attachmentService.uploadEncryptedAttachment(
                chatId = chatId,
                encryptedBytes = encryptedBytes,
                oneTimeView = oneTimeView,
                deleteAfterDownload = deleteAfterDownload,
                ttlSec = selfDestructSec
            )
            val attachmentId = upload.attachmentId
            if (!upload.accepted || attachmentId == null) {
                _attachmentError.value = "Wrong information."
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
                selfDestructSec = selfDestructSec,
                oneTimeView = oneTimeView,
                deleteAfterDownload = deleteAfterDownload
            )
            messageSender.saveLocalAttachmentMessage(chatId, message)
            chatTransport.sendEncryptedPayload(chatId, payloadCipher.encrypt(attachmentMetadata(message)))
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

    fun executeAdminClearAll() {
        viewModelScope.launch {
            chatTransport.broadcastGlobalWipe()
            executeLocalMemoryPurge()
        }
    }

    fun createForum(
        name: String,
        readExpirySec: Int,
        overallExpirySec: Int,
        allowImages: Boolean,
        allowVideos: Boolean,
        allowFiles: Boolean
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
                allowFiles = allowFiles
            )
            messageRepository.createForumSession(session)
            chatTransport.joinChat(forumId)
        }
    }

    private suspend fun joinAvailableSessions() {
        sessions.value.forEach { session -> chatTransport.joinChat(session.id) }
    }

    fun updateDisguiseSettings(enabled: Boolean, pin: String) {
        disguiseManager.setDisguiseEnabled(enabled)
        disguiseManager.savePin(pin)
        _disguiseSettings.value = DisguiseSettings(enabled, pin)
    }

    fun completeCamouflagePinSetup(pin: String) {
        val safePin = pin.ifBlank { "2026" }
        disguiseManager.setDisguiseEnabled(true)
        disguiseManager.savePin(safePin)
        _disguiseSettings.value = DisguiseSettings(isDisguised = true, pin = safePin)
        _showCamouflagePinPrompt.value = false
    }

    fun lockApp() {
        if (disguiseSettings.value.isDisguised) _isLocked.value = true
    }

    fun logoutForLifecycleExit() {
        viewModelScope.launch {
            logoutLocal()
            _isLocked.value = disguiseSettings.value.isDisguised
        }
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
        if (disguiseManager.verifyPin(cleanExpr)) {
            _isLocked.value = false
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

    private suspend fun logoutLocal() {
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
    }

    private fun parseIncomingMessage(chatId: String, decryptedContent: String): Message {
        val json = runCatching { JSONObject(decryptedContent) }.getOrNull()
        if (json?.optString("kind") == "attachment") {
            return attachmentMessage(
                sender = "Remote node",
                receiver = if (chatId.startsWith("dm_")) "You" else null,
                attachmentId = json.optString("attachment_id"),
                mediaType = json.optString("media_type", "FILE"),
                fileName = json.optString("name", "attachment"),
                mimeType = json.optString("mime_type", "application/octet-stream"),
                sizeBytes = json.optLong("size_bytes", 0L),
                selfDestructSec = json.optInt("self_destruct_sec", 10),
                oneTimeView = json.optBoolean("one_time", false),
                deleteAfterDownload = json.optBoolean("delete_after_download", false)
            )
        }

        return Message(
            id = UUID.randomUUID().toString(),
            sender = "Remote node",
            receiver = if (chatId.startsWith("dm_")) "You" else null,
            content = decryptedContent,
            timestampMs = System.currentTimeMillis(),
            selfDestructDurationSec = 10
        )
    }

    private fun attachmentMessage(
        sender: String,
        receiver: String?,
        attachmentId: String,
        mediaType: String,
        fileName: String,
        mimeType: String,
        sizeBytes: Long,
        selfDestructSec: Int,
        oneTimeView: Boolean,
        deleteAfterDownload: Boolean
    ): Message {
        val safeName = fileName.ifBlank { "attachment" }
        return Message(
            id = UUID.randomUUID().toString(),
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
            deleteAfterDownload = deleteAfterDownload
        )
    }

    private fun attachmentMetadata(message: Message): String {
        return JSONObject()
            .put("kind", "attachment")
            .put("attachment_id", message.attachmentId)
            .put("name", message.attachmentName)
            .put("media_type", message.mediaType)
            .put("mime_type", message.attachmentMimeType)
            .put("size_bytes", message.attachmentSizeBytes)
            .put("self_destruct_sec", message.selfDestructDurationSec)
            .put("one_time", message.oneTimeView)
            .put("delete_after_download", message.deleteAfterDownload)
            .toString()
    }

    override fun onCleared() {
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
        const val MAX_ATTACHMENT_BYTES = 100L * 1024L * 1024L
    }
}

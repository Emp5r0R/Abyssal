package com.abyssal.chat.presentation.viewmodel

import androidx.compose.runtime.State
import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.abyssal.chat.data.network.InMemoryPayloadCipher
import com.abyssal.chat.domain.model.ChatSession
import com.abyssal.chat.domain.model.Message
import com.abyssal.chat.domain.model.NodeSession
import com.abyssal.chat.domain.model.User
import com.abyssal.chat.domain.model.ServerStatus
import com.abyssal.chat.domain.model.DisguiseSettings
import com.abyssal.chat.domain.repository.IIdentityService
import com.abyssal.chat.domain.repository.IMessageRepository
import com.abyssal.chat.domain.repository.IMessageSender
import com.abyssal.chat.domain.repository.IChatTransport
import com.abyssal.chat.domain.repository.IDisguiseManager
import com.abyssal.chat.domain.repository.INodeConfigService
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
    private val disguiseManager: IDisguiseManager,
    private val payloadCipher: InMemoryPayloadCipher = InMemoryPayloadCipher()
) : ViewModel() {

    private val _currentScreen = MutableStateFlow<Screen>(Screen.Entrance)
    val currentScreen: StateFlow<Screen> = _currentScreen.asStateFlow()

    private val _currentUser = MutableStateFlow<User?>(null)
    val currentUser: StateFlow<User?> = _currentUser.asStateFlow()

    val serverStatus: StateFlow<ServerStatus> = chatTransport.getServerStatus()
        .stateIn(viewModelScope, SharingStarted.Lazily, ServerStatus("DISCONNECTED", "No node", 0))

    private val _inviteCodeError = mutableStateOf<String?>(null)
    val inviteCodeError: State<String?> = _inviteCodeError

    private val _isVerifyingCode = mutableStateOf(false)
    val isVerifyingCode: State<Boolean> = _isVerifyingCode

    // Camouflage disguise states
    private val _isLocked = MutableStateFlow(false)
    val isLocked: StateFlow<Boolean> = _isLocked.asStateFlow()

    private val _disguiseSettings = MutableStateFlow(DisguiseSettings())
    val disguiseSettings: StateFlow<DisguiseSettings> = _disguiseSettings.asStateFlow()

    private val _calculatorDisplay = MutableStateFlow("0")
    val calculatorDisplay: StateFlow<String> = _calculatorDisplay.asStateFlow()

    // Observe active sessions directly from repository
    val sessions: StateFlow<List<ChatSession>> = messageRepository.getChatSessions()
        .stateIn(viewModelScope, SharingStarted.Lazily, emptyList())

    // Track active chat messages reactively
    private val _activeChatId = MutableStateFlow<String?>(null)
    val activeMessages: StateFlow<List<Message>> = _activeChatId.flatMapLatest { id ->
        if (id != null) messageRepository.getMessages(id) else flowOf(emptyList())
    }.stateIn(viewModelScope, SharingStarted.Lazily, emptyList())

    init {
        // Load initial camouflage settings
        _disguiseSettings.value = DisguiseSettings(
            isDisguised = disguiseManager.isDisguiseEnabled(),
            pin = disguiseManager.getPin()
        )
        // If disguise is active, lock on startup
        _isLocked.value = disguiseManager.isDisguiseEnabled()

        // Observe network transport layer for global wipe signals
        viewModelScope.launch {
            chatTransport.getIncomingWipeCommands().collect {
                executeLocalMemoryPurge()
            }
        }

        viewModelScope.launch {
            chatTransport.getIncomingPayloads().collect { incoming ->
                val message = Message(
                    id = UUID.randomUUID().toString(),
                    sender = "Remote node",
                    receiver = "You",
                    content = "Encrypted payload received. Awaiting session key.",
                    timestampMs = System.currentTimeMillis(),
                    selfDestructDurationSec = 10
                )
                messageRepository.saveMessage(incoming.chatId, message)
            }
        }
    }

    fun navigateTo(screen: Screen) {
        _currentScreen.value = screen
        if (screen is Screen.Chat) {
            _activeChatId.value = screen.sessionId
            viewModelScope.launch {
                chatTransport.joinChat(screen.sessionId)
            }
        } else {
            _activeChatId.value = null
        }
    }

    fun submitInviteCode(code: String, nodeUrl: String) {
        viewModelScope.launch {
            _isVerifyingCode.value = true
            _inviteCodeError.value = null

            val endpoint = nodeConfigService.normalizeNodeUrl(nodeUrl).getOrElse {
                _inviteCodeError.value = it.message ?: "Invalid node URL."
                _isVerifyingCode.value = false
                return@launch
            }

            val validation = identityService.validateInviteCode(code, endpoint)
            if (validation.accepted && validation.token != null) {
                val generatedIdentity = identityService.generateRandomIdentity()
                val identity = generatedIdentity.copy(isAdmin = validation.isAdmin)
                nodeConfigService.setActiveSession(
                    NodeSession(
                        endpoint = endpoint,
                        token = validation.token,
                        nodeId = validation.nodeId ?: endpoint.displayHost,
                        isAdmin = validation.isAdmin
                    )
                )
                _currentUser.value = identity
                chatTransport.connect()
                _currentScreen.value = Screen.Dashboard
            } else {
                _inviteCodeError.value = validation.error ?: "Access denied by node."
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

    fun sendMedia(mediaType: String, fileName: String, sizeMb: Int, selfDestructSec: Int) {
        val chatId = _activeChatId.value ?: return
        viewModelScope.launch {
            messageSender.sendMediaMessage(chatId, mediaType, fileName, sizeMb, selfDestructSec)
            val mediaSummary = "$mediaType:$fileName:$sizeMb"
            chatTransport.sendEncryptedPayload(chatId, payloadCipher.encrypt(mediaSummary))
        }
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
        }
    }

    // Camouflage Disguise Management Actions
    fun updateDisguiseSettings(enabled: Boolean, pin: String) {
        disguiseManager.setDisguiseEnabled(enabled)
        disguiseManager.savePin(pin)
        _disguiseSettings.value = DisguiseSettings(enabled, pin)
    }

    fun lockApp() {
        if (disguiseSettings.value.isDisguised) {
            _isLocked.value = true
        }
    }

    // Calculator Operations Parsing
    fun onCalculatorInput(input: String) {
        val current = _calculatorDisplay.value
        when (input) {
            "C" -> _calculatorDisplay.value = "0"
            "=" -> {
                _calculatorDisplay.value = evaluateExpression(current)
            }
            "+", "-", "*", "/" -> {
                if (current != "Error" && current != "0") {
                    val lastChar = current.last().toString()
                    if (lastChar == "+" || lastChar == "-" || lastChar == "*" || lastChar == "/") {
                        _calculatorDisplay.value = current.dropLast(1) + input
                    } else {
                        _calculatorDisplay.value = current + input
                    }
                }
            }
            else -> { // Numbers and dot
                if (current == "0" || current == "Error") {
                    _calculatorDisplay.value = input
                } else {
                    _calculatorDisplay.value = current + input
                }
            }
        }
    }

    private fun evaluateExpression(expr: String): String {
        return try {
            // Secure Hook: Check if calculated expression matches camouflage unlock PIN
            if (disguiseManager.verifyPin(expr)) {
                _isLocked.value = false
                return "0"
            }
            
            val cleanExpr = expr.replace(" ", "")
            val regex = Regex("(-?\\d+\\.?\\d*)([+\\-*/])(-?\\d+\\.?\\d*)")
            val match = regex.matchEntire(cleanExpr)
            if (match != null) {
                val num1 = match.groupValues[1].toDouble()
                val op = match.groupValues[2]
                val num2 = match.groupValues[3].toDouble()
                val res = when (op) {
                    "+" -> num1 + num2
                    "-" -> num1 - num2
                    "*" -> num1 * num2
                    "/" -> if (num2 != 0.0) num1 / num2 else Double.NaN
                    else -> 0.0
                }
                if (res.isNaN()) "Error" else {
                    if (res % 1.0 == 0.0) res.toLong().toString() else res.toString()
                }
            } else {
                if (disguiseManager.verifyPin(cleanExpr)) {
                    _isLocked.value = false
                    "0"
                } else {
                    cleanExpr
                }
            }
        } catch (e: Exception) {
            "Error"
        }
    }

    private suspend fun executeLocalMemoryPurge() {
        messageRepository.clearAllData()
        identityService.logout()
        nodeConfigService.clear()
        chatTransport.disconnect()
        _currentUser.value = null
        _currentScreen.value = Screen.Entrance
    }

    override fun onCleared() {
        chatTransport.disconnect()
        super.onCleared()
    }
}

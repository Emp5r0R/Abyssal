package com.abyssal.chat.data.repository

import com.abyssal.chat.domain.model.ChatSession
import com.abyssal.chat.domain.model.Message
import com.abyssal.chat.domain.repository.IMessageRepository
import com.abyssal.chat.domain.repository.IMessageSender
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.util.UUID

class InMemoryMessageRepository : IMessageRepository, IMessageSender {
    private val scope = CoroutineScope(Dispatchers.Default + Job())

    private val _sessions = MutableStateFlow<List<ChatSession>>(emptyList())
    private val _messages = MutableStateFlow<Map<String, List<Message>>>(emptyMap())

    init {
        val cyberFoxId = "dm_cyberfox"
        val neoRiderId = "dm_neorider"
        val voltStaticId = "dm_voltstatic"

        // Emojis removed, wordlists only. No default forums created.
        val initialSessions = listOf(
            ChatSession(cyberFoxId, "SilentWolf482", isForum = false, lastMessage = null, unreadCount = 2, selfDestructTimerSec = 5),
            ChatSession(neoRiderId, "NebulaTiger93", isForum = false, lastMessage = null, unreadCount = 1, selfDestructTimerSec = 10),
            ChatSession(voltStaticId, "StaticCore108", isForum = false, lastMessage = null, unreadCount = 0, selfDestructTimerSec = 7)
        )

        val initialMessages = mapOf(
            cyberFoxId to listOf(
                Message(UUID.randomUUID().toString(), "SilentWolf482", "You", "Identity derived. E2EE handshake confirmed.", System.currentTimeMillis() - 10000, 5)
            ),
            neoRiderId to listOf(
                Message(UUID.randomUUID().toString(), "NebulaTiger93", "You", "Ready for secure deployment.", System.currentTimeMillis() - 20000, 10)
            ),
            voltStaticId to listOf(
                Message(UUID.randomUUID().toString(), "StaticCore108", "You", "Handshake active. Session keys locked.", System.currentTimeMillis() - 5000, 7)
            )
        )

        _sessions.value = initialSessions
        _messages.value = initialMessages

        updateLastMessages()
        startMemorySweeper()
    }

    private fun updateLastMessages() {
        val currentMsgs = _messages.value
        _sessions.value = _sessions.value.map { session ->
            val msgs = currentMsgs[session.id] ?: emptyList()
            val last = msgs.lastOrNull()
            
            // Mask actual message content in personal DM previews
            val previewMsg = last?.let { msg ->
                if (!session.isForum) {
                    msg.copy(content = "Message received")
                } else {
                    msg
                }
            }
            
            session.copy(lastMessage = previewMsg)
        }
    }

    private fun startMemorySweeper() {
        scope.launch {
            while (isActive) {
                delay(100) // Fast 100ms sweep cycle
                val now = System.currentTimeMillis()
                var updated = false
                
                val cleanMessages = _messages.value.mapValues { (chatId, list) ->
                    val session = _sessions.value.find { it.id == chatId }
                    val overallLimit = session?.overallExpirySec ?: 0
                    
                    val filtered = list.filter { msg ->
                        // 1. Overall absolute self-destruct check (expires regardless of read or not)
                        if (overallLimit > 0) {
                            val elapsed = now - msg.timestampMs
                            if (elapsed >= overallLimit * 1000L) {
                                updated = true
                                return@filter false
                            }
                        }
                        
                        // 2. Read-destruct check (expires X seconds after read)
                        val readTime = msg.readTimestampMs
                        if (readTime != null) {
                            val elapsed = now - readTime
                            val keep = elapsed < msg.selfDestructDurationSec * 1000L
                            if (!keep) updated = true
                            keep
                        } else {
                            true
                        }
                    }
                    filtered
                }

                if (updated) {
                    _messages.value = cleanMessages
                    updateLastMessages()
                }
            }
        }
    }

    override fun getChatSessions(): Flow<List<ChatSession>> = _sessions.asStateFlow()

    override fun getMessages(chatId: String): Flow<List<Message>> {
        return _messages.map { map -> map[chatId] ?: emptyList() }
    }

    override suspend fun saveMessage(chatId: String, message: Message) {
        val currentChatMsgs = _messages.value[chatId]?.toMutableList() ?: mutableListOf()
        currentChatMsgs.add(message)
        _messages.value = _messages.value.toMutableMap().apply { put(chatId, currentChatMsgs) }
        updateLastMessages()
    }

    override suspend fun createForumSession(session: ChatSession) {
        val current = _sessions.value.toMutableList()
        current.add(session)
        _sessions.value = current
        _messages.value = _messages.value.toMutableMap().apply { put(session.id, emptyList()) }
        updateLastMessages()
    }

    override suspend fun sendMessage(chatId: String, content: String, selfDestructSec: Int) {
        val messageId = UUID.randomUUID().toString()
        val newMsg = Message(
            id = messageId,
            sender = "You",
            receiver = if (chatId.startsWith("dm_")) chatId.removePrefix("dm_") else null,
            content = content,
            timestampMs = System.currentTimeMillis(),
            selfDestructDurationSec = selfDestructSec
        )

        saveMessage(chatId, newMsg)

        // Simulating the WebSocket remote reply arriving
        if (chatId.startsWith("dm_")) {
            val contactName = _sessions.value.find { it.id == chatId }?.name ?: "RemoteNode"
            scope.launch {
                delay(1200)
                val replyId = UUID.randomUUID().toString()
                val reply = Message(
                    id = replyId,
                    sender = contactName,
                    receiver = "You",
                    content = "Copy that. Sanitizing buffer structures.",
                    timestampMs = System.currentTimeMillis(),
                    selfDestructDurationSec = selfDestructSec
                )
                saveMessage(chatId, reply)
            }
        }
    }

    override suspend fun sendMediaMessage(chatId: String, mediaType: String, fileName: String, sizeMb: Int, selfDestructSec: Int) {
        val messageId = UUID.randomUUID().toString()
        val newMsg = Message(
            id = messageId,
            sender = "You",
            receiver = if (chatId.startsWith("dm_")) chatId.removePrefix("dm_") else null,
            content = "Sent $mediaType ($sizeMb MB): $fileName",
            timestampMs = System.currentTimeMillis(),
            selfDestructDurationSec = selfDestructSec,
            isMedia = true,
            mediaType = mediaType,
            mediaSizeMb = sizeMb
        )

        saveMessage(chatId, newMsg)

        if (chatId.startsWith("dm_")) {
            val contactName = _sessions.value.find { it.id == chatId }?.name ?: "RemoteNode"
            scope.launch {
                delay(1500)
                val replyId = UUID.randomUUID().toString()
                val reply = Message(
                    id = replyId,
                    sender = contactName,
                    receiver = "You",
                    content = "Acknowledged. Payload decrypted in RAM.",
                    timestampMs = System.currentTimeMillis(),
                    selfDestructDurationSec = selfDestructSec
                )
                saveMessage(chatId, reply)
            }
        }
    }

    override suspend fun markAsRead(chatId: String, messageId: String) {
        val chatMsgs = _messages.value[chatId] ?: return
        var changed = false
        val updated = chatMsgs.map { msg ->
            if (msg.id == messageId && msg.readTimestampMs == null) {
                changed = true
                msg.copy(readTimestampMs = System.currentTimeMillis())
            } else {
                msg
            }
        }
        if (changed) {
            _messages.value = _messages.value.toMutableMap().apply { put(chatId, updated) }
            
            _sessions.value = _sessions.value.map { session ->
                if (session.id == chatId) {
                    session.copy(unreadCount = 0)
                } else {
                    session
                }
            }
        }
    }

    override suspend fun clearAllData() {
        _messages.value = emptyMap()
        _sessions.value = emptyList()
    }
}

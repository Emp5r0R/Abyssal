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
        resetToEmpty()
        startMemorySweeper()
    }

    private fun resetToEmpty() {
        _sessions.value.forEach { it.lastMessage?.let(::wipeMessageKeys) }
        _sessions.value = emptyList()
        _messages.value = emptyMap()
    }

    private fun updateLastMessages() {
        val currentMsgs = _messages.value
        _sessions.value = _sessions.value.map { session ->
            val msgs = currentMsgs[session.id] ?: emptyList()
            val last = msgs.lastOrNull()
            
            // Mask actual message content in personal DM previews
            val previewMsg = last?.let { msg ->
                if (!session.isForum) {
                    msg.copy(
                        content = "Message received",
                        senderPublicKey = null,
                        attachmentKey = null
                    )
                } else {
                    msg.copy(senderPublicKey = null, attachmentKey = null)
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
                
                val cleanMessages = _messages.value.mapValues { (_, list) ->
                    val filtered = list.filter { msg ->
                        // 1. Overall absolute self-destruct check (expires regardless of read or not)
                        val overallLimit = msg.absoluteExpirySec
                        if (overallLimit > 0) {
                            val elapsed = now - msg.timestampMs
                            if (elapsed >= overallLimit * 1000L) {
                                updated = true
                                wipeMessageKeys(msg)
                                return@filter false
                            }
                        }
                        
                        // 2. Read-destruct check (expires X seconds after read)
                        val readTime = msg.readTimestampMs
                        if (readTime != null && msg.selfDestructDurationSec > 0) {
                            val elapsed = now - readTime
                            val keep = elapsed < msg.selfDestructDurationSec * 1000L
                            if (!keep) {
                                updated = true
                                wipeMessageKeys(msg)
                            }
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
        ensureSessionExists(chatId, message.selfDestructDurationSec)
        val currentChatMsgs = _messages.value[chatId]?.toMutableList() ?: mutableListOf()
        val existing = currentChatMsgs.firstOrNull { it.id == message.id }
        if (existing != null) {
            if (existing !== message) wipeMessageKeys(message)
            return
        }
        val storedMessage = message.copy(
            senderPublicKey = message.senderPublicKey?.copyOf(),
            attachmentKey = message.attachmentKey?.copyOf()
        )
        wipeMessageKeys(message)
        currentChatMsgs.add(storedMessage)
        _messages.value = _messages.value.toMutableMap().apply { put(chatId, currentChatMsgs) }
        updateLastMessages()
    }

    override suspend fun createForumSession(session: ChatSession) {
        val current = _sessions.value.toMutableList()
        val existingIndex = current.indexOfFirst { it.id == session.id }
        if (existingIndex >= 0) {
            current[existingIndex] = session.copy(
                lastMessage = current[existingIndex].lastMessage,
                unreadCount = current[existingIndex].unreadCount
            )
        } else {
            current.add(session)
        }
        _sessions.value = current
        _messages.value = _messages.value.toMutableMap().apply { putIfAbsent(session.id, emptyList()) }
        updateLastMessages()
    }

    override suspend fun deleteChatSession(chatId: String) {
        val removedSession = _sessions.value.firstOrNull { it.id == chatId }
        _sessions.value = _sessions.value.filterNot { it.id == chatId }
        val removed = _messages.value[chatId].orEmpty()
        removed.forEach(::wipeMessageKeys)
        removedSession?.lastMessage?.let(::wipeMessageKeys)
        _messages.value = _messages.value.toMutableMap().apply { remove(chatId) }
    }

    private fun ensureSessionExists(chatId: String, selfDestructSec: Int) {
        if (_sessions.value.any { it.id == chatId }) return

        val isRoom = chatId.startsWith("room_") || chatId.startsWith("forum_")
        val session = ChatSession(
            id = chatId,
            name = chatId.removePrefix("room_").removePrefix("forum_").replace('_', ' ')
                .replaceFirstChar { it.titlecase() },
            isForum = isRoom,
            lastMessage = null,
            unreadCount = 1,
            selfDestructTimerSec = selfDestructSec
        )
        _sessions.value = _sessions.value + session
    }

    override suspend fun sendMessage(
        chatId: String,
        content: String,
        selfDestructSec: Int,
        replyToMessageId: String?
    ) {
        val newMsg = Message(
            id = UUID.randomUUID().toString(),
            sender = "You",
            receiver = if (chatId.startsWith("dm_")) chatId.removePrefix("dm_") else null,
            content = content,
            timestampMs = System.currentTimeMillis(),
            selfDestructDurationSec = selfDestructSec,
            absoluteExpirySec = 0,
            replyToMessageId = replyToMessageId
        )

        saveMessage(chatId, newMsg)
    }

    override suspend fun saveLocalAttachmentMessage(chatId: String, message: Message) {
        saveMessage(chatId, message)
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

    override suspend fun forgetAttachmentKey(chatId: String, messageId: String) {
        val current = _messages.value[chatId] ?: return
        var changed = false
        val updated = current.map { message ->
            if (message.id == messageId && message.attachmentKey != null) {
                changed = true
                message.attachmentKey.fill(0)
                message.copy(attachmentKey = null)
            } else {
                message
            }
        }
        if (changed) {
            _messages.value = _messages.value.toMutableMap().apply { put(chatId, updated) }
            updateLastMessages()
        }
    }

    override suspend fun clearAllData() {
        _messages.value.values.flatten().forEach(::wipeMessageKeys)
        resetToEmpty()
    }

    private fun wipeMessageKeys(message: Message) {
        message.senderPublicKey?.fill(0)
        message.attachmentKey?.fill(0)
    }
}

package com.abyssal.chat.data.repository

import com.abyssal.chat.domain.model.ChatSession
import com.abyssal.chat.domain.model.Message
import com.abyssal.chat.domain.repository.IMessageRepository
import com.abyssal.chat.domain.repository.IMessageSender
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.util.LinkedHashMap
import java.util.UUID

internal const val MAX_MESSAGES_PER_CHAT = 500
internal const val MAX_MESSAGES_TOTAL = 5_000
internal const val MAX_MESSAGE_BYTES_PER_CHAT = 8L * 1024L * 1024L
internal const val MAX_MESSAGE_BYTES_TOTAL = 32L * 1024L * 1024L

class InMemoryMessageRepository : IMessageRepository, IMessageSender {
    private data class MessageLocation(
        val chatId: String,
        val messages: MutableList<Message>,
        val index: Int
    )

    private val scope = CoroutineScope(Dispatchers.Default + Job())
    private val stateLock = Any()

    private val _sessions = MutableStateFlow<List<ChatSession>>(emptyList())
    private val _messages = MutableStateFlow<Map<String, List<Message>>>(emptyMap())

    init {
        resetToEmpty()
        startMemorySweeper()
    }

    private fun resetToEmpty() {
        synchronized(stateLock) {
            _sessions.value.forEach { it.lastMessage?.let(::wipeMessageKeys) }
            _sessions.value = emptyList()
            _messages.value = emptyMap()
        }
    }

    private fun updateLastMessages() {
        synchronized(stateLock) {
            _sessions.value = _sessions.value.map { session ->
                // Dashboard is outside the chat boundary. Do not project even
                // message metadata; the chat screen owns message visibility.
                session.copy(lastMessage = null)
            }
        }
    }

    private fun startMemorySweeper() {
        scope.launch {
            while (isActive) {
                delay(100) // Fast 100ms sweep cycle
                val now = System.currentTimeMillis()
                synchronized(stateLock) {
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
    }

    override fun getChatSessions(): Flow<List<ChatSession>> = _sessions.asStateFlow()

    override fun getMessages(chatId: String): Flow<List<Message>> {
        return _messages.map { map -> map[chatId] ?: emptyList() }
    }

    override suspend fun saveMessage(chatId: String, message: Message) {
        synchronized(stateLock) {
            val candidateBytes = estimatedMessageBytes(message)
            if (candidateBytes > MAX_MESSAGE_BYTES_PER_CHAT ||
                candidateBytes > MAX_MESSAGE_BYTES_TOTAL
            ) {
                wipeMessageKeys(message)
                return
            }

            val nextMessages = _messages.value
                .mapValuesTo(LinkedHashMap()) { (_, messages) -> messages.toMutableList() }
            val currentChatMsgs = nextMessages.getOrPut(chatId) { mutableListOf() }
            val existing = currentChatMsgs.firstOrNull { it.id == message.id }
            if (existing != null) {
                if (existing !== message) wipeMessageKeys(message)
                return
            }

            var chatBytes = currentChatMsgs.sumOf(::estimatedMessageBytes)
            var globalCount = nextMessages.values.sumOf { it.size }
            var globalBytes = nextMessages.values.sumOf { messages ->
                messages.sumOf(::estimatedMessageBytes)
            }

            fun evictAt(index: Int, messages: MutableList<Message>): Boolean {
                if (index !in messages.indices) return false
                val removed = messages.removeAt(index)
                val removedBytes = estimatedMessageBytes(removed)
                chatBytes -= if (messages === currentChatMsgs) removedBytes else 0L
                globalBytes -= removedBytes
                globalCount--
                wipeMessageKeys(removed)
                return true
            }

            fun oldestIndex(messages: MutableList<Message>): Int = messages.indices
                .minWithOrNull(
                    compareBy<Int>({ messages[it].timestampMs }, { messages[it].id }, { it })
                ) ?: -1

            while (
                currentChatMsgs.size >= MAX_MESSAGES_PER_CHAT ||
                chatBytes + candidateBytes > MAX_MESSAGE_BYTES_PER_CHAT
            ) {
                if (!evictAt(oldestIndex(currentChatMsgs), currentChatMsgs)) break
            }

            fun oldestGlobal(): MessageLocation? = nextMessages.entries
                .asSequence()
                .flatMap { (chat, messages) ->
                    messages.indices.asSequence().map { index ->
                        MessageLocation(chat, messages, index)
                    }
                }
                .minWithOrNull(
                    compareBy<MessageLocation>(
                        { it.messages[it.index].timestampMs },
                        { it.chatId },
                        { it.messages[it.index].id },
                        { it.index }
                    )
                )

            while (
                globalCount >= MAX_MESSAGES_TOTAL ||
                globalBytes + candidateBytes > MAX_MESSAGE_BYTES_TOTAL
            ) {
                val victim = oldestGlobal() ?: break
                if (!evictAt(victim.index, victim.messages)) break
                if (victim.messages === currentChatMsgs) {
                    chatBytes = currentChatMsgs.sumOf(::estimatedMessageBytes)
                }
            }

            val storedMessage = message.copy(
                senderPublicKey = message.senderPublicKey?.copyOf(),
                attachmentKey = message.attachmentKey?.copyOf()
            )
            wipeMessageKeys(message)
            currentChatMsgs.add(storedMessage)
            nextMessages[chatId] = currentChatMsgs
            ensureSessionExists(chatId, message.selfDestructDurationSec)
            _messages.value = nextMessages
            updateLastMessages()
        }
    }

    override suspend fun createForumSession(session: ChatSession) {
        synchronized(stateLock) {
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
    }

    override suspend fun deleteChatSession(chatId: String) {
        synchronized(stateLock) {
            val removedSession = _sessions.value.firstOrNull { it.id == chatId }
            _sessions.value = _sessions.value.filterNot { it.id == chatId }
            val removed = _messages.value[chatId].orEmpty()
            removed.forEach(::wipeMessageKeys)
            removedSession?.lastMessage?.let(::wipeMessageKeys)
            _messages.value = _messages.value.toMutableMap().apply { remove(chatId) }
        }
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
        synchronized(stateLock) {
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
    }

    override suspend fun forgetAttachmentKey(chatId: String, messageId: String) {
        synchronized(stateLock) {
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
    }

    override suspend fun clearAllData() {
        clearAllDataNow()
    }

    override fun clearAllDataNow() {
        synchronized(stateLock) {
            _messages.value.values.flatten().forEach(::wipeMessageKeys)
            resetToEmpty()
        }
    }

    override fun close() {
        clearAllDataNow()
        scope.cancel()
    }

    private fun wipeMessageKeys(message: Message) {
        message.senderPublicKey?.fill(0)
        message.attachmentKey?.fill(0)
    }

    private fun estimatedMessageBytes(message: Message): Long {
        var total = 256L
        fun addString(value: String?) {
            if (value == null) return
            total = total.saturatingAdd(value.length.toLong().saturatingMultiply(2L))
        }
        addString(message.id)
        addString(message.sender)
        addString(message.receiver)
        addString(message.content)
        addString(message.mediaType)
        addString(message.attachmentId)
        addString(message.attachmentName)
        addString(message.attachmentMimeType)
        addString(message.replyToMessageId)
        addString(message.reactionShortcode)
        total = total.saturatingAdd(message.senderPublicKey?.size?.toLong() ?: 0L)
        total = total.saturatingAdd(message.attachmentKey?.size?.toLong() ?: 0L)
        return total
    }

    private fun Long.saturatingAdd(value: Long): Long =
        if (Long.MAX_VALUE - this < value) Long.MAX_VALUE else this + value

    private fun Long.saturatingMultiply(value: Long): Long =
        if (this != 0L && Long.MAX_VALUE / this < value) Long.MAX_VALUE else this * value
}

package com.abyssal.chat.presentation.viewmodel

import com.abyssal.chat.data.storage.EncryptedDeviceStore
import com.abyssal.chat.domain.model.DeviceStoreSnapshot
import com.abyssal.chat.domain.model.Message
import com.abyssal.chat.domain.repository.IMessageRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Keeps the signed-in account's messages, room names and contact names in the
 * encrypted device store while the relay allows it. Call from the main thread.
 */
@OptIn(FlowPreview::class)
internal class DeviceStorageController(
    private val store: EncryptedDeviceStore?,
    private val repository: IMessageRepository,
    private val scope: CoroutineScope
) {
    private var session: EncryptedDeviceStore.Session? = null
    private var saveJob: Job? = null
    private var latest: DeviceStoreSnapshot? = null
    private val _active = MutableStateFlow(false)

    /** Whether messages are currently being kept on this device. */
    val active: StateFlow<Boolean> = _active.asStateFlow()

    /**
     * After sign-in. Without a relay share (the relay does not allow device
     * storage) nothing is opened. Otherwise the saved snapshot is restored
     * through [onRestored] and later changes are saved. Wipes [share].
     */
    fun attach(
        share: ByteArray?,
        nodeId: String,
        username: String,
        roomNames: Flow<Map<String, String>>,
        displayNames: Flow<Map<String, String>>,
        onRestored: (DeviceStoreSnapshot) -> Unit
    ) {
        detach(flush = false)
        if (share == null || store == null) {
            share?.fill(0)
            return
        }
        val opened = try {
            store.open(share, nodeId, username)
        } finally {
            share.fill(0)
        } ?: return
        session = opened
        _active.value = true
        saveJob = scope.launch {
            val restored = withContext(Dispatchers.IO) { runCatching { opened.load() }.getOrNull() }
            if (session !== opened) return@launch
            restored?.let(onRestored)
            // Start saving only after the restore, so an empty first state never overwrites the file.
            combine(repository.observeAllMessages(), roomNames, displayNames) { messages, rooms, names ->
                DeviceStoreSnapshot(messages, rooms, names)
            }.drop(1).debounce(SAVE_DEBOUNCE_MS).collect { snapshot ->
                latest = snapshot
                if (session === opened) withContext(Dispatchers.IO) { runCatching { opened.save(snapshot) } }
            }
        }
    }

    /**
     * Stops saving and wipes the store key from memory; the file stays for the
     * next sign-in. With [flush], the latest state is written first.
     */
    fun detach(flush: Boolean = true) {
        val current = session ?: return
        saveJob?.cancel()
        saveJob = null
        if (flush) {
            val snapshot = DeviceStoreSnapshot(
                repository.snapshotAllMessages(),
                latest?.roomNames.orEmpty(),
                latest?.displayNames.orEmpty()
            )
            runCatching { current.save(snapshot) }
        }
        latest = null
        current.close()
        session = null
        _active.value = false
    }

    /** Deletes everything saved on this device, for every account, and the device key. */
    fun eraseAll() {
        detach(flush = false)
        runCatching { store?.eraseAll() }
    }

    companion object {
        const val SAVE_DEBOUNCE_MS = 1_000L

        /** Forum names worth keeping: ones the room owner actually sent. */
        fun learnedRoomNames(sessions: List<com.abyssal.chat.domain.model.ChatSession>): Map<String, String> =
            sessions.filter { it.isForum && com.abyssal.chat.domain.model.roomLabel(it.id, it.name) == it.name }
                .associate { it.id to it.name }

        /** Messages of the chats that should be kept. */
        fun messagesFor(all: Map<String, List<Message>>): Map<String, List<Message>> = all.filterValues { it.isNotEmpty() }
    }
}

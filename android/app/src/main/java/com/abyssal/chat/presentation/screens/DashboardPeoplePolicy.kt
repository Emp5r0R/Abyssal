package com.abyssal.chat.presentation.screens

import com.abyssal.chat.domain.model.UserPresence

internal fun directPeersForDirectory(
    presence: List<UserPresence>,
    currentUsername: String?,
    establishedDirectPeerUsernames: Set<String> = emptySet()
): List<UserPresence> = presence
    .filterNot { user ->
        user.username.equals(currentUsername, ignoreCase = true) ||
            establishedDirectPeerUsernames.any { it.equals(user.username, ignoreCase = true) }
    }
    .sortedBy { it.username }

internal fun peopleDirectoryEntryLabel(username: String, connected: Boolean): String =
    "Open direct conversation with $username · ${if (connected) "ONLINE" else "OFFLINE"}"

internal fun peopleDirectoryEmptyStateLabel(): String = "No peers active"

internal fun directConversationEmptyStateTitle(): String = "No direct conversations"

internal fun directConversationEmptyStateDetail(peerCount: Int): String =
    if (peerCount == 0) {
        "No peers are currently available on this relay."
    } else {
        "Select a peer from People to start a conversation."
    }

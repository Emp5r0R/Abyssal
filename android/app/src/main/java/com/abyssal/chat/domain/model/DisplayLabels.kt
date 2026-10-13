package com.abyssal.chat.domain.model

import java.util.Locale

private val GENERATED_ACCOUNT = Regex("^acct_([0-9a-fA-F]{8,})$")

/** Shortens a generated account ID such as `acct_10ba…ce30` to `10ba…ce30`, like the web client. */
fun shortAccountId(username: String): String {
    val hex = GENERATED_ACCOUNT.matchEntire(username)?.groupValues?.get(1) ?: return username
    return "${hex.take(4)}…${hex.takeLast(4)}"
}

/** Shortens an opaque room ID such as `forum_<hex>` for display. */
fun shortRoomId(roomId: String): String {
    val body = roomId.removePrefix("forum_")
    return if (body.length > 12) "${body.take(4)}…${body.takeLast(4)}" else body
}

/**
 * A room's display name. Members who never received the owner's room name see
 * the opaque ID as the name; show that shortened rather than as 32 hex digits.
 */
fun roomLabel(roomId: String, name: String): String {
    val body = roomId.removePrefix("forum_")
    return if (name.isNotBlank() && name != body.take(36) && name != roomId) name else "Room ${shortRoomId(roomId)}"
}

/** Two-character avatar text for an account or display name. */
fun accountInitials(label: String): String {
    val source = GENERATED_ACCOUNT.matchEntire(label)?.groupValues?.get(1)
        ?: label.filter { it.isLetterOrDigit() }
    return source.take(2).uppercase(Locale.ROOT).ifEmpty { "?" }
}

/**
 * The label for a peer: their self-chosen display name when one was seen, else
 * the shortened account ID. Display names are unverified, so screens keep the
 * account ID visible next to them.
 */
fun peerLabel(username: String, displayNames: Map<String, String>): String =
    displayNames[username.lowercase(Locale.ROOT)] ?: shortAccountId(username)

/** One open conversation as listed and searched on the dashboard. */
data class ConversationEntry(val id: String, val isRoom: Boolean, val label: String, val searchText: String)

fun conversationEntries(sessions: List<ChatSession>, displayNames: Map<String, String>): List<ConversationEntry> =
    sessions.map { session ->
        if (session.isForum) {
            ConversationEntry(session.id, true, roomLabel(session.id, session.name), session.id)
        } else {
            ConversationEntry(session.id, false, peerLabel(session.name, displayNames), session.name)
        }
    }

/** Case-insensitive match on the label or the underlying ID. */
fun filterConversations(entries: List<ConversationEntry>, query: String): List<ConversationEntry> {
    val needle = query.trim().lowercase(Locale.ROOT)
    if (needle.isEmpty()) return entries
    return entries.filter {
        it.label.lowercase(Locale.ROOT).contains(needle) || it.searchText.lowercase(Locale.ROOT).contains(needle)
    }
}

/** Most display names kept per session; the oldest entry is dropped beyond this. */
const val MAX_KNOWN_DISPLAY_NAMES = 512

/**
 * Records the latest self-chosen display name seen from [username], keyed in
 * lower case. Blank names are ignored and the map stays bounded.
 */
fun withDisplayName(names: Map<String, String>, username: String, displayName: String?): Map<String, String> {
    val name = displayName?.trim()?.takeIf { it.isNotEmpty() } ?: return names
    val key = username.lowercase(Locale.ROOT)
    if (names[key] == name) return names
    val updated = LinkedHashMap(names)
    updated.remove(key)
    updated[key] = name
    while (updated.size > MAX_KNOWN_DISPLAY_NAMES) updated.remove(updated.keys.first())
    return updated
}

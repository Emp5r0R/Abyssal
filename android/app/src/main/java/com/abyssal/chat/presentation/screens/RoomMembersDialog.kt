package com.abyssal.chat.presentation.screens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.abyssal.chat.domain.model.peerLabel
import com.abyssal.chat.domain.model.shortAccountId
import com.abyssal.chat.theme.Danger

/** Sorts the owner first, then you, then everyone else by label. */
internal fun sortedRoomMembers(
    members: List<String>,
    ownerUsername: String?,
    currentUsername: String?,
    displayNames: Map<String, String>
): List<String> = members.sortedWith(
    compareBy<String> {
        when {
            ownerUsername != null && it.equals(ownerUsername, ignoreCase = true) -> 0
            currentUsername != null && it.equals(currentUsername, ignoreCase = true) -> 1
            else -> 2
        }
    }.thenBy { peerLabel(it, displayNames).lowercase() }
)

/**
 * Who is in a room. The owner can remove anyone else; the removed member's
 * app drops the room and later messages are encrypted without them.
 */
@Composable
internal fun RoomMembersDialog(
    members: List<String>,
    ownerUsername: String?,
    currentUsername: String?,
    displayNames: Map<String, String>,
    connected: Boolean,
    onRemove: (String, (Boolean) -> Unit) -> Unit,
    onDismiss: () -> Unit
) {
    var confirming by remember { mutableStateOf<String?>(null) }
    var failed by remember { mutableStateOf(false) }
    val isOwner = ownerUsername != null && ownerUsername.equals(currentUsername, ignoreCase = true)
    MirageDialog(
        title = "Members (${members.size})",
        onDismiss = onDismiss,
        icon = { Avatar("", size = 40.dp, icon = AppIcons.Users) }
    ) {
        if (failed) {
            Text("Could not remove that member. Try again when the relay is connected.", color = Danger, fontSize = 13.sp)
        }
        Column(Modifier.heightIn(max = 420.dp).verticalScroll(rememberScrollState())) {
            sortedRoomMembers(members, ownerUsername, currentUsername, displayNames).forEach { member ->
                val label = peerLabel(member, displayNames)
                val roomOwner = ownerUsername != null && member.equals(ownerUsername, ignoreCase = true)
                val you = currentUsername != null && member.equals(currentUsername, ignoreCase = true)
                ListRow(
                    leading = { Avatar(label, size = 36.dp) },
                    title = { PrivacyBlurred { RowTitle(if (you) "You" else label) } },
                    subtitle = {
                        RowSubtitle(listOfNotNull(shortAccountId(member), "Owner".takeIf { roomOwner }).joinToString(" · "))
                    },
                    trailing = if (isOwner && !you && !roomOwner) {
                        {
                            MirageSecondaryButton(
                                text = "Remove",
                                onClick = { confirming = member },
                                enabled = connected,
                                danger = true,
                                compact = true
                            )
                        }
                    } else null
                )
            }
        }
    }
    confirming?.let { member ->
        ConfirmDialog(
            title = "Remove from room?",
            message = "${peerLabel(member, displayNames)} stops receiving messages in this room. They can ask to join again.",
            confirmLabel = "Remove",
            onConfirm = {
                confirming = null
                failed = false
                onRemove(member) { removed -> failed = !removed }
            },
            onDismiss = { confirming = null }
        )
    }
}

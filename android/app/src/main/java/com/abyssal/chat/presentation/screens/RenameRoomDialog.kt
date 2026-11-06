package com.abyssal.chat.presentation.screens

import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.abyssal.chat.theme.Danger
import com.abyssal.chat.theme.TextMuted

/** Longest room name the encrypted room profile accepts. */
internal const val MAX_ROOM_NAME = 36

/** Whether [value], trimmed, is a room name the room profile accepts. */
internal fun validRoomName(value: String): Boolean {
    val name = value.trim()
    return name.length in 1..MAX_ROOM_NAME && name.none(Char::isISOControl) &&
        name.codePoints().noneMatch { it in 0xd800..0xdfff }
}

/** The owner renames a room. Members on current apps see the new name; older apps keep the old one. */
@Composable
internal fun RenameRoomDialog(
    currentName: String,
    connected: Boolean,
    onRename: (String, (Boolean) -> Unit) -> Unit,
    onDismiss: () -> Unit
) {
    var name by remember { mutableStateOf(currentName) }
    var busy by remember { mutableStateOf(false) }
    var failed by remember { mutableStateOf(false) }
    val valid = validRoomName(name) && name.trim() != currentName
    MirageDialog(title = "Rename room", onDismiss = onDismiss, icon = { Avatar("", size = 40.dp, icon = AppIcons.Pencil) }) {
        Text(
            "The new name is sent end-to-end encrypted to everyone in the room.",
            color = TextMuted,
            fontSize = 14.sp,
            lineHeight = 20.sp
        )
        Spacer(Modifier.height(14.dp))
        AppTextField(
            value = name,
            onValueChange = {
                failed = false
                name = it.take(MAX_ROOM_NAME)
            },
            label = "Room name",
            supportingText = "Up to $MAX_ROOM_NAME characters."
        )
        if (failed) {
            Text("Could not rename the room. Try again when the relay is connected.", color = Danger, fontSize = 13.sp)
        }
        DialogButtons(
            "Cancel",
            if (busy) "Saving…" else "Save",
            onDismiss,
            {
                busy = true
                onRename(name.trim()) { renamed ->
                    busy = false
                    if (renamed) onDismiss() else failed = true
                }
            },
            valid && connected && !busy
        )
    }
}

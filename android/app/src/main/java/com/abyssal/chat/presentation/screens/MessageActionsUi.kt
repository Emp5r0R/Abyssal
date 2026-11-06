@file:OptIn(ExperimentalLayoutApi::class)

package com.abyssal.chat.presentation.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.abyssal.chat.domain.model.Message
import com.abyssal.chat.domain.model.MessageAction
import com.abyssal.chat.domain.model.MessageActionCodec
import com.abyssal.chat.domain.model.MessageActionPolicy
import com.abyssal.chat.theme.Accent
import com.abyssal.chat.theme.AccentBorder
import com.abyssal.chat.theme.AccentSoft
import com.abyssal.chat.theme.Danger
import com.abyssal.chat.theme.Outline
import com.abyssal.chat.theme.SurfaceHigh
import com.abyssal.chat.theme.SurfaceRaised
import com.abyssal.chat.theme.TextMuted
import com.abyssal.chat.theme.TextPrimary

/** Reaction counts under a message. Tapping one toggles your own reaction. */
@Composable
internal fun MessageReactionsRow(
    message: Message,
    currentUsername: String?,
    enabled: Boolean,
    onToggle: (String, Boolean) -> Unit,
    modifier: Modifier = Modifier
) {
    val summary = MessageActionPolicy.summary(message, currentUsername)
    if (summary.isEmpty()) return
    FlowRow(modifier = modifier.padding(top = 4.dp), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
        summary.forEach { item ->
            val shape = RoundedCornerShape(100.dp)
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .padding(bottom = 4.dp)
                    .clip(shape)
                    .background(if (item.mine) AccentSoft else SurfaceHigh)
                    .border(1.dp, if (item.mine) AccentBorder else Outline, shape)
                    .clickable(enabled = enabled, role = Role.Button) { onToggle(item.emoji, !item.mine) }
                    .semantics {
                        selected = item.mine
                        contentDescription = "${item.emoji} ${item.count}" + if (item.mine) ", including you" else ""
                    }
                    .padding(horizontal = 8.dp, vertical = 3.dp)
            ) {
                Text(item.emoji, fontSize = 14.sp)
                Text(
                    "${item.count}",
                    color = if (item.mine) Accent else TextMuted,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.padding(start = 4.dp)
                )
            }
        }
    }
}

/** Long-press menu for a message: react, reply, copy, and for your own messages edit and delete. */
@Composable
internal fun MessageActionsSheet(
    message: Message,
    currentUsername: String?,
    canSend: Boolean,
    onDismiss: () -> Unit,
    onReact: (String, Boolean) -> Unit,
    onReply: () -> Unit,
    onCopy: (() -> Unit)?,
    onEdit: () -> Unit,
    onDelete: () -> Unit
) {
    val mine = MessageActionPolicy.summary(message, currentUsername).filter { it.mine }.map { it.emoji }.toSet()
    val canEdit = canSend && currentUsername != null &&
        MessageActionPolicy.allowed(message, MessageAction.Edit(message.id, "x"), currentUsername, currentUsername)
    val canDelete = canSend && currentUsername != null &&
        MessageActionPolicy.allowed(message, MessageAction.Delete(message.id), currentUsername, currentUsername)
    MirageDialog(title = "Message", onDismiss = onDismiss) {
        if (canSend) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                MessageActionCodec.REACTION_EMOJI.forEach { emoji ->
                    val active = emoji in mine
                    Box(
                        contentAlignment = Alignment.Center,
                        modifier = Modifier
                            .size(44.dp)
                            .clip(CircleShape)
                            .background(if (active) AccentSoft else SurfaceRaised)
                            .clickable(role = Role.Button) { onReact(emoji, !active) }
                            .semantics {
                                selected = active
                                contentDescription = if (active) "Remove $emoji reaction" else "React with $emoji"
                            }
                    ) {
                        Text(emoji, fontSize = 22.sp)
                    }
                }
            }
        }
        SheetAction(AppIcons.Reply, "Reply", onClick = onReply)
        if (onCopy != null) SheetAction(AppIcons.Copy, "Copy text", onClick = onCopy)
        if (canEdit) SheetAction(AppIcons.Pencil, "Edit", onClick = onEdit)
        if (canDelete) SheetAction(AppIcons.Trash, "Delete for everyone", danger = true, onClick = onDelete)
        Spacer(Modifier.height(4.dp))
    }
}

@Composable
private fun SheetAction(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    danger: Boolean = false,
    onClick: () -> Unit
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .clip(ControlShape)
            .clickable(role = Role.Button, onClick = onClick)
            .padding(horizontal = 8.dp, vertical = 12.dp)
    ) {
        AppIcon(icon, tint = if (danger) Danger else TextMuted, size = 20.dp)
        Spacer(Modifier.width(14.dp))
        Text(label, color = if (danger) Danger else TextPrimary, fontSize = 15.sp, fontWeight = FontWeight.Medium)
    }
}

/** Shown above the composer while you edit one of your messages. */
@Composable
internal fun EditComposerPreview(message: Message, onCancel: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 12.dp, end = 12.dp, top = 8.dp)
            .clip(ControlShape)
            .background(SurfaceRaised)
            .padding(start = 12.dp, end = 2.dp, top = 6.dp, bottom = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        AppIcon(AppIcons.Pencil, tint = Accent, size = 16.dp)
        Column(modifier = Modifier.weight(1f).padding(horizontal = 10.dp)) {
            Text("Editing your message", color = Accent, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
            PrivacyBlurred(revealOnTap = false) {
                Text(message.content, color = TextMuted, fontSize = 13.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
        IconAction(AppIcons.Close, "Cancel edit", onCancel, size = 36.dp, iconSize = 16.dp)
    }
}

/** Search field under the chat header; filters the conversation to matching messages. */
@Composable
internal fun ConversationSearchBar(query: String, matches: Int, onQueryChange: (String) -> Unit, onClose: () -> Unit) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.fillMaxWidth().padding(start = 12.dp, end = 4.dp, top = 6.dp, bottom = 6.dp)
    ) {
        AppTextField(
            value = query,
            onValueChange = { onQueryChange(it.take(200)) },
            label = "Search this conversation",
            placeholder = "Search messages in memory",
            supportingText = if (query.isNotBlank()) "$matches found" else null,
            modifier = Modifier.weight(1f)
        )
        IconAction(AppIcons.Close, "Close search", onClose)
    }
}

package com.abyssal.chat.presentation.screens

import android.content.Context
import android.graphics.BitmapFactory
import android.graphics.ImageDecoder
import android.graphics.SurfaceTexture
import android.graphics.drawable.AnimatedImageDrawable
import android.media.MediaDataSource
import android.media.MediaPlayer
import android.net.Uri
import android.os.Build
import android.provider.OpenableColumns
import android.view.Surface
import android.view.TextureView
import android.view.ViewGroup
import android.widget.ImageView
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Checkbox
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import com.abyssal.chat.domain.model.AttachmentUploadProgress
import com.abyssal.chat.domain.model.ChatSession
import com.abyssal.chat.domain.model.DecryptedAttachment
import com.abyssal.chat.domain.model.Message
import com.abyssal.chat.domain.model.MessageAttentionPolicy
import com.abyssal.chat.domain.model.ServerStatus
import com.abyssal.chat.domain.model.UserPresence
import com.abyssal.chat.presentation.viewmodel.ChatViewModel
import com.abyssal.chat.presentation.viewmodel.Screen
import com.abyssal.chat.theme.DeepBlack
import com.abyssal.chat.theme.DeepBlue
import com.abyssal.chat.theme.GlassBorder
import com.abyssal.chat.theme.NeonCyan
import com.abyssal.chat.theme.NeonGreen
import com.abyssal.chat.theme.PureWhite
import com.abyssal.chat.theme.SelfDestructAmber
import com.abyssal.chat.theme.SteelMuted
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.nio.ByteBuffer
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean

@Composable
fun ChatScreen(viewModel: ChatViewModel, sessionId: String) {
    val messages by viewModel.activeMessages.collectAsState()
    val sessions by viewModel.sessions.collectAsState()
    val status by viewModel.serverStatus.collectAsState()
    val attachmentPreview by viewModel.attachmentPreview.collectAsState()
    val uploadProgress by viewModel.attachmentUploadProgress.collectAsState()
    val currentUser by viewModel.currentUser.collectAsState()
    val presence by viewModel.presence.collectAsState()
    val attachmentError = viewModel.attachmentError.value
    val currentSession = remember(sessions, sessionId) { sessions.find { it.id == sessionId } }

    ChatContent(
        session = currentSession,
        messages = messages,
        status = status,
        attachmentPreview = attachmentPreview,
        uploadProgress = uploadProgress,
        attachmentError = attachmentError,
        currentUsername = currentUser?.username,
        presence = presence,
        onBack = { viewModel.navigateTo(Screen.Dashboard) },
        onSendMessage = viewModel::sendMessage,
        onSendAttachment = viewModel::sendAttachment,
        onMessageVisible = viewModel::markMessageAsRead,
        onViewAttachment = viewModel::viewAttachment,
        onSaveAttachment = viewModel::saveAttachment,
        onDismissAttachmentPreview = viewModel::dismissAttachmentPreview,
        onExternalSystemUiStart = viewModel::beginExternalSystemUi,
        onExternalSystemUiEnd = viewModel::endExternalSystemUi,
        onUserActivity = viewModel::recordUserActivity
    )
}

@Composable
private fun ChatContent(
    session: ChatSession?,
    messages: List<Message>,
    status: ServerStatus,
    attachmentPreview: DecryptedAttachment?,
    uploadProgress: AttachmentUploadProgress,
    attachmentError: String?,
    currentUsername: String?,
    presence: List<UserPresence>,
    onBack: () -> Unit,
    onSendMessage: (String, Int, String?) -> Unit,
    onSendAttachment: (String, String, String, ByteArray, Int, Boolean, Boolean, String?, String?) -> Unit,
    onMessageVisible: (String) -> Unit,
    onViewAttachment: (Message) -> Unit,
    onSaveAttachment: (Message, Uri) -> Unit,
    onDismissAttachmentPreview: () -> Unit,
    onExternalSystemUiStart: () -> Unit,
    onExternalSystemUiEnd: () -> Unit,
    onUserActivity: () -> Unit
) {
    var textInput by remember { mutableStateOf("") }
    var selectedTimerSec by remember(session) { mutableIntStateOf(session?.selfDestructTimerSec ?: 5) }
    var showAttachmentDialog by remember { mutableStateOf(false) }
    var showBundledGifDialog by remember { mutableStateOf(false) }
    var saveTargetMessage by remember { mutableStateOf<Message?>(null) }
    var replyingToMessageId by remember(session?.id) { mutableStateOf<String?>(null) }
    var highlightedMessageId by remember(session?.id) { mutableStateOf<String?>(null) }
    var hasPositionedMessageList by remember(session?.id) { mutableStateOf(false) }
    val messageListState = remember(session?.id) { LazyListState() }
    val inputFocusRequester = remember { FocusRequester() }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val hapticFeedback = LocalHapticFeedback.current
    val messagesById = remember(messages) { messages.associateBy(Message::id) }
    val replyingToMessage = replyingToMessageId?.let(messagesById::get)
    val isConnected = status.state == "CONNECTED"
    val bundledAssets = remember { context.listBundledEmojiAssets() }
    val bundledByShortcode = remember(bundledAssets) {
        bundledAssets.associateBy { it.shortcode.lowercase(Locale.ROOT) }
    }
    val composerToken = trailingComposerToken(textInput)
    val reactionSuggestions = remember(composerToken, bundledAssets) {
        composerToken
            ?.takeIf { it.startsWith(":") }
            ?.lowercase(Locale.ROOT)
            ?.let { query -> bundledAssets.filter { it.shortcode.startsWith(query) }.take(6) }
            ?: emptyList()
    }
    val mentionSuggestions = remember(composerToken, presence, currentUsername) {
        val query = composerToken?.takeIf { it.startsWith("@") }?.drop(1).orEmpty()
        if (composerToken?.startsWith("@") != true) {
            emptyList()
        } else {
            presence
                .asSequence()
                .filterNot { it.username.equals(currentUsername, ignoreCase = true) }
                .filter { it.username.contains(query, ignoreCase = true) }
                .distinctBy { it.username.lowercase(Locale.ROOT) }
                .sortedWith(
                    compareByDescending<UserPresence> { it.connected }
                        .thenBy { it.username.lowercase(Locale.ROOT) }
                )
                .take(6)
                .map { it.username }
                .toList()
        }
    }

    LaunchedEffect(replyingToMessageId, replyingToMessage) {
        if (replyingToMessageId != null && replyingToMessage == null) {
            replyingToMessageId = null
        }
    }

    LaunchedEffect(replyingToMessageId) {
        if (replyingToMessageId != null) inputFocusRequester.requestFocus()
    }

    LaunchedEffect(messages.lastOrNull()?.id) {
        if (messages.isEmpty()) {
            hasPositionedMessageList = false
            return@LaunchedEffect
        }

        val lastVisibleIndex = messageListState.layoutInfo.visibleItemsInfo.lastOrNull()?.index ?: -1
        val isNearBottom = lastVisibleIndex >= messages.lastIndex - 2
        if (!hasPositionedMessageList) {
            messageListState.scrollToItem(messages.lastIndex)
            hasPositionedMessageList = true
        } else if (isNearBottom) {
            messageListState.animateScrollToItem(messages.lastIndex)
        }
    }
    val saveLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("*/*")) { uri ->
        onExternalSystemUiEnd()
        val message = saveTargetMessage
        if (uri != null && message != null) onSaveAttachment(message, uri)
        saveTargetMessage = null
    }

    MirageBackground {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .statusBarsPadding()
        ) {
            ChatHeader(
                session = session,
                status = status,
                onBack = onBack
            )

            if (messages.isEmpty()) {
                EmptyState(
                    title = "No messages yet",
                    detail = "Messages appear here only while they are active in memory.",
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f)
                )
            } else {
                LazyColumn(
                    state = messageListState,
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f)
                        .padding(horizontal = 14.dp, vertical = 10.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    items(messages, key = { it.id }) { message ->
                        MessageBubbleItem(
                            message = message,
                            replyTarget = message.replyToMessageId?.let(messagesById::get),
                            highlighted = highlightedMessageId == message.id,
                            onBecomeVisible = { onMessageVisible(message.id) },
                            onReply = {
                                hapticFeedback.performHapticFeedback(HapticFeedbackType.LongPress)
                                replyingToMessageId = message.id
                            },
                            currentUsername = currentUsername,
                            onMentionSender = { sender ->
                                textInput = appendMention(textInput, sender)
                                inputFocusRequester.requestFocus()
                            },
                            onOpenReply = { messageId ->
                                messages.indexOfFirst { it.id == messageId }
                                    .takeIf { it >= 0 }
                                    ?.let { index ->
                                        scope.launch {
                                            messageListState.animateScrollToItem(index)
                                            highlightedMessageId = messageId
                                            delay(900)
                                            if (highlightedMessageId == messageId) highlightedMessageId = null
                                        }
                                    }
                            },
                            onViewAttachment = { onViewAttachment(message) },
                            onSaveAttachment = {
                                saveTargetMessage = message
                                onExternalSystemUiStart()
                                saveLauncher.launch(encryptedExportName(message.attachmentName ?: "attachment"))
                            }
                        )
                    }
                }
            }

            RetentionPicker(
                selectedTimerSec = selectedTimerSec,
                lockedTimerSec = session?.selfDestructTimerSec?.takeIf { session.isForum },
                onSelected = { selectedTimerSec = it }
            )

            UploadProgressStrip(uploadProgress = uploadProgress)

            if (replyingToMessage != null) {
                ReplyComposerPreview(
                    message = replyingToMessage,
                    onCancel = { replyingToMessageId = null }
                )
            }

            ComposerSuggestions(
                reactionSuggestions = reactionSuggestions,
                mentionSuggestions = mentionSuggestions,
                onReactionSelected = { asset ->
                    textInput = replaceTrailingComposerToken(textInput, asset.shortcode)
                    inputFocusRequester.requestFocus()
                },
                onMentionSelected = { username ->
                    textInput = replaceTrailingComposerToken(textInput, "@$username")
                    inputFocusRequester.requestFocus()
                }
            )

            ChatInputBar(
                value = textInput,
                onValueChange = {
                    textInput = it
                    onUserActivity()
                },
                onAttach = { showAttachmentDialog = true },
                onGif = { showBundledGifDialog = true },
                onSend = {
                    val trimmed = textInput.trim()
                    if (trimmed.isNotEmpty()) {
                        val reaction = bundledByShortcode[trimmed.lowercase(Locale.ROOT)]
                        if (reaction == null) {
                            onSendMessage(trimmed, selectedTimerSec, replyingToMessageId)
                            textInput = ""
                            replyingToMessageId = null
                        } else {
                            val replyTargetId = replyingToMessageId
                            scope.launch {
                                val payload = withContext(Dispatchers.IO) {
                                    context.readBundledEmoji(reaction)
                                } ?: return@launch
                                onSendAttachment(
                                    "IMAGE",
                                    payload.fileName,
                                    payload.mimeType,
                                    payload.bytes,
                                    selectedTimerSec,
                                    false,
                                    false,
                                    replyTargetId,
                                    payload.shortcode
                                )
                                textInput = ""
                                replyingToMessageId = null
                            }
                        }
                    }
                },
                canSend = textInput.isNotBlank() && isConnected,
                isConnected = isConnected,
                focusRequester = inputFocusRequester
            )
        }

        if (showAttachmentDialog) {
            AttachmentDialog(
                session = session,
                selectedTimerSec = selectedTimerSec,
                attachmentError = attachmentError,
                onDismiss = { showAttachmentDialog = false },
                onSendAttachment = { type, name, mime, bytes, oneTime, deleteAfterDownload ->
                    onSendAttachment(
                        type,
                        name,
                        mime,
                        bytes,
                        selectedTimerSec,
                        oneTime,
                        deleteAfterDownload,
                        replyingToMessageId,
                        null
                    )
                    replyingToMessageId = null
                    showAttachmentDialog = false
                },
                onExternalSystemUiStart = onExternalSystemUiStart,
                onExternalSystemUiEnd = onExternalSystemUiEnd
            )
        }

        if (showBundledGifDialog) {
            BundledGifDialog(
                session = session,
                onDismiss = { showBundledGifDialog = false },
                onSend = { asset ->
                    onSendAttachment(
                        "IMAGE",
                        asset.fileName,
                        asset.mimeType,
                        asset.bytes,
                        selectedTimerSec,
                        false,
                        false,
                        replyingToMessageId,
                        asset.shortcode
                    )
                    replyingToMessageId = null
                    showBundledGifDialog = false
                }
            )
        }

        if (attachmentPreview != null) {
            AttachmentPreviewDialog(
                attachment = attachmentPreview,
                onDismiss = onDismissAttachmentPreview
            )
        }
    }
}

@Composable
private fun ChatHeader(
    session: ChatSession?,
    status: ServerStatus,
    onBack: () -> Unit
) {
    Column {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            MirageIconButton(
                contentDescription = "Back to dashboard",
                onClick = onBack,
                accent = NeonCyan.copy(alpha = 0.28f)
            ) {
                ArrowBackIcon(modifier = Modifier.size(18.dp), color = NeonCyan)
            }

            Spacer(modifier = Modifier.width(12.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = if (session?.isForum == true) "#${session.name}" else session?.name ?: "Secure chat",
                    color = PureWhite,
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Bold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    LockIcon(modifier = Modifier.size(10.dp), color = NeonGreen)
                    Text(
                        text = "Encrypted  ${status.latencyMs}ms",
                        color = NeonGreen,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold,
                        modifier = Modifier.padding(start = 6.dp)
                    )
                }
            }
        }
        Spacer(
            modifier = Modifier
                .fillMaxWidth()
                .height(1.dp)
                .background(SteelMuted.copy(alpha = 0.12f))
        )
    }
}

@Composable
private fun RetentionPicker(
    selectedTimerSec: Int,
    lockedTimerSec: Int?,
    onSelected: (Int) -> Unit
) {
    val timerOptions = listOf(5, 10, 30, 60)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(DeepBlue.copy(alpha = 0.62f))
            .border(BorderStroke(1.dp, GlassBorder), RoundedCornerShape(topStart = 8.dp, topEnd = 8.dp))
            .padding(horizontal = 14.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            TimerIcon(modifier = Modifier.size(14.dp), color = SteelMuted)
            Text(
                text = if (lockedTimerSec != null) "Room retention" else "Retention",
                color = SteelMuted,
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.padding(start = 7.dp)
            )
        }
        Row(
            modifier = Modifier
                .weight(1f)
                .padding(start = 12.dp)
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(7.dp, Alignment.End),
            verticalAlignment = Alignment.CenterVertically
        ) {
            if (lockedTimerSec != null) {
                TimerChip(
                    text = "${lockedTimerSec}s locked",
                    selected = true,
                    onClick = {}
                )
            } else {
                timerOptions.forEach { option ->
                    TimerChip(
                        text = "${option}s",
                        selected = selectedTimerSec == option,
                        onClick = { onSelected(option) }
                    )
                }
            }
        }
    }
}

@Composable
private fun UploadProgressStrip(uploadProgress: AttachmentUploadProgress) {
    if (!uploadProgress.active) return

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(DeepBlue.copy(alpha = 0.78f))
            .border(BorderStroke(1.dp, NeonCyan.copy(alpha = 0.28f)), RoundedCornerShape(0.dp))
            .padding(horizontal = 14.dp, vertical = 10.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "Uploading ${uploadProgress.mediaType.lowercase()}",
                    color = NeonCyan,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    fontFamily = FontFamily.Monospace
                )
                Text(
                    text = uploadProgress.fileName,
                    color = PureWhite,
                    fontSize = 13.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
            Text(
                text = "${(uploadProgress.fraction * 100f).toInt()}%",
                color = NeonGreen,
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace
            )
        }
        LinearProgressIndicator(
            progress = { uploadProgress.fraction },
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 9.dp)
                .height(4.dp),
            color = NeonCyan,
            trackColor = SteelMuted.copy(alpha = 0.2f)
        )
        Text(
            text = "${formatBytes(uploadProgress.bytesSent)} / ${formatBytes(uploadProgress.totalBytes)}",
            color = SteelMuted,
            fontSize = 11.sp,
            modifier = Modifier.padding(top = 5.dp)
        )
    }
}

@Composable
private fun ReplyComposerPreview(
    message: Message,
    onCancel: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(DeepBlue.copy(alpha = 0.82f))
            .border(BorderStroke(1.dp, NeonCyan.copy(alpha = 0.22f)))
            .padding(horizontal = 12.dp, vertical = 9.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Spacer(
            modifier = Modifier
                .width(3.dp)
                .height(34.dp)
                .background(NeonCyan, RoundedCornerShape(2.dp))
        )
        Column(
            modifier = Modifier
                .weight(1f)
                .padding(horizontal = 10.dp)
        ) {
            Text(
                text = "Replying to ${if (message.sender == "You") "your message" else message.sender}",
                color = NeonCyan,
                fontSize = 12.sp,
                fontWeight = FontWeight.Bold,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Text(
                text = replyPreviewText(message),
                color = SteelMuted,
                fontSize = 12.sp,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
        MirageIconButton(
            contentDescription = "Cancel reply",
            onClick = onCancel,
            modifier = Modifier.size(36.dp)
        ) {
            CloseIcon(modifier = Modifier.size(14.dp), color = SteelMuted)
        }
    }
}

@Composable
private fun ChatInputBar(
    value: String,
    onValueChange: (String) -> Unit,
    onAttach: () -> Unit,
    onGif: () -> Unit,
    onSend: () -> Unit,
    canSend: Boolean,
    isConnected: Boolean,
    focusRequester: FocusRequester
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(DeepBlack)
            .navigationBarsPadding()
            .imePadding()
            .padding(12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        MirageIconButton(
            contentDescription = "Add attachment",
            onClick = onAttach,
            enabled = isConnected
        ) {
            PaperclipIcon(modifier = Modifier.size(20.dp), color = SteelMuted)
        }

        MirageIconButton(
            contentDescription = "Open bundled GIFs",
            onClick = onGif,
            modifier = Modifier.size(44.dp),
            accent = NeonGreen.copy(alpha = 0.24f),
            enabled = isConnected
        ) {
            Text(
                text = "GIF",
                color = NeonGreen,
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace
            )
        }

        OutlinedTextField(
            value = value,
            onValueChange = onValueChange,
            placeholder = {
                Text(
                    if (isConnected) "Message" else "Waiting for node",
                    color = SteelMuted.copy(alpha = 0.65f),
                    fontSize = 14.sp
                )
            },
            textStyle = TextStyle(color = PureWhite, fontSize = 15.sp),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = NeonCyan,
                unfocusedBorderColor = SteelMuted.copy(alpha = 0.24f),
                cursorColor = NeonCyan,
                focusedTextColor = PureWhite,
                unfocusedTextColor = PureWhite
            ),
            shape = RoundedCornerShape(24.dp),
            singleLine = false,
            minLines = 1,
            maxLines = 4,
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
            keyboardActions = KeyboardActions(onSend = { if (canSend) onSend() }),
            modifier = Modifier
                .weight(1f)
                .focusRequester(focusRequester)
                .heightIn(min = 48.dp, max = 136.dp)
                .padding(horizontal = 10.dp)
        )

        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier
                .size(48.dp)
                .clip(CircleShape)
                .background(if (canSend) NeonCyan else SteelMuted.copy(alpha = 0.18f))
                .semantics { contentDescription = "Send message" }
                .clickable(enabled = canSend, role = Role.Button, onClick = onSend)
        ) {
            SendIcon(modifier = Modifier.size(18.dp), color = if (canSend) DeepBlack else SteelMuted)
        }
    }
}

@Composable
private fun ComposerSuggestions(
    reactionSuggestions: List<BundledEmojiAsset>,
    mentionSuggestions: List<String>,
    onReactionSelected: (BundledEmojiAsset) -> Unit,
    onMentionSelected: (String) -> Unit
) {
    if (reactionSuggestions.isEmpty() && mentionSuggestions.isEmpty()) return

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(DeepBlue.copy(alpha = 0.82f))
            .horizontalScroll(rememberScrollState())
            .padding(horizontal = 12.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        reactionSuggestions.forEach { asset ->
            GlassSurface(
                modifier = Modifier
                    .height(44.dp)
                    .clickable { onReactionSelected(asset) },
                borderColor = NeonGreen.copy(alpha = 0.28f),
                backgroundColor = DeepBlack.copy(alpha = 0.52f)
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 9.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    BundledEmojiPreview(
                        assetPath = asset.path,
                        modifier = Modifier
                            .size(30.dp)
                            .clip(RoundedCornerShape(5.dp))
                    )
                    Text(
                        text = asset.shortcode,
                        color = NeonGreen,
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        modifier = Modifier.padding(start = 7.dp)
                    )
                }
            }
        }
        mentionSuggestions.forEach { username ->
            GlassSurface(
                modifier = Modifier
                    .height(44.dp)
                    .clickable { onMentionSelected(username) },
                borderColor = SelfDestructAmber.copy(alpha = 0.3f),
                backgroundColor = DeepBlack.copy(alpha = 0.52f)
            ) {
                Text(
                    text = "@$username",
                    color = SelfDestructAmber,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 13.dp)
                )
            }
        }
    }
}

@Composable
private fun AttachmentDialog(
    session: ChatSession?,
    selectedTimerSec: Int,
    attachmentError: String?,
    onDismiss: () -> Unit,
    onSendAttachment: (String, String, String, ByteArray, Boolean, Boolean) -> Unit,
    onExternalSystemUiStart: () -> Unit,
    onExternalSystemUiEnd: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var localError by remember { mutableStateOf<String?>(null) }
    var oneTimeView by remember { mutableStateOf(false) }
    var deleteAfterDownload by remember { mutableStateOf(false) }
    val imagesOk = session?.allowImages != false
    val videosOk = session?.allowVideos != false
    val filesOk = session?.allowFiles != false
    fun handlePicked(uri: Uri?, mediaType: String, allowOneTime: Boolean) {
        if (uri == null) return
        scope.launch {
            val picked = withContext(Dispatchers.IO) {
                context.readPickedAttachment(uri, mediaType, attachmentLimitBytes(mediaType))
            }
            if (picked == null) {
                localError = "Wrong information."
            } else {
                onSendAttachment(
                    picked.mediaType,
                    picked.name,
                    picked.mimeType,
                    picked.bytes,
                    oneTimeView && allowOneTime,
                    deleteAfterDownload || (oneTimeView && allowOneTime)
                )
            }
        }
    }
    val imagePicker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        onExternalSystemUiEnd()
        handlePicked(uri, "IMAGE", true)
    }
    val videoPicker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        onExternalSystemUiEnd()
        handlePicked(uri, "VIDEO", true)
    }
    val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        onExternalSystemUiEnd()
        handlePicked(uri, "FILE", false)
    }

    MirageDialog(title = "Add attachment", onDismiss = onDismiss) {
        Text(
            text = if (session?.isForum == true) {
                "Room rules: image ${session.imageReadTimerSec}s, video ${session.videoReadTimerSec}s, file ${session.fileReadTimerSec}s after read."
            } else {
                "Encrypted upload. ${selectedTimerSec}s retention after read."
            },
            color = SteelMuted,
            fontSize = 13.sp,
            textAlign = androidx.compose.ui.text.style.TextAlign.Center,
            lineHeight = 18.sp
        )

        if (attachmentError != null || localError != null) {
            Text(
                text = attachmentError ?: localError ?: "",
                color = SelfDestructAmber,
                fontSize = 13.sp,
                textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                modifier = Modifier.padding(top = 12.dp)
            )
        }

        AttachmentOptionToggle(
            label = "One-time view",
            detail = "Images and videos only. Save disabled.",
            checked = oneTimeView,
            onCheckedChange = { oneTimeView = it },
            modifier = Modifier.padding(top = 16.dp)
        )
        AttachmentOptionToggle(
            label = "Delete after download",
            detail = "Server removes encrypted bytes after first fetch.",
            checked = deleteAfterDownload,
            onCheckedChange = { deleteAfterDownload = it },
            modifier = Modifier.padding(top = 8.dp)
        )

        Column(
            modifier = Modifier.padding(top = 14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            AttachmentRow(
                label = "Image",
                detail = roomMediaRuleDetail(session, "IMAGE", "Pick image or GIF up to 20 MB"),
                enabled = imagesOk,
                onClick = {
                    onExternalSystemUiStart()
                    imagePicker.launch("image/*")
                }
            )
            AttachmentRow(
                label = "Video",
                detail = roomMediaRuleDetail(session, "VIDEO", "Pick video up to 100 MB"),
                enabled = videosOk,
                onClick = {
                    onExternalSystemUiStart()
                    videoPicker.launch("video/*")
                }
            )
            AttachmentRow(
                label = "Document",
                detail = roomMediaRuleDetail(session, "FILE", "Pick file up to 200 MB"),
                enabled = filesOk,
                onClick = {
                    onExternalSystemUiStart()
                    filePicker.launch("*/*")
                }
            )
        }

        MirageSecondaryButton(
            text = "Cancel",
            onClick = onDismiss,
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 18.dp)
        )
    }
}

@Composable
private fun AttachmentOptionToggle(
    label: String,
    detail: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier
) {
    Row(
        modifier = modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Checkbox(checked = checked, onCheckedChange = onCheckedChange)
        Column(modifier = Modifier.padding(start = 6.dp)) {
            Text(label, color = PureWhite, fontSize = 13.sp, fontWeight = FontWeight.Bold)
            Text(detail, color = SteelMuted, fontSize = 11.sp)
        }
    }
}

@Composable
private fun AttachmentRow(
    label: String,
    detail: String,
    enabled: Boolean,
    onClick: () -> Unit
) {
    GlassSurface(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(enabled = enabled, onClick = onClick),
        borderColor = if (enabled) GlassBorder else GlassBorder.copy(alpha = 0.18f),
        backgroundColor = if (enabled) Color.White.copy(alpha = 0.06f) else SteelMuted.copy(alpha = 0.05f)
    ) {
        Row(
            modifier = Modifier.padding(13.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .size(36.dp)
                    .clip(CircleShape)
                    .background(DeepBlack.copy(alpha = 0.55f))
            ) {
                MediaFileIcon(
                    modifier = Modifier.size(16.dp),
                    color = if (enabled) NeonCyan else SteelMuted
                )
            }
            Column(modifier = Modifier.padding(start = 12.dp)) {
                Text(
                    text = label,
                    color = if (enabled) PureWhite else SteelMuted,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = if (enabled) detail else "Disabled by room policy",
                    color = SteelMuted,
                    fontSize = 12.sp
                )
            }
        }
    }
}

@Composable
private fun BundledGifDialog(
    session: ChatSession?,
    onDismiss: () -> Unit,
    onSend: (BundledEmojiPayload) -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val assets = remember { context.listBundledEmojiAssets() }
    var query by remember { mutableStateOf("") }
    val filteredAssets = remember(assets, query) {
        val normalized = query.trim().lowercase(Locale.ROOT)
        if (normalized.isEmpty()) assets else assets.filter {
            it.label.contains(normalized) || it.shortcode.contains(normalized)
        }
    }
    val imagesOk = session?.allowImages != false

    MirageDialog(title = "GIFs", onDismiss = onDismiss) {
        if (!imagesOk) {
            Text(
                text = "Disabled by room policy.",
                color = SelfDestructAmber,
                fontSize = 13.sp,
                textAlign = androidx.compose.ui.text.style.TextAlign.Center
            )
        } else {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                placeholder = { Text("Search", color = SteelMuted) },
                singleLine = true,
                textStyle = TextStyle(color = PureWhite, fontSize = 14.sp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = NeonCyan,
                    unfocusedBorderColor = GlassBorder,
                    cursorColor = NeonCyan,
                    focusedTextColor = PureWhite,
                    unfocusedTextColor = PureWhite
                ),
                shape = RoundedCornerShape(8.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 12.dp)
            )
            LazyVerticalGrid(
                columns = GridCells.Fixed(3),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(360.dp)
            ) {
                items(filteredAssets, key = { it.path }) { asset ->
                    BundledEmojiTile(
                        asset = asset,
                        onClick = {
                            scope.launch {
                                withContext(Dispatchers.IO) { context.readBundledEmoji(asset) }
                                    ?.let(onSend)
                            }
                        }
                    )
                }
            }
        }

        MirageSecondaryButton(
            text = "Cancel",
            onClick = onDismiss,
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 16.dp)
        )
    }
}

@Composable
private fun BundledEmojiTile(
    asset: BundledEmojiAsset,
    onClick: () -> Unit
) {
    GlassSurface(
        modifier = Modifier
            .height(106.dp)
            .clickable(onClick = onClick),
        borderColor = GlassBorder.copy(alpha = 0.42f),
        backgroundColor = Color.White.copy(alpha = 0.05f)
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
            modifier = Modifier.padding(6.dp)
        ) {
            BundledEmojiPreview(
                assetPath = asset.path,
                modifier = Modifier
                    .size(58.dp)
                    .clip(RoundedCornerShape(6.dp))
            )
            Text(
                text = asset.shortcode,
                color = NeonGreen,
                fontSize = 10.sp,
                fontFamily = FontFamily.Monospace,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.padding(top = 5.dp)
            )
        }
    }
}

@Composable
private fun BundledEmojiPreview(
    assetPath: String,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        AndroidView(
            factory = { viewContext ->
                ImageView(viewContext).apply {
                    scaleType = ImageView.ScaleType.FIT_CENTER
                    setBackgroundColor(android.graphics.Color.TRANSPARENT)
                    val drawable = runCatching {
                        ImageDecoder.decodeDrawable(
                            ImageDecoder.createSource(viewContext.assets, assetPath)
                        )
                    }.getOrNull()
                    setImageDrawable(drawable)
                    (drawable as? AnimatedImageDrawable)?.start()
                }
            },
            modifier = modifier.background(DeepBlack.copy(alpha = 0.35f))
        )
        return
    }

    val bytes = remember(assetPath) {
        runCatching { context.assets.open(assetPath).use { it.readBytes() } }.getOrNull()
    }
    val bitmap = remember(bytes) { bytes?.let { BitmapFactory.decodeByteArray(it, 0, it.size) } }
    if (bitmap != null) {
        Image(
            bitmap = bitmap.asImageBitmap(),
            contentDescription = null,
            contentScale = ContentScale.Fit,
            modifier = modifier.background(DeepBlack.copy(alpha = 0.35f))
        )
    } else {
        Box(
            contentAlignment = Alignment.Center,
            modifier = modifier.background(DeepBlack.copy(alpha = 0.35f))
        ) {
            MediaFileIcon(modifier = Modifier.size(20.dp), color = SteelMuted)
        }
    }
}

@Composable
private fun MessageBubbleItem(
    message: Message,
    replyTarget: Message?,
    highlighted: Boolean,
    currentUsername: String?,
    onBecomeVisible: () -> Unit,
    onReply: () -> Unit,
    onMentionSender: (String) -> Unit,
    onOpenReply: (String) -> Unit,
    onViewAttachment: () -> Unit,
    onSaveAttachment: () -> Unit
) {
    val isMine = message.sender == "You"
    val requiresAttention = !isMine && (message.mentionsCurrentUser || message.repliesToCurrentUser)

    LaunchedEffect(message.id) {
        onBecomeVisible()
    }

    var progressFraction by remember { mutableFloatStateOf(1f) }
    var millisRemaining by remember { mutableFloatStateOf(message.selfDestructDurationSec * 1000f) }

    LaunchedEffect(message.readTimestampMs) {
        message.readTimestampMs?.let { readTime ->
            val limit = message.selfDestructDurationSec * 1000f
            while (true) {
                val elapsed = System.currentTimeMillis() - readTime
                val remaining = limit - elapsed
                millisRemaining = remaining.coerceAtLeast(0f)
                progressFraction = (remaining / limit).coerceIn(0f, 1f)
                if (remaining <= 0f) break
                delay(100)
            }
        }
    }

    val expiringSoon = millisRemaining <= 3000f && message.readTimestampMs != null
    val visible = millisRemaining > 0f
    val alpha by animateFloatAsState(
        targetValue = if (expiringSoon) 0.82f else 1f,
        animationSpec = tween(250),
        label = "message_alpha"
    )
    val accent = when {
        expiringSoon -> SelfDestructAmber
        requiresAttention -> SelfDestructAmber
        isMine -> NeonCyan
        else -> NeonGreen
    }

    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = if (isMine) Alignment.End else Alignment.Start
    ) {
        if (!isMine) {
            Text(
                text = message.sender,
                color = SteelMuted,
                fontSize = 11.sp,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier
                    .padding(start = 8.dp, bottom = 4.dp)
                    .clickable(role = Role.Button) { onMentionSender(message.sender) }
            )
        }

        AnimatedVisibility(
            visible = visible,
            enter = fadeIn(tween(220)),
            exit = fadeOut(tween(220))
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = if (isMine) Arrangement.End else Arrangement.Start,
                verticalAlignment = Alignment.CenterVertically
            ) {
                if (isMine) {
                    MessageReplyAction(onReply = onReply)
                    Spacer(modifier = Modifier.width(6.dp))
                }

                GlassSurface(
                    modifier = Modifier
                        .fillMaxWidth(0.78f)
                        .alpha(alpha),
                    borderColor = accent.copy(alpha = if (highlighted || requiresAttention) 0.95f else 0.42f),
                    backgroundColor = if (requiresAttention) {
                        SelfDestructAmber.copy(alpha = 0.1f)
                    } else {
                        com.abyssal.chat.theme.GlassCardBg
                    }
                ) {
                    Column(modifier = Modifier.padding(13.dp)) {
                        if (requiresAttention) {
                            Text(
                                text = attentionLabel(message),
                                color = SelfDestructAmber,
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Bold,
                                fontFamily = FontFamily.Monospace,
                                modifier = Modifier.padding(bottom = 8.dp)
                            )
                        }
                        if (message.replyToMessageId != null) {
                            MessageReplyReference(
                                target = replyTarget,
                                onOpen = { onOpenReply(message.replyToMessageId) }
                            )
                            Spacer(modifier = Modifier.height(10.dp))
                        }

                        if (message.isMedia) {
                            MediaMessageContent(
                                message = message,
                                onViewAttachment = onViewAttachment,
                                onSaveAttachment = onSaveAttachment
                            )
                        } else {
                            MessageText(
                                content = message.content,
                                currentUsername = currentUsername
                            )
                        }

                        if (message.readTimestampMs != null) {
                            CountdownRow(
                                millisRemaining = millisRemaining,
                                progressFraction = progressFraction,
                                expiringSoon = expiringSoon
                            )
                        }
                    }
                }

                if (!isMine) {
                    Spacer(modifier = Modifier.width(6.dp))
                    MessageReplyAction(onReply = onReply)
                }
            }
        }
    }
}

private fun attentionLabel(message: Message): String {
    return when {
        message.mentionsCurrentUser && message.repliesToCurrentUser -> "MENTIONED + REPLIED TO YOU"
        message.mentionsCurrentUser -> "MENTIONED YOU"
        else -> "REPLIED TO YOU"
    }
}

@Composable
private fun MessageText(content: String, currentUsername: String?) {
    val styledContent = remember(content, currentUsername) {
        buildAnnotatedString {
            append(content)
            MessageAttentionPolicy.mentionRanges(content, currentUsername).forEach { range ->
                addStyle(
                    style = SpanStyle(
                        color = SelfDestructAmber,
                        background = SelfDestructAmber.copy(alpha = 0.13f),
                        fontWeight = FontWeight.Bold
                    ),
                    start = range.first,
                    end = range.last + 1
                )
            }
        }
    }
    Text(
        text = styledContent,
        color = PureWhite,
        fontSize = 15.sp,
        lineHeight = 21.sp
    )
}

@Composable
private fun MessageReplyAction(onReply: () -> Unit) {
    MirageIconButton(
        contentDescription = "Reply to message",
        onClick = onReply,
        modifier = Modifier.size(36.dp),
        accent = NeonCyan.copy(alpha = 0.18f)
    ) {
        ReplyIcon(modifier = Modifier.size(16.dp), color = SteelMuted)
    }
}

@Composable
private fun MessageReplyReference(
    target: Message?,
    onOpen: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(6.dp))
            .background(DeepBlack.copy(alpha = 0.48f))
            .clickable(enabled = target != null, role = Role.Button, onClick = onOpen)
            .padding(horizontal = 9.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Spacer(
            modifier = Modifier
                .width(2.dp)
                .height(31.dp)
                .background(if (target != null) NeonCyan else SteelMuted, RoundedCornerShape(2.dp))
        )
        Column(modifier = Modifier.padding(start = 8.dp).weight(1f)) {
            Text(
                text = target?.let { if (it.sender == "You") "You" else it.sender }
                    ?: "Original message unavailable",
                color = if (target != null) NeonCyan else SteelMuted,
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            if (target != null) {
                Text(
                    text = replyPreviewText(target),
                    color = SteelMuted,
                    fontSize = 12.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
    }
}

private fun replyPreviewText(message: Message): String {
    if (!message.isMedia) return message.content
    if (message.oneTimeView) return "One-time media"
    val mediaType = message.mediaType?.uppercase(Locale.ROOT) ?: "FILE"
    return "$mediaType - ${message.attachmentName ?: message.content}"
}

@Composable
private fun MediaMessageContent(
    message: Message,
    onViewAttachment: () -> Unit,
    onSaveAttachment: () -> Unit
) {
    val context = LocalContext.current
    val reactionAsset = remember(message.reactionShortcode, message.attachmentName) {
        val shortcode = message.reactionShortcode ?: return@remember null
        context.listBundledEmojiAssets().firstOrNull { asset ->
            asset.shortcode == shortcode && asset.fileName == message.attachmentName
        }
    }
    if (reactionAsset != null) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(8.dp))
                .background(DeepBlack.copy(alpha = 0.42f))
                .border(BorderStroke(1.dp, GlassBorder), RoundedCornerShape(8.dp))
                .padding(8.dp)
        ) {
            BundledEmojiPreview(
                assetPath = reactionAsset.path,
                modifier = Modifier
                    .fillMaxWidth()
                    .aspectRatio(4f / 3f)
                    .clip(RoundedCornerShape(6.dp))
                    .clickable(role = Role.Button, onClick = onViewAttachment)
            )
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 7.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = reactionAsset.shortcode,
                    color = NeonGreen,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    fontFamily = FontFamily.Monospace
                )
                if (message.saveAllowed) {
                    Text(
                        text = "SAVE ENCRYPTED",
                        color = SteelMuted,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.clickable(role = Role.Button, onClick = onSaveAttachment)
                    )
                }
            }
        }
        return
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .background(DeepBlack.copy(alpha = 0.42f))
            .border(BorderStroke(1.dp, GlassBorder), RoundedCornerShape(8.dp))
            .padding(10.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .size(36.dp)
                    .clip(CircleShape)
                    .background(Color.White.copy(alpha = 0.06f))
            ) {
                MediaFileIcon(modifier = Modifier.size(16.dp), color = NeonCyan)
            }
            Column(modifier = Modifier.padding(start = 10.dp).weight(1f)) {
                Text(
                    text = message.mediaType ?: "FILE",
                    color = NeonCyan,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    fontFamily = FontFamily.Monospace
                )
                Text(
                    text = message.attachmentName ?: message.content,
                    color = PureWhite,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = "${message.mediaSizeMb} MB  |  ${if (message.oneTimeView) "one-time view" else "RAM encrypted"}",
                    color = SteelMuted,
                    fontSize = 11.sp
                )
            }
        }

        Row(
            modifier = Modifier.padding(top = 10.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            MirageSecondaryButton(
                text = if (message.oneTimeView) "View once" else "Open",
                onClick = onViewAttachment,
                modifier = Modifier.weight(1f)
            )
            if (message.saveAllowed) {
                MirageSecondaryButton(
                    text = "Save encrypted",
                    onClick = onSaveAttachment,
                    modifier = Modifier.weight(1f)
                )
            }
        }
    }
}

@Composable
private fun CountdownRow(
    millisRemaining: Float,
    progressFraction: Float,
    expiringSoon: Boolean
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.End,
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 10.dp)
    ) {
        Text(
            text = "disappears in",
            color = SteelMuted,
            fontSize = 11.sp
        )
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier
                .padding(start = 6.dp)
                .size(18.dp)
        ) {
            Canvas(modifier = Modifier.fillMaxSize()) {
                drawCircle(
                    color = Color.White.copy(alpha = 0.12f),
                    radius = size.minDimension / 2,
                    style = Stroke(width = 3.dp.toPx())
                )
                drawArc(
                    color = if (expiringSoon) SelfDestructAmber else NeonCyan,
                    startAngle = -90f,
                    sweepAngle = 360f * progressFraction,
                    useCenter = false,
                    style = Stroke(width = 3.dp.toPx())
                )
            }
        }
        Text(
            text = "${String.format(Locale.ROOT, "%.1f", millisRemaining / 1000f)}s",
            color = if (expiringSoon) SelfDestructAmber else NeonCyan,
            fontSize = 12.sp,
            fontWeight = FontWeight.Bold,
            fontFamily = FontFamily.Monospace,
            modifier = Modifier.padding(start = 6.dp)
        )
    }
}

@Composable
private fun AttachmentPreviewDialog(
    attachment: DecryptedAttachment,
    onDismiss: () -> Unit
) {
    MirageDialog(title = attachment.name, onDismiss = onDismiss) {
        when {
            attachment.mimeType.startsWith("video/") -> RamVideoPreview(attachment.bytes)
            attachment.mimeType.startsWith("image/") -> RamImagePreview(attachment.bytes, attachment.mimeType)
            else -> AttachmentLoadedPanel(attachment)
        }

        if (attachment.oneTimeView) {
            Text(
                text = "One-time view. Save disabled.",
                color = SelfDestructAmber,
                fontSize = 12.sp,
                textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                modifier = Modifier.padding(top = 12.dp)
            )
        }

        MiragePrimaryButton(
            text = "Close",
            onClick = onDismiss,
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 16.dp)
        )
    }
}

@Composable
private fun RamImagePreview(bytes: ByteArray, mimeType: String) {
    val isAnimatedGif = mimeType.equals("image/gif", ignoreCase = true)
    if (isAnimatedGif && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        AndroidView(
            factory = { context ->
                ImageView(context).apply {
                    layoutParams = ViewGroup.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.MATCH_PARENT
                    )
                    scaleType = ImageView.ScaleType.FIT_CENTER
                    setBackgroundColor(android.graphics.Color.BLACK)
                    val drawable = runCatching {
                        ImageDecoder.decodeDrawable(ImageDecoder.createSource(ByteBuffer.wrap(bytes)))
                    }.getOrNull()
                    setImageDrawable(drawable)
                    (drawable as? AnimatedImageDrawable)?.start()
                }
            },
            modifier = Modifier
                .fillMaxWidth()
                .height(320.dp)
                .clip(RoundedCornerShape(8.dp))
                .background(DeepBlack)
        )
        return
    }

    val bitmap = remember(bytes) { BitmapFactory.decodeByteArray(bytes, 0, bytes.size) }
    if (bitmap != null) {
        Image(
            bitmap = bitmap.asImageBitmap(),
            contentDescription = "Attachment preview",
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(8.dp))
                .background(DeepBlack)
        )
    } else {
        AttachmentLoadedPanel(
            DecryptedAttachment("", "image", "IMAGE", mimeType, bytes, oneTimeView = false)
        )
    }
}

@Composable
private fun RamVideoPreview(bytes: ByteArray) {
    var prepared by remember(bytes) { mutableStateOf(false) }
    var playbackFailed by remember(bytes) { mutableStateOf(false) }
    val prepareStarted = remember(bytes) { AtomicBoolean(false) }
    val mediaPlayer = remember(bytes) {
        MediaPlayer().apply {
            setDataSource(ByteArrayMediaDataSource(bytes))
            isLooping = true
            setOnPreparedListener { player ->
                prepared = true
                runCatching { player.start() }.onFailure { playbackFailed = true }
            }
            setOnErrorListener { _, _, _ ->
                playbackFailed = true
                true
            }
        }
    }

    DisposableEffect(mediaPlayer) {
        onDispose {
            runCatching {
                if (mediaPlayer.isPlaying) mediaPlayer.stop()
                mediaPlayer.release()
            }
        }
    }

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(320.dp)
            .clip(RoundedCornerShape(8.dp))
            .background(DeepBlack)
    ) {
        AndroidView(
            factory = { context ->
                TextureView(context).apply {
                    setBackgroundColor(android.graphics.Color.BLACK)
                    surfaceTextureListener = object : TextureView.SurfaceTextureListener {
                        private var surface: Surface? = null

                        override fun onSurfaceTextureAvailable(texture: SurfaceTexture, width: Int, height: Int) {
                            surface = Surface(texture).also { renderSurface ->
                                runCatching {
                                    mediaPlayer.setSurface(renderSurface)
                                    if (prepareStarted.compareAndSet(false, true)) {
                                        mediaPlayer.prepareAsync()
                                    } else if (prepared && !mediaPlayer.isPlaying) {
                                        mediaPlayer.start()
                                    }
                                }.onFailure { playbackFailed = true }
                            }
                        }

                        override fun onSurfaceTextureSizeChanged(texture: SurfaceTexture, width: Int, height: Int) = Unit

                        override fun onSurfaceTextureDestroyed(texture: SurfaceTexture): Boolean {
                            runCatching {
                                if (mediaPlayer.isPlaying) mediaPlayer.pause()
                                mediaPlayer.setSurface(null)
                            }
                            surface?.release()
                            surface = null
                            return true
                        }

                        override fun onSurfaceTextureUpdated(texture: SurfaceTexture) = Unit
                    }
                }
            },
            modifier = Modifier.fillMaxSize()
        )

        if (!prepared && !playbackFailed) {
            Text(
                text = "Loading video",
                color = SteelMuted,
                fontSize = 12.sp,
                modifier = Modifier.align(Alignment.Center)
            )
        }

        if (playbackFailed) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.align(Alignment.Center)
            ) {
                MediaFileIcon(modifier = Modifier.size(28.dp), color = SelfDestructAmber)
                Text(
                    text = "Preview unavailable",
                    color = SelfDestructAmber,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(top = 8.dp)
                )
            }
        }
    }
}

@Composable
private fun AttachmentLoadedPanel(attachment: DecryptedAttachment) {
    GlassSurface(modifier = Modifier.fillMaxWidth()) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier.padding(18.dp)
        ) {
            MediaFileIcon(modifier = Modifier.size(28.dp), color = NeonCyan)
            Text(
                text = attachment.mediaType,
                color = NeonCyan,
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.padding(top = 10.dp)
            )
            Text(
                text = "${attachment.bytes.size / 1024} KB loaded in RAM",
                color = SteelMuted,
                fontSize = 12.sp,
                modifier = Modifier.padding(top = 4.dp)
            )
        }
    }
}

private data class PickedAttachment(
    val mediaType: String,
    val name: String,
    val mimeType: String,
    val bytes: ByteArray
)

private data class BundledEmojiAsset(
    val fileName: String
) {
    val path: String = "$BUNDLED_EMOJI_ASSET_DIR/$fileName"
    val label: String = fileName.substringBeforeLast('.')
    val mimeType: String = if (fileName.endsWith(".gif", ignoreCase = true)) "image/gif" else "image/png"
    val shortcode: String = MessageAttentionPolicy.shortcodeForFileName(fileName).orEmpty()
}

private data class BundledEmojiPayload(
    val fileName: String,
    val mimeType: String,
    val bytes: ByteArray,
    val shortcode: String
)

private class ByteArrayMediaDataSource(private val bytes: ByteArray) : MediaDataSource() {
    override fun readAt(position: Long, buffer: ByteArray, offset: Int, size: Int): Int {
        if (position < 0 || position >= bytes.size) return -1
        val length = minOf(size, bytes.size - position.toInt())
        bytes.copyInto(buffer, destinationOffset = offset, startIndex = position.toInt(), endIndex = position.toInt() + length)
        return length
    }

    override fun getSize(): Long = bytes.size.toLong()

    override fun close() = Unit
}

private fun Context.listBundledEmojiAssets(): List<BundledEmojiAsset> {
    return assets.list(BUNDLED_EMOJI_ASSET_DIR)
        ?.filter { name ->
            name.endsWith(".gif", ignoreCase = true) || name.endsWith(".png", ignoreCase = true)
        }
        ?.sorted()
        ?.map(::BundledEmojiAsset)
        ?: emptyList()
}

private fun Context.readBundledEmoji(asset: BundledEmojiAsset): BundledEmojiPayload? {
    return runCatching {
        val bytes = assets.open(asset.path).use { it.readBytes() }
        if (bytes.isEmpty() || bytes.size > attachmentLimitBytes("IMAGE")) return null
        BundledEmojiPayload(
            fileName = asset.fileName,
            mimeType = asset.mimeType,
            bytes = bytes,
            shortcode = asset.shortcode
        )
    }.getOrNull()
}

private fun Context.readPickedAttachment(uri: Uri, mediaType: String, maxBytes: Long): PickedAttachment? {
    var knownSize = -1L
    val name = contentResolver.query(uri, null, null, null, null)?.use { cursor ->
        val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
        val sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE)
        if (cursor.moveToFirst()) {
            if (sizeIndex >= 0) knownSize = cursor.getLong(sizeIndex)
            if (nameIndex >= 0) cursor.getString(nameIndex) else null
        } else {
            null
        }
    } ?: "attachment"
    if (knownSize > maxBytes) return null
    val mimeType = contentResolver.getType(uri) ?: "application/octet-stream"
    val bytes = contentResolver.openInputStream(uri)?.use { input ->
        input.readBytes()
    } ?: return null
    if (bytes.size > maxBytes) return null
    return PickedAttachment(mediaType, name, mimeType, bytes)
}

private fun attachmentLimitBytes(mediaType: String): Long {
    return when (mediaType.uppercase()) {
        "IMAGE" -> 20L * 1024L * 1024L
        "VIDEO" -> 100L * 1024L * 1024L
        else -> 200L * 1024L * 1024L
    }
}

private fun roomMediaRuleDetail(session: ChatSession?, mediaType: String, fallback: String): String {
    if (session?.isForum != true) return fallback
    val (readSec, absoluteSec, enforced) = when (mediaType) {
        "IMAGE" -> Triple(session.imageReadTimerSec, session.imageOverallExpirySec, session.enforceImageAbsoluteExpiry)
        "VIDEO" -> Triple(session.videoReadTimerSec, session.videoOverallExpirySec, session.enforceVideoAbsoluteExpiry)
        else -> Triple(session.fileReadTimerSec, session.fileOverallExpirySec, session.enforceFileAbsoluteExpiry)
    }
    val absolute = if (enforced && absoluteSec > 0) ", ${absoluteSec}s absolute" else ""
    return "${readSec}s after read$absolute"
}

private fun formatBytes(bytes: Long): String {
    val mb = bytes / (1024f * 1024f)
    return if (mb >= 1f) {
        "${String.format(Locale.ROOT, "%.1f", mb)} MB"
    } else {
        "${(bytes / 1024L).coerceAtLeast(0L)} KB"
    }
}

private fun encryptedExportName(name: String): String {
    val safeName = name.ifBlank { "attachment" }
    return if (safeName.endsWith(".abyssal", ignoreCase = true)) safeName else "$safeName.abyssal"
}

private fun trailingComposerToken(value: String): String? {
    val start = value.indexOfLast { it.isWhitespace() } + 1
    val token = value.substring(start)
    return token.takeIf { it.startsWith(":") || it.startsWith("@") }
}

private fun replaceTrailingComposerToken(value: String, replacement: String): String {
    val start = value.indexOfLast { it.isWhitespace() } + 1
    return value.substring(0, start) + replacement + " "
}

private fun appendMention(value: String, username: String): String {
    val prefix = value.trimEnd()
    return if (prefix.isEmpty()) "@$username " else "$prefix @$username "
}

private const val BUNDLED_EMOJI_ASSET_DIR = "abyssal_emojis"

@Preview
@Composable
private fun ChatContentPreview() {
    ChatContent(
        session = ChatSession("room", "operations", true, null, 0, 5),
        messages = listOf(
            Message("1", "NebulaTiger93", null, "Keys rotated for the room.", 0L, 5),
            Message(
                "2",
                "You",
                null,
                "Confirmed.",
                0L,
                10,
                readTimestampMs = System.currentTimeMillis(),
                replyToMessageId = "1"
            )
        ),
        status = ServerStatus("CONNECTED", "Node-Alpha", 24),
        attachmentPreview = null,
        uploadProgress = AttachmentUploadProgress(),
        attachmentError = null,
        currentUsername = "NebulaTiger93",
        presence = listOf(UserPresence("SilentFox482", true)),
        onBack = {},
        onSendMessage = { _, _, _ -> },
        onSendAttachment = { _, _, _, _, _, _, _, _, _ -> },
        onMessageVisible = {},
        onViewAttachment = {},
        onSaveAttachment = { _, _ -> },
        onDismissAttachmentPreview = {},
        onExternalSystemUiStart = {},
        onExternalSystemUiEnd = {},
        onUserActivity = {}
    )
}

@file:OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)

package com.abyssal.chat.presentation.screens

import androidx.compose.foundation.layout.FlowRow
import com.abyssal.chat.domain.model.withDisplayName
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.lazy.itemsIndexed
import com.abyssal.chat.domain.model.roomLabel
import com.abyssal.chat.domain.model.peerLabel
import com.abyssal.chat.domain.model.shortAccountId
import com.abyssal.chat.domain.model.MlsRoomVisibility
import com.abyssal.chat.theme.Warning
import com.abyssal.chat.theme.WarningSoft
import com.abyssal.chat.theme.TextSubtle
import com.abyssal.chat.theme.SurfaceRaised
import com.abyssal.chat.theme.SurfaceHigh
import com.abyssal.chat.theme.OnAccent
import com.abyssal.chat.theme.AccentBorder
import com.abyssal.chat.theme.OwnBubble
import androidx.compose.material3.HorizontalDivider
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.widthIn
import androidx.compose.ui.text.withStyle
import java.text.DateFormat
import java.util.Date
import kotlin.math.ceil
import androidx.compose.ui.graphics.compositeOver
import com.abyssal.chat.data.qr.ClipboardQrImage
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.foundation.text.selection.SelectionContainer
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
import android.widget.Toast
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
import androidx.compose.material3.TextButton
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
import androidx.compose.ui.platform.LocalLifecycleOwner
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
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import com.abyssal.chat.domain.model.AttachmentUploadProgress
import com.abyssal.chat.domain.model.AttachmentSavePolicy
import com.abyssal.chat.domain.model.ChatSession
import com.abyssal.chat.domain.model.DecryptedAttachment
import com.abyssal.chat.domain.model.DirectTrustStatus
import com.abyssal.chat.domain.model.Message
import com.abyssal.chat.domain.model.MessageAttentionPolicy
import com.abyssal.chat.domain.model.SenderClient
import com.abyssal.chat.domain.model.ServerStatus
import com.abyssal.chat.domain.model.UserPresence
import com.abyssal.chat.data.network.BoundedInputReader
import com.abyssal.chat.data.network.ByteArrayAttachmentSource
import com.abyssal.chat.data.network.ContentUriAttachmentSource
import com.abyssal.chat.data.network.attachmentSelectionLimitBytes
import com.abyssal.chat.data.network.protocolAttachmentLimitBytes
import com.abyssal.chat.data.qr.LocalQrImageReader
import com.abyssal.chat.domain.repository.IAttachmentPlaintextSource
import com.abyssal.chat.presentation.viewmodel.ChatViewModel
import com.abyssal.chat.presentation.viewmodel.Screen
import com.abyssal.chat.theme.Background
import com.abyssal.chat.theme.SurfaceBase
import com.abyssal.chat.theme.Outline
import com.abyssal.chat.theme.Accent
import com.abyssal.chat.theme.Success
import com.abyssal.chat.theme.TextPrimary
import com.abyssal.chat.theme.Danger
import com.abyssal.chat.theme.TextMuted
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.Job
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
    val directTrust by viewModel.directTrust.collectAsState()
    val displayNames by viewModel.knownDisplayNames.collectAsState()
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
        directTrust = directTrust,
        onBack = { viewModel.navigateTo(Screen.Dashboard) },
        onSendMessage = viewModel::sendMessage,
        onSendAttachmentSource = viewModel::sendAttachmentSource,
        onMessageVisible = viewModel::markMessageAsRead,
        onViewAttachment = viewModel::viewAttachment,
        onSaveAttachment = viewModel::saveAttachment,
        onDismissAttachmentPreview = viewModel::dismissAttachmentPreview,
        onExternalSystemUiStart = viewModel::beginExternalSystemUi,
        onExternalSystemUiEnd = viewModel::endExternalSystemUi,
        onUserActivity = viewModel::recordUserActivity,
        onVerifyToken = viewModel::verifyDirectVerificationToken,
        knownDisplayNames = displayNames
    )
}

@Composable
internal fun ChatContent(
    session: ChatSession?,
    messages: List<Message>,
    status: ServerStatus,
    attachmentPreview: DecryptedAttachment?,
    uploadProgress: AttachmentUploadProgress,
    attachmentError: String?,
    currentUsername: String?,
    presence: List<UserPresence>,
    directTrust: DirectTrustStatus,
    onBack: () -> Unit,
    onSendMessage: (String, Int, String?) -> Unit,
    onSendAttachmentSource: (
        String,
        String,
        String,
        IAttachmentPlaintextSource,
        Int,
        Boolean,
        Boolean,
        String?,
        String?
    ) -> Unit,
    onMessageVisible: (String) -> Unit,
    onViewAttachment: (Message) -> Unit,
    onSaveAttachment: (Message, Uri) -> Unit,
    onDismissAttachmentPreview: () -> Unit,
    onExternalSystemUiStart: () -> Long,
    onExternalSystemUiEnd: (Long) -> Boolean,
    onUserActivity: () -> Unit,
    onVerifyToken: (String) -> Boolean,
    knownDisplayNames: Map<String, String> = emptyMap()
) {
    // Names seen in this conversation fill in for senders the dashboard has not met yet.
    val displayNames = remember(knownDisplayNames, messages) {
        messages.fold(knownDisplayNames) { names, message ->
            if (message.sender == "You") names else withDisplayName(names, message.sender, message.senderDisplayName)
        }
    }
    var textInput by remember { mutableStateOf("") }
    var selectedTimerSec by remember(session) { mutableIntStateOf(session?.selfDestructTimerSec ?: 5) }
    var showAttachmentDialog by remember { mutableStateOf(false) }
    var showBundledGifDialog by remember { mutableStateOf(false) }
    var saveTargetMessage by remember { mutableStateOf<Message?>(null) }
    var savePickerToken by remember { mutableStateOf<Long?>(null) }
    var replyingToMessageId by remember(session?.id) { mutableStateOf<String?>(null) }
    var highlightedMessageId by remember(session?.id) { mutableStateOf<String?>(null) }
    var hasPositionedMessageList by remember(session?.id) { mutableStateOf(false) }
    var showTrustDialog by remember(session?.id) { mutableStateOf(false) }
    val messageListState = remember(session?.id) { LazyListState() }
    val inputFocusRequester = remember { FocusRequester() }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val hapticFeedback = LocalHapticFeedback.current
    val messagesById = remember(messages) { messages.associateBy(Message::id) }
    val replyingToMessage = replyingToMessageId?.let(messagesById::get)
    val isConnected = ConnectionStatusCopy.isLive(status.state)
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
        val token = savePickerToken
        val accepted = token != null && onExternalSystemUiEnd(token)
        if (token != null && savePickerToken == token) {
            savePickerToken = null
            val message = saveTargetMessage
            saveTargetMessage = null
            if (accepted && uri != null && message != null) onSaveAttachment(message, uri)
        }
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
                directTrust = directTrust,
                presence = presence,
                displayNames = displayNames,
                onVerifySafetyNumber = { showTrustDialog = true },
                onBack = onBack
            )

            if (messages.isEmpty()) {
                EmptyState(
                    title = "No messages yet",
                    detail = "Say hello. Messages live only in memory and disappear on their timer.",
                    icon = AppIcons.Message,
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
                        .padding(horizontal = 8.dp),
                    contentPadding = PaddingValues(vertical = 10.dp)
                ) {
                    itemsIndexed(messages, key = { _, item -> item.id }) { index, message ->
                        MessageBubbleItem(
                            message = message,
                            showSender = index == 0 || messages[index - 1].sender != message.sender,
                            displayNames = displayNames,
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
                                val pickerToken = onExternalSystemUiStart()
                                savePickerToken = pickerToken
                                runCatching {
                                    saveLauncher.launch(AttachmentSavePolicy.sanitizedFileName(message.attachmentName))
                                }.onFailure {
                                    if (savePickerToken == pickerToken) {
                                        onExternalSystemUiEnd(pickerToken)
                                        savePickerToken = null
                                        saveTargetMessage = null
                                    }
                                }
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
                    displayNames = displayNames,
                    onCancel = { replyingToMessageId = null }
                )
            }

            ComposerSuggestions(
                reactionSuggestions = reactionSuggestions,
                mentionSuggestions = mentionSuggestions,
                displayNames = displayNames,
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
                                onSendAttachmentSource(
                                    "IMAGE",
                                    payload.fileName,
                                    payload.mimeType,
                                    ByteArrayAttachmentSource(payload.bytes),
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
                connectionState = status.state,
                focusRequester = inputFocusRequester
            )
        }

        if (showTrustDialog && directTrust.active && directTrust.safetyNumber != null &&
            directTrust.verificationToken != null
        ) {
            DirectTrustDialog(
                safetyNumber = directTrust.safetyNumber,
                verificationToken = directTrust.verificationToken,
                onDismiss = { showTrustDialog = false },
                onVerify = onVerifyToken,
                onExternalSystemUiStart = onExternalSystemUiStart,
                onExternalSystemUiEnd = onExternalSystemUiEnd
            )
        }

        if (showAttachmentDialog) {
            AttachmentDialog(
                session = session,
                selectedTimerSec = selectedTimerSec,
                attachmentError = attachmentError,
                onDismiss = { showAttachmentDialog = false },
                onSendAttachment = { type, name, mime, source, oneTime, deleteAfterDownload ->
                    onSendAttachmentSource(
                        type,
                        name,
                        mime,
                        source,
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
                    onSendAttachmentSource(
                        "IMAGE",
                        asset.fileName,
                        asset.mimeType,
                        ByteArrayAttachmentSource(asset.bytes),
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
    directTrust: DirectTrustStatus,
    presence: List<UserPresence>,
    displayNames: Map<String, String>,
    onVerifySafetyNumber: () -> Unit,
    onBack: () -> Unit
) {
    val isRoom = session?.isForum != false
    val title = when {
        session == null -> "Secure chat"
        session.isForum -> roomLabel(session.id, session.name)
        else -> peerLabel(session.name, displayNames)
    }
    val peerOnline = session?.takeIf { !it.isForum }?.let { direct ->
        presence.firstOrNull { it.username.equals(direct.name, ignoreCase = true) }?.connected
    }
    val canVerify = !isRoom && directTrust.active && directTrust.safetyNumber != null
    Column {
        Row(
            modifier = Modifier.fillMaxWidth().padding(start = 4.dp, end = 8.dp, top = 6.dp, bottom = 6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconAction(AppIcons.ArrowLeft, "Back to dashboard", onBack, tint = TextPrimary)
            if (isRoom) {
                Avatar("", size = 38.dp, icon = if (session?.roomVisibility == MlsRoomVisibility.PUBLIC) AppIcons.Globe else AppIcons.Hash,
                    tone = if (session?.roomVisibility == MlsRoomVisibility.PUBLIC) Tone.Success else Tone.Accent)
            } else {
                Avatar(title, size = 38.dp, online = peerOnline)
            }
            Column(modifier = Modifier.weight(1f).padding(start = 10.dp)) {
                PrivacyBlurred {
                    Text(
                        text = title,
                        color = TextPrimary,
                        fontSize = 17.sp,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(top = 1.dp)) {
                    when {
                        !ConnectionStatusCopy.isLive(status.state) -> Text(
                            ConnectionStatusCopy.statusLabel(status.state),
                            color = Warning,
                            fontSize = 12.sp,
                            maxLines = 1
                        )
                        isRoom -> Text(
                            listOfNotNull(
                                if (session?.roomVisibility == MlsRoomVisibility.PUBLIC) "Public room" else "Private room",
                                session?.let { roomDisappearLabel(it.selfDestructTimerSec) }
                            ).joinToString(" · "),
                            color = TextSubtle,
                            fontSize = 12.sp,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        else -> {
                            Text(
                                if (peerOnline == true) "Online" else "Offline",
                                color = if (peerOnline == true) Success else TextSubtle,
                                fontSize = 12.sp
                            )
                            session?.name?.takeIf { shortAccountId(it) != title }?.let {
                                Text(
                                    " · ${shortAccountId(it)}",
                                    color = TextSubtle,
                                    fontSize = 12.sp,
                                    fontFamily = FontFamily.Monospace,
                                    maxLines = 1
                                )
                            }
                        }
                    }
                }
            }
            if (isRoom && session != null) {
                val clipboard = LocalClipboardManager.current
                val context = LocalContext.current
                var copied by remember(session.id) { mutableStateOf(false) }
                IconAction(
                    icon = if (copied) AppIcons.Check else AppIcons.Copy,
                    contentDescription = if (copied) "Room ID copied" else "Copy room ID",
                    onClick = {
                        clipboard.setText(AnnotatedString(session.id))
                        copied = true
                        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
                            Toast.makeText(context, "Room ID copied", Toast.LENGTH_SHORT).show()
                        }
                    },
                    tint = if (copied) Success else TextMuted
                )
            }
            if (canVerify) {
                ToneBadge(
                    text = if (directTrust.verified) "Verified" else "Verify",
                    tone = if (directTrust.verified) Tone.Success else Tone.Warning,
                    icon = if (directTrust.verified) AppIcons.ShieldCheck else AppIcons.ShieldAlert,
                    onClick = onVerifySafetyNumber,
                    modifier = Modifier.semantics {
                        contentDescription = if (directTrust.verified) "Identity verified. Open verification" else "Not verified. Verify identity"
                    }
                )
            }
        }
        HorizontalDivider(color = Outline)
    }
}

private fun roomDisappearLabel(readSec: Int): String =
    if (readSec > 0) "messages vanish ${durationLabel(readSec)} after reading" else "messages stay until the session ends"

@Composable
private fun DirectTrustDialog(
    safetyNumber: String,
    verificationToken: String,
    onDismiss: () -> Unit,
    onVerify: (String) -> Boolean,
    onExternalSystemUiStart: () -> Long,
    onExternalSystemUiEnd: (Long) -> Boolean
) {
    var presentedToken by remember(verificationToken) { mutableStateOf("") }
    var rejected by remember(verificationToken) { mutableStateOf(false) }
    var scanning by remember(verificationToken) { mutableStateOf(false) }
    var readingImage by remember(verificationToken) { mutableStateOf(false) }
    var imageError by remember(verificationToken) { mutableStateOf(false) }
    var imagePickerToken by remember(verificationToken) { mutableStateOf<Long?>(null) }
    val context = LocalContext.current
    val lifecycle = LocalLifecycleOwner.current
    val scope = rememberCoroutineScope()
    var imageJob by remember(verificationToken) { mutableStateOf<Job?>(null) }
    DisposableEffect(lifecycle, verificationToken) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP) imageJob?.cancel()
        }
        lifecycle.lifecycle.addObserver(observer)
        onDispose {
            lifecycle.lifecycle.removeObserver(observer)
            imageJob?.cancel()
            imagePickerToken?.let(onExternalSystemUiEnd)
            imagePickerToken = null
        }
    }
    val clipboard = LocalClipboardManager.current
    var copied by remember(verificationToken) { mutableStateOf(false) }
    val readImage: (android.net.Uri) -> Unit = { uri ->
        if (!readingImage) {
            readingImage = true
            imageError = false
            imageJob = scope.launch {
                try {
                    val value = LocalQrImageReader.read(context.contentResolver, uri)
                    require(isCanonicalVerificationToken(value))
                    presentedToken = value
                    rejected = false
                } catch (error: CancellationException) {
                    throw error
                } catch (_: Exception) {
                    imageError = true
                } finally {
                    readingImage = false
                }
            }
        }
    }
    val imagePicker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        val token = imagePickerToken
        imagePickerToken = null
        val accepted = token != null && onExternalSystemUiEnd(token)
        if (accepted && uri != null) readImage(uri)
    }
    if (scanning) {
        DirectVerificationQrScanner(
            onScanned = {
                presentedToken = it
                rejected = false
                scanning = false
            },
            onDismiss = { scanning = false },
            onExternalSystemUiStart = onExternalSystemUiStart,
            onExternalSystemUiEnd = onExternalSystemUiEnd
        )
    }
    MirageDialog(
        title = "Verify identity",
        onDismiss = onDismiss,
        icon = { Avatar("", size = 40.dp, icon = AppIcons.ShieldCheck) }
    ) {
        Text(
            text = "Optional. Messages are encrypted either way. Verifying proves you are talking to the right person: compare over a channel you trust, then scan or paste their code.",
            color = TextMuted,
            fontSize = 14.sp,
            lineHeight = 20.sp
        )
        Box(modifier = Modifier.fillMaxWidth().padding(top = 16.dp), contentAlignment = Alignment.Center) {
            DirectVerificationQr(verificationToken)
        }
        SectionLabel("Your verification code", modifier = Modifier.padding(top = 16.dp))
        Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            SelectionContainer(modifier = Modifier.weight(1f)) {
                Text(
                    text = verificationToken,
                    color = TextPrimary,
                    fontSize = 12.sp,
                    lineHeight = 16.sp,
                    fontFamily = FontFamily.Monospace
                )
            }
            IconAction(
                icon = if (copied) AppIcons.Check else AppIcons.Copy,
                contentDescription = if (copied) "Copied" else "Copy verification code",
                onClick = {
                    clipboard.setText(AnnotatedString(verificationToken))
                    copied = true
                },
                tint = if (copied) Success else Accent,
                size = 40.dp,
                iconSize = 18.dp
            )
        }
        SectionLabel("Safety number", modifier = Modifier.padding(top = 14.dp))
        Text(
            text = safetyNumber,
            color = TextPrimary,
            fontSize = 18.sp,
            fontWeight = FontWeight.SemiBold,
            fontFamily = FontFamily.Monospace,
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 4.dp)
                .semantics { contentDescription = "Safety number $safetyNumber" }
        )
        Text(
            text = "You and your peer see the same number. It comes from public keys and is safe to share.",
            color = TextSubtle,
            fontSize = 12.sp,
            lineHeight = 17.sp,
            modifier = Modifier.padding(top = 2.dp)
        )
        SectionLabel("Their code", modifier = Modifier.padding(top = 18.dp, bottom = 8.dp))
        FlowRow(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            MirageSecondaryButton("Scan QR", { scanning = true }, enabled = !readingImage, icon = AppIcons.ScanLine, compact = true)
            MirageSecondaryButton(
                text = if (readingImage) "Reading…" else "Open image",
                onClick = {
                    imagePickerToken = onExternalSystemUiStart()
                    imagePicker.launch("image/*")
                },
                enabled = !readingImage,
                icon = AppIcons.Image,
                compact = true
            )
            MirageSecondaryButton(
                text = "Paste QR image",
                onClick = {
                    val uri = ClipboardQrImage.imageUri(context)
                    if (uri == null) imageError = true else readImage(uri)
                },
                enabled = !readingImage,
                icon = AppIcons.ClipboardPaste,
                compact = true
            )
        }
        if (imageError) {
            Text(
                text = "No valid QR code found. Copy a screenshot of your peer's QR, then paste it.",
                color = Danger,
                fontSize = 12.sp,
                modifier = Modifier.padding(top = 6.dp)
            )
        }
        AppTextField(
            value = presentedToken,
            onValueChange = {
                presentedToken = it.take(96)
                rejected = false
            },
            label = "Peer's verification code",
            placeholder = "abyssal:verify:v1:…",
            textStyle = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 12.sp, color = TextPrimary),
            isError = rejected,
            supportingText = if (rejected) "That code does not match this conversation." else null,
            modifier = Modifier.padding(top = 10.dp)
        )
        Text(
            text = "Trust is kept in memory only and resets after a reconnect, identity change, sign-out, wipe or session expiry.",
            color = TextSubtle,
            fontSize = 12.sp,
            lineHeight = 17.sp,
            modifier = Modifier.padding(top = 10.dp)
        )
        DialogButtons(
            cancel = "Close",
            confirm = "Verify",
            onCancel = onDismiss,
            onConfirm = {
                val accepted = onVerify(presentedToken)
                rejected = !accepted
                if (accepted) {
                    presentedToken = ""
                    onDismiss()
                }
            },
            confirmEnabled = presentedToken.isNotBlank()
        )
    }
}

@Composable
private fun RetentionPicker(
    selectedTimerSec: Int,
    lockedTimerSec: Int?,
    onSelected: (Int) -> Unit
) {
    val timerOptions = listOf(0, 5, 10, 30, 60)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 14.dp, end = 12.dp, top = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        AppIcon(AppIcons.Timer, tint = TextSubtle, size = 16.dp)
        if (lockedTimerSec != null) {
            Text(
                text = if (lockedTimerSec == 0) "The room keeps messages until the session ends"
                else "Room rule: messages disappear ${durationLabel(lockedTimerSec)} after reading",
                color = TextSubtle,
                fontSize = 12.sp,
                modifier = Modifier.padding(start = 6.dp)
            )
        } else {
            Text(
                "After reading",
                color = TextSubtle,
                fontSize = 12.sp,
                maxLines = 1,
                modifier = Modifier.padding(start = 6.dp, end = 10.dp)
            )
            SegmentedControl(
                options = timerOptions.map { if (it == 0) "Off" else durationLabel(it) },
                selectedIndex = timerOptions.indexOf(selectedTimerSec).coerceAtLeast(0),
                onSelect = { onSelected(timerOptions[it]) },
                compact = true,
                modifier = Modifier.weight(1f).semantics { contentDescription = "Disappear after reading" }
            )
        }
    }
}

@Composable
private fun UploadProgressStrip(uploadProgress: AttachmentUploadProgress) {
    if (!uploadProgress.active) return

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 6.dp)
            .clip(ControlShape)
            .background(SurfaceRaised)
            .padding(horizontal = 12.dp, vertical = 10.dp)
            .semantics { contentDescription = "Attachment upload progress" }
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            AppIcon(AppIcons.Paperclip, tint = Accent, size = 16.dp)
            Text(
                text = uploadProgress.fileName,
                color = TextPrimary,
                fontSize = 13.sp,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f).padding(horizontal = 8.dp)
            )
            Text(
                text = "${(uploadProgress.fraction * 100f).toInt()}%",
                color = Accent,
                fontSize = 13.sp,
                fontWeight = FontWeight.SemiBold
            )
        }
        LinearProgressIndicator(
            progress = { uploadProgress.fraction },
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp).height(4.dp).clip(RoundedCornerShape(2.dp)),
            color = Accent,
            trackColor = SurfaceHigh
        )
        Text(
            text = "Encrypting and uploading · ${formatBytes(uploadProgress.bytesSent)} of ${formatBytes(uploadProgress.totalBytes)}",
            color = TextSubtle,
            fontSize = 12.sp,
            modifier = Modifier.padding(top = 6.dp)
        )
    }
}

@Composable
private fun ReplyComposerPreview(
    message: Message,
    displayNames: Map<String, String>,
    onCancel: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 12.dp, end = 12.dp, top = 8.dp)
            .clip(ControlShape)
            .background(SurfaceRaised)
            .padding(start = 12.dp, end = 2.dp, top = 6.dp, bottom = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Spacer(modifier = Modifier.width(3.dp).height(34.dp).background(Accent, RoundedCornerShape(2.dp)))
        Column(modifier = Modifier.weight(1f).padding(horizontal = 10.dp)) {
            Text(
                text = "Replying to ${if (message.sender == "You") "yourself" else peerLabel(message.sender, displayNames)}",
                color = Accent,
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            PrivacyBlurred(revealOnTap = false) {
                Text(
                    text = replyPreviewText(message),
                    color = TextMuted,
                    fontSize = 13.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
        IconAction(AppIcons.Close, "Cancel reply", onCancel, size = 36.dp, iconSize = 16.dp)
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
    connectionState: String,
    focusRequester: FocusRequester
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .navigationBarsPadding()
            .imePadding()
            .padding(start = 6.dp, end = 10.dp, top = 8.dp, bottom = 8.dp),
        verticalAlignment = Alignment.Bottom
    ) {
        IconAction(AppIcons.Paperclip, "Add attachment", onAttach, enabled = isConnected, tint = TextMuted)
        IconAction(AppIcons.SmilePlus, "Send a GIF", onGif, enabled = isConnected, tint = TextMuted)
        Box(
            contentAlignment = Alignment.CenterStart,
            modifier = Modifier
                .weight(1f)
                .padding(horizontal = 4.dp)
                .heightIn(min = 44.dp)
                .clip(RoundedCornerShape(22.dp))
                .background(SurfaceRaised)
                .border(1.dp, Outline, RoundedCornerShape(22.dp))
                .padding(horizontal = 16.dp, vertical = 11.dp)
        ) {
            if (value.isEmpty()) {
                Text(
                    ConnectionStatusCopy.composerPlaceholder(connectionState),
                    color = TextSubtle,
                    fontSize = 15.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
            BasicTextField(
                value = value,
                onValueChange = onValueChange,
                textStyle = TextStyle(color = TextPrimary, fontSize = 15.sp, lineHeight = 21.sp),
                cursorBrush = SolidColor(Accent),
                maxLines = 5,
                keyboardOptions = KeyboardOptions(
                    capitalization = KeyboardCapitalization.Sentences,
                    imeAction = ImeAction.Send
                ),
                keyboardActions = KeyboardActions(onSend = { if (canSend) onSend() }),
                modifier = Modifier
                    .fillMaxWidth()
                    .focusRequester(focusRequester)
                    .semantics { contentDescription = "Message" }
            )
        }
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier
                .size(44.dp)
                .clip(CircleShape)
                .background(if (canSend) Accent else SurfaceHigh)
                .semantics { contentDescription = "Send message" }
                .clickable(enabled = canSend, role = Role.Button, onClick = onSend)
        ) {
            AppIcon(AppIcons.Send, tint = if (canSend) OnAccent else TextSubtle, size = 20.dp)
        }
    }
}

@Composable
private fun ComposerSuggestions(
    reactionSuggestions: List<BundledEmojiAsset>,
    mentionSuggestions: List<String>,
    displayNames: Map<String, String>,
    onReactionSelected: (BundledEmojiAsset) -> Unit,
    onMentionSelected: (String) -> Unit
) {
    if (reactionSuggestions.isEmpty() && mentionSuggestions.isEmpty()) return

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .padding(start = 12.dp, end = 12.dp, top = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        reactionSuggestions.forEach { asset ->
            Row(
                modifier = Modifier
                    .height(44.dp)
                    .clip(ControlShape)
                    .background(SurfaceRaised)
                    .border(1.dp, Outline, ControlShape)
                    .clickable(role = Role.Button, onClickLabel = "Send ${asset.shortcode}") { onReactionSelected(asset) }
                    .padding(horizontal = 8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                BundledEmojiPreview(assetPath = asset.path, modifier = Modifier.size(30.dp).clip(RoundedCornerShape(6.dp)))
                Text(
                    text = asset.shortcode,
                    color = TextMuted,
                    fontSize = 12.sp,
                    fontFamily = FontFamily.Monospace,
                    modifier = Modifier.padding(start = 6.dp)
                )
            }
        }
        mentionSuggestions.forEach { username ->
            val label = peerLabel(username, displayNames)
            Row(
                modifier = Modifier
                    .height(44.dp)
                    .clip(ControlShape)
                    .background(SurfaceRaised)
                    .border(1.dp, Outline, ControlShape)
                    .clickable(role = Role.Button, onClickLabel = "Mention $label") { onMentionSelected(username) }
                    .padding(start = 6.dp, end = 12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Avatar(label, size = 30.dp)
                Text(
                    text = "@$label",
                    color = TextPrimary,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.padding(start = 8.dp)
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
    onSendAttachment: (
        String,
        String,
        String,
        IAttachmentPlaintextSource,
        Boolean,
        Boolean
    ) -> Unit,
    onExternalSystemUiStart: () -> Long,
    onExternalSystemUiEnd: (Long) -> Boolean
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var localError by remember { mutableStateOf<String?>(null) }
    var oneTimeView by remember { mutableStateOf(false) }
    var deleteAfterDownload by remember { mutableStateOf(false) }
    var pickerToken by remember { mutableStateOf<Long?>(null) }
    val imagesOk = session?.allowImages != false
    val videosOk = session?.allowVideos != false
    val filesOk = session?.allowFiles != false
    fun handlePicked(uri: Uri?, mediaType: String, allowOneTime: Boolean) {
        if (uri == null) return
        scope.launch {
            try {
                val picked = withContext(Dispatchers.IO) {
                    context.readPickedAttachment(uri, mediaType, protocolAttachmentLimitBytes(mediaType))
                }
                if (picked == null) {
                    localError = "That file could not be read. Try another one."
                } else {
                    var transferred = false
                    try {
                        onSendAttachment(
                            picked.mediaType,
                            picked.name,
                            picked.mimeType,
                            picked.source,
                            oneTimeView && allowOneTime,
                            deleteAfterDownload || (oneTimeView && allowOneTime)
                        )
                        transferred = true
                    } finally {
                        if (!transferred) picked.source.destroy()
                    }
                }
            } catch (error: CancellationException) {
                throw error
            } catch (_: Exception) {
                // Content providers are external processes. Never let provider faults
                // crash the app or expose a provider-specific error to the user.
                localError = "That file could not be read. Try another one."
            }
        }
    }

    fun finishPicker(uri: Uri?, mediaType: String, allowOneTime: Boolean) {
        val token = pickerToken
        val accepted = token != null && onExternalSystemUiEnd(token)
        if (token != null && pickerToken == token) pickerToken = null
        // Do not even open the provider URI for an expired or stale callback.
        if (accepted) handlePicked(uri, mediaType, allowOneTime)
    }

    val imagePicker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        finishPicker(uri, "IMAGE", true)
    }
    val videoPicker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        finishPicker(uri, "VIDEO", true)
    }
    val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        finishPicker(uri, "FILE", false)
    }

    MirageDialog(
        title = "Send an attachment",
        onDismiss = onDismiss,
        icon = { Avatar("", size = 40.dp, icon = AppIcons.Paperclip) }
    ) {
        Text(
            text = if (session?.isForum == true) {
                "Encrypted before upload. Room rules: images ${retentionLabel(session.imageReadTimerSec)}, videos ${retentionLabel(session.videoReadTimerSec)}, files ${retentionLabel(session.fileReadTimerSec)} after reading."
            } else {
                if (selectedTimerSec == 0) "Encrypted before upload. Kept until the session ends."
                else "Encrypted before upload. Disappears ${durationLabel(selectedTimerSec)} after reading."
            },
            color = TextMuted,
            fontSize = 14.sp,
            lineHeight = 20.sp
        )

        if (attachmentError != null || localError != null) {
            Text(
                text = attachmentError ?: localError ?: "",
                color = Danger,
                fontSize = 13.sp,
                modifier = Modifier.padding(top = 12.dp)
            )
        }

        AttachmentOptionToggle(
            label = "View once",
            detail = "Images and videos open one time and cannot be saved.",
            checked = oneTimeView,
            onCheckedChange = { oneTimeView = it },
            modifier = Modifier.padding(top = 16.dp)
        )
        AttachmentOptionToggle(
            label = "Delete after download",
            detail = "The relay removes the encrypted file once it is downloaded.",
            checked = deleteAfterDownload,
            onCheckedChange = { deleteAfterDownload = it },
            modifier = Modifier.padding(top = 8.dp)
        )

        Column(
            modifier = Modifier.padding(top = 14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            AttachmentRow(
                label = "Photo or GIF",
                detail = roomMediaRuleDetail(session, "IMAGE", "Up to 20 MB"),
                enabled = imagesOk,
                icon = AppIcons.Image,
                onClick = {
                    val token = onExternalSystemUiStart()
                    pickerToken = token
                    runCatching { imagePicker.launch("image/*") }
                        .onFailure {
                            if (pickerToken == token) {
                                onExternalSystemUiEnd(token)
                                pickerToken = null
                            }
                            localError = "That file could not be read. Try another one."
                        }
                }
            )
            AttachmentRow(
                label = "Video",
                detail = roomMediaRuleDetail(session, "VIDEO", "Up to 100 MB"),
                enabled = videosOk,
                icon = AppIcons.Video,
                onClick = {
                    val token = onExternalSystemUiStart()
                    pickerToken = token
                    runCatching { videoPicker.launch("video/*") }
                        .onFailure {
                            if (pickerToken == token) {
                                onExternalSystemUiEnd(token)
                                pickerToken = null
                            }
                            localError = "That file could not be read. Try another one."
                        }
                }
            )
            AttachmentRow(
                label = "File",
                detail = roomMediaRuleDetail(session, "FILE", "Up to 200 MB"),
                enabled = filesOk,
                icon = AppIcons.File,
                onClick = {
                    val token = onExternalSystemUiStart()
                    pickerToken = token
                    runCatching { filePicker.launch("*/*") }
                        .onFailure {
                            if (pickerToken == token) {
                                onExternalSystemUiEnd(token)
                                pickerToken = null
                            }
                            localError = "That file could not be read. Try another one."
                        }
                }
            )
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

private fun retentionLabel(seconds: Int): String = if (seconds == 0) "never" else durationLabel(seconds)

@Composable
private fun AttachmentOptionToggle(
    label: String,
    detail: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier
) {
    Box(modifier = modifier) {
        PreferenceSwitch(label = label, detail = detail, checked = checked, onCheckedChange = onCheckedChange)
    }
}

@Composable
private fun AttachmentRow(
    label: String,
    detail: String,
    enabled: Boolean,
    onClick: () -> Unit,
    icon: ImageVector = AppIcons.File
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(ControlShape)
            .background(SurfaceRaised)
            .border(1.dp, Outline, ControlShape)
            .clickable(enabled = enabled, role = Role.Button, onClick = onClick)
            .alpha(if (enabled) 1f else 0.5f)
            .padding(12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Avatar("", size = 40.dp, icon = icon, tone = if (enabled) Tone.Accent else Tone.Neutral)
        Column(modifier = Modifier.padding(start = 12.dp).weight(1f)) {
            Text(text = label, color = TextPrimary, fontSize = 15.sp, fontWeight = FontWeight.SemiBold)
            Text(text = if (enabled) detail else "Not allowed in this room", color = TextMuted, fontSize = 13.sp)
        }
        AppIcon(AppIcons.ChevronRight, tint = TextSubtle, size = 18.dp)
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

    MirageDialog(
        title = "Send a GIF",
        onDismiss = onDismiss,
        icon = { Avatar("", size = 40.dp, icon = AppIcons.SmilePlus) }
    ) {
        if (!imagesOk) {
            Text(text = "This room does not allow images or GIFs.", color = TextMuted, fontSize = 14.sp)
        } else {
            AppTextField(
                value = query,
                onValueChange = { query = it.take(32) },
                label = "Search GIFs",
                placeholder = "wave, party, thumbs…",
                modifier = Modifier.padding(bottom = 12.dp)
            )
            LazyVerticalGrid(
                columns = GridCells.Fixed(3),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(340.dp)
            ) {
                items(filteredAssets, key = { it.path }) { asset ->
                    BundledEmojiTile(
                        asset = asset,
                        onClick = {
                            scope.launch {
                                val payload = withContext(Dispatchers.IO) { context.readBundledEmoji(asset) }
                                    ?: return@launch
                                var transferred = false
                                try {
                                    onSend(payload)
                                    transferred = true
                                } finally {
                                    if (!transferred) payload.bytes.fill(0)
                                }
                            }
                        }
                    )
                }
            }
        }

        MirageSecondaryButton(
            text = "Close",
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
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
        modifier = Modifier
            .height(104.dp)
            .clip(ControlShape)
            .background(SurfaceRaised)
            .clickable(role = Role.Button, onClickLabel = "Send ${asset.shortcode}", onClick = onClick)
            .padding(6.dp)
    ) {
        BundledEmojiPreview(assetPath = asset.path, modifier = Modifier.size(60.dp).clip(RoundedCornerShape(8.dp)))
        Text(
            text = asset.shortcode,
            color = TextMuted,
            fontSize = 11.sp,
            fontFamily = FontFamily.Monospace,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.padding(top = 6.dp)
        )
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
                        ) { decoder, info, _ ->
                            decoder.setTargetSampleSize(previewSampleSize(info.size.width, info.size.height))
                            decoder.setMemorySizePolicy(ImageDecoder.MEMORY_POLICY_LOW_RAM)
                        }
                    }.getOrNull()
                    setImageDrawable(drawable)
                    (drawable as? AnimatedImageDrawable)?.start()
                }
            },
            modifier = modifier.background(Background.copy(alpha = 0.35f))
        )
        return
    }

    val bytes = remember(assetPath) {
        runCatching {
            context.assets.open(assetPath).use {
                BoundedInputReader.read(it, attachmentSelectionLimitBytes("IMAGE"))
            }
        }.getOrNull()
    }
    val bitmap = remember(bytes) { bytes?.let(::decodeBoundedPreviewBitmap) }
    if (bitmap != null) {
        Image(
            bitmap = bitmap.asImageBitmap(),
            contentDescription = null,
            contentScale = ContentScale.Fit,
            modifier = modifier.background(Background.copy(alpha = 0.35f))
        )
    } else {
        Box(
            contentAlignment = Alignment.Center,
            modifier = modifier.background(Background.copy(alpha = 0.35f))
        ) {
            AppIcon(AppIcons.File, tint = TextMuted, size = 20.dp)
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun MessageBubbleItem(
    message: Message,
    replyTarget: Message?,
    highlighted: Boolean,
    showSender: Boolean,
    currentUsername: String?,
    displayNames: Map<String, String>,
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
    var millisRemaining by remember {
        mutableFloatStateOf(
            if (message.selfDestructDurationSec > 0) message.selfDestructDurationSec * 1000f
            else Float.POSITIVE_INFINITY
        )
    }

    LaunchedEffect(message.readTimestampMs) {
        message.readTimestampMs?.takeIf { message.selfDestructDurationSec > 0 }?.let { readTime ->
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

    val expiringSoon = message.selfDestructDurationSec > 0 && millisRemaining <= 3000f && message.readTimestampMs != null
    val visible = message.selfDestructDurationSec == 0 || millisRemaining > 0f
    val alpha by animateFloatAsState(
        targetValue = if (expiringSoon) 0.7f else 1f,
        animationSpec = tween(250),
        label = "message_alpha"
    )
    val bubbleShape = if (isMine) {
        RoundedCornerShape(topStart = 18.dp, topEnd = 18.dp, bottomStart = 18.dp, bottomEnd = 6.dp)
    } else {
        RoundedCornerShape(topStart = 18.dp, topEnd = 18.dp, bottomStart = 6.dp, bottomEnd = 18.dp)
    }
    val borderColor = when {
        highlighted -> Accent
        requiresAttention -> Warning.copy(alpha = 0.6f)
        isMine -> AccentBorder.copy(alpha = 0.25f)
        else -> Outline
    }

    Column(
        modifier = Modifier.fillMaxWidth().padding(top = if (showSender) 10.dp else 2.dp),
        horizontalAlignment = if (isMine) Alignment.End else Alignment.Start
    ) {
        if (!isMine && showSender) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.padding(start = 6.dp, bottom = 4.dp)
            ) {
                val label = message.senderDisplayName?.takeIf { it.isNotBlank() } ?: peerLabel(message.sender, displayNames)
                PrivacyBlurred(modifier = Modifier.weight(1f, fill = false)) {
                    Text(
                        text = label,
                        color = Accent,
                        fontSize = 13.sp,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.clickable(role = Role.Button, onClickLabel = "Mention") { onMentionSender(message.sender) }
                    )
                }
                if (label != shortAccountId(message.sender)) {
                    Text(
                        shortAccountId(message.sender),
                        color = TextSubtle,
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        maxLines = 1,
                        modifier = Modifier.padding(start = 6.dp)
                    )
                }
                if (message.senderClient == SenderClient.WEB) {
                    WebOriginBadge(notice = message.senderClient.originNotice())
                }
            }
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
                if (isMine) MessageReplyAction(onReply = onReply)

                Column(
                    modifier = Modifier
                        .weight(1f, fill = false)
                        .widthIn(max = 340.dp)
                        .alpha(alpha)
                        .clip(bubbleShape)
                        .background(
                            when {
                                requiresAttention -> WarningSoft.compositeOver(SurfaceRaised)
                                isMine -> OwnBubble
                                else -> SurfaceRaised
                            }
                        )
                        .border(1.dp, borderColor, bubbleShape)
                        .combinedClickable(
                            onClick = {},
                            onLongClick = onReply,
                            onLongClickLabel = "Reply"
                        )
                        .padding(horizontal = 12.dp, vertical = 9.dp)
                ) {
                    if (requiresAttention) {
                        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(bottom = 6.dp)) {
                            AppIcon(AppIcons.At, tint = Warning, size = 13.dp)
                            Text(
                                text = attentionLabel(message),
                                color = Warning,
                                fontSize = 12.sp,
                                fontWeight = FontWeight.SemiBold,
                                modifier = Modifier.padding(start = 4.dp)
                            )
                        }
                    }
                    if (message.replyToMessageId != null) {
                        MessageReplyReference(
                            target = replyTarget,
                            displayNames = displayNames,
                            onOpen = { onOpenReply(message.replyToMessageId) }
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                    }

                    if (message.isMedia) {
                        MediaMessageContent(
                            message = message,
                            onViewAttachment = onViewAttachment,
                            onSaveAttachment = onSaveAttachment
                        )
                    } else {
                        PrivacyBlurred {
                            MessageText(content = message.content, currentUsername = currentUsername)
                        }
                    }

                    MessageFooter(
                        timestampMs = message.timestampMs,
                        counting = message.readTimestampMs != null && message.selfDestructDurationSec > 0,
                        millisRemaining = millisRemaining,
                        progressFraction = progressFraction,
                        expiringSoon = expiringSoon,
                        retentionSec = message.selfDestructDurationSec,
                        modifier = Modifier.align(Alignment.End)
                    )
                }

                if (!isMine) MessageReplyAction(onReply = onReply)
            }
        }
    }
}

private fun attentionLabel(message: Message): String {
    return when {
        message.mentionsCurrentUser && message.repliesToCurrentUser -> "Mentioned and replied to you"
        message.mentionsCurrentUser -> "Mentioned you"
        else -> "Replied to you"
    }
}

@Composable
private fun WebOriginBadge(notice: String) {
    val context = LocalContext.current
    ToneBadge(
        text = "Web",
        tone = Tone.Neutral,
        icon = AppIcons.Monitor,
        onClick = { Toast.makeText(context, notice, Toast.LENGTH_LONG).show() },
        modifier = Modifier.padding(start = 6.dp).semantics { contentDescription = notice }
    )
}

@Composable
private fun MessageText(content: String, currentUsername: String?) {
    val styledContent = remember(content, currentUsername) {
        buildAnnotatedString {
            var cursor = 0
            MessageAttentionPolicy.mentionRanges(content, currentUsername).forEach { range ->
                append(content.substring(cursor, range.first))
                // Show the reader's own mention as "@you", as the web client does.
                withStyle(SpanStyle(color = Warning, background = WarningSoft, fontWeight = FontWeight.SemiBold)) {
                    append("@you")
                }
                cursor = range.last + 1
            }
            append(content.substring(cursor))
        }
    }
    Text(
        text = styledContent,
        color = TextPrimary,
        fontSize = 15.sp,
        lineHeight = 21.sp
    )
}

/** Send time plus, once read, a small countdown ring until the message disappears. */
@Composable
private fun MessageFooter(
    timestampMs: Long,
    counting: Boolean,
    millisRemaining: Float,
    progressFraction: Float,
    expiringSoon: Boolean,
    retentionSec: Int,
    modifier: Modifier = Modifier
) {
    val time = remember(timestampMs) { DateFormat.getTimeInstance(DateFormat.SHORT).format(Date(timestampMs)) }
    Row(verticalAlignment = Alignment.CenterVertically, modifier = modifier.padding(top = 4.dp)) {
        when {
            counting -> {
                val color = if (expiringSoon) Danger else TextSubtle
                Canvas(modifier = Modifier.size(11.dp)) {
                    drawCircle(color = color.copy(alpha = 0.3f), radius = size.minDimension / 2, style = Stroke(width = 1.6.dp.toPx()))
                    drawArc(
                        color = color,
                        startAngle = -90f,
                        sweepAngle = 360f * progressFraction,
                        useCenter = false,
                        style = Stroke(width = 1.6.dp.toPx())
                    )
                }
                Text(
                    "${ceil(millisRemaining / 1000f).toInt()}s",
                    color = color,
                    fontSize = 11.sp,
                    modifier = Modifier.padding(start = 4.dp, end = 8.dp)
                        .semantics { contentDescription = "Disappears in ${ceil(millisRemaining / 1000f).toInt()} seconds" }
                )
            }
            retentionSec > 0 -> {
                AppIcon(AppIcons.Timer, tint = TextSubtle, size = 11.dp)
                Text(
                    "${durationLabel(retentionSec)} after reading",
                    color = TextSubtle,
                    fontSize = 11.sp,
                    modifier = Modifier.padding(start = 3.dp, end = 8.dp)
                )
            }
        }
        Text(time, color = TextSubtle, fontSize = 11.sp)
    }
}

@Composable
private fun MessageReplyAction(onReply: () -> Unit) {
    IconAction(AppIcons.Reply, "Reply to message", onReply, size = 36.dp, iconSize = 16.dp, tint = TextSubtle)
}

@Composable
private fun MessageReplyReference(
    target: Message?,
    displayNames: Map<String, String>,
    onOpen: () -> Unit
) {
    Row(
        modifier = Modifier
            .clip(RoundedCornerShape(10.dp))
            .background(Background.copy(alpha = 0.45f))
            .clickable(enabled = target != null, role = Role.Button, onClickLabel = "Show original", onClick = onOpen)
            .padding(horizontal = 8.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Spacer(
            modifier = Modifier
                .width(3.dp)
                .height(30.dp)
                .background(if (target != null) Accent else TextSubtle, RoundedCornerShape(2.dp))
        )
        Column(modifier = Modifier.padding(start = 8.dp)) {
            Text(
                text = target?.let { if (it.sender == "You") "You" else peerLabel(it.sender, displayNames) }
                    ?: "Original message is gone",
                color = if (target != null) Accent else TextSubtle,
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            if (target != null) {
                PrivacyBlurred(revealOnTap = false) {
                    Text(
                        text = replyPreviewText(target),
                        color = TextMuted,
                        fontSize = 13.sp,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
        }
    }
}

private fun replyPreviewText(message: Message): String = conversationPreview(message.copy(sender = ""))

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
        Column {
            BundledEmojiPreview(
                assetPath = reactionAsset.path,
                modifier = Modifier
                    .size(160.dp)
                    .clip(RoundedCornerShape(12.dp))
                    .clickable(role = Role.Button, onClickLabel = "Open GIF", onClick = onViewAttachment)
            )
            Text(
                text = reactionAsset.shortcode,
                color = TextSubtle,
                fontSize = 12.sp,
                fontFamily = FontFamily.Monospace,
                modifier = Modifier.padding(top = 4.dp)
            )
        }
        return
    }

    val icon = when (message.mediaType) {
        "IMAGE" -> AppIcons.Image
        "VIDEO" -> AppIcons.Video
        else -> AppIcons.File
    }
    Column(modifier = Modifier.widthIn(min = 220.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Avatar("", size = 40.dp, icon = icon)
            Column(modifier = Modifier.padding(start = 10.dp).weight(1f, fill = false)) {
                PrivacyBlurred {
                    Text(
                        text = if (message.oneTimeView) "One-time ${(message.mediaType ?: "file").lowercase(Locale.ROOT)}"
                        else message.attachmentName ?: message.content,
                        color = TextPrimary,
                        fontSize = 14.sp,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                Text(
                    text = listOfNotNull(
                        if (message.attachmentSizeBytes > 0) formatBytes(message.attachmentSizeBytes) else "${message.mediaSizeMb} MB",
                        if (message.oneTimeView) "opens once" else "encrypted"
                    ).joinToString(" · "),
                    color = TextSubtle,
                    fontSize = 12.sp
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
                icon = AppIcons.Eye,
                compact = true,
                modifier = Modifier.weight(1f)
            )
            if (AttachmentSavePolicy.canSave(message)) {
                MirageSecondaryButton(
                    text = "Save",
                    onClick = onSaveAttachment,
                    icon = AppIcons.Download,
                    compact = true,
                    modifier = Modifier.weight(1f)
                )
            }
        }
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
                color = Danger,
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
                        ImageDecoder.decodeDrawable(ImageDecoder.createSource(ByteBuffer.wrap(bytes))) { decoder, info, _ ->
                            decoder.setTargetSampleSize(previewSampleSize(info.size.width, info.size.height))
                            decoder.setMemorySizePolicy(ImageDecoder.MEMORY_POLICY_LOW_RAM)
                        }
                    }.getOrNull()
                    setImageDrawable(drawable)
                    (drawable as? AnimatedImageDrawable)?.start()
                }
            },
            modifier = Modifier
                .fillMaxWidth()
                .height(320.dp)
                .clip(RoundedCornerShape(8.dp))
                .background(Background)
        )
        return
    }

    val bitmap = remember(bytes) { decodeBoundedPreviewBitmap(bytes) }
    if (bitmap != null) {
        Image(
            bitmap = bitmap.asImageBitmap(),
            contentDescription = "Attachment preview",
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(8.dp))
                .background(Background)
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
    var prepareRequested by remember(bytes) { mutableStateOf(false) }
    val prepareStarted = remember(bytes) { AtomicBoolean(false) }
    val mediaPlayer = remember(bytes) {
        val player = runCatching { MediaPlayer() }.getOrNull() ?: return@remember null
        runCatching {
            player.setDataSource(ByteArrayMediaDataSource(bytes))
            player.isLooping = true
            player.setOnPreparedListener { preparedPlayer ->
                prepared = true
                runCatching { preparedPlayer.start() }.onFailure { playbackFailed = true }
            }
            player.setOnErrorListener { _, _, _ ->
                playbackFailed = true
                true
            }
            player
        }.getOrElse {
            runCatching { player.release() }
            null
        }
    }

    if (mediaPlayer == null) {
        AttachmentLoadedPanel(
            DecryptedAttachment("", "video", "VIDEO", "video/*", bytes, oneTimeView = false)
        )
        return
    }

    DisposableEffect(mediaPlayer) {
        onDispose {
            runCatching {
                if (mediaPlayer.isPlaying) mediaPlayer.stop()
                mediaPlayer.release()
            }
        }
    }

    // MediaPlayer is an external parser. A malformed authenticated attachment
    // must not keep the chat surface waiting forever.
    LaunchedEffect(prepareRequested, prepared, playbackFailed) {
        if (!prepareRequested || prepared || playbackFailed) return@LaunchedEffect
        delay(MAX_VIDEO_PREPARE_MS)
        if (!prepared && !playbackFailed) {
            playbackFailed = true
            runCatching { mediaPlayer.reset() }
        }
    }

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(320.dp)
            .clip(RoundedCornerShape(8.dp))
            .background(Background)
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
                                        prepareRequested = true
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
            Column(
                modifier = Modifier.align(Alignment.Center),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                AbyssalMarkLoader(
                    size = AbyssalMarkLoaderSize.Small,
                    description = "Loading video"
                )
                Text(
                    text = "Loading video",
                    color = TextMuted,
                    fontSize = 12.sp,
                    modifier = Modifier.padding(top = 8.dp)
                )
            }
        }

        if (playbackFailed) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.align(Alignment.Center)
            ) {
                AppIcon(AppIcons.File, tint = Danger, size = 28.dp)
                Text(
                    text = "Preview unavailable",
                    color = Danger,
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
            AppIcon(AppIcons.File, tint = Accent, size = 28.dp)
            Text(
                text = attachment.mediaType,
                color = Accent,
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.padding(top = 10.dp)
            )
            Text(
                text = "${attachment.bytes.size / 1024} KB loaded in RAM",
                color = TextMuted,
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
    val source: IAttachmentPlaintextSource
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
        if (
            position < 0L ||
            position >= bytes.size.toLong() ||
            offset < 0 ||
            size < 0 ||
            offset > buffer.size - size
        ) return -1
        val start = position.toInt()
        val length = minOf(size, bytes.size - start)
        bytes.copyInto(buffer, destinationOffset = offset, startIndex = start, endIndex = start + length)
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
        val bytes = assets.open(asset.path).use {
            BoundedInputReader.read(it, attachmentSelectionLimitBytes("IMAGE"))
        } ?: return null
        if (bytes.isEmpty()) return null
        BundledEmojiPayload(
            fileName = asset.fileName,
            mimeType = asset.mimeType,
            bytes = bytes,
            shortcode = asset.shortcode
        )
    }.getOrNull()
}

private fun Context.readPickedAttachment(uri: Uri, mediaType: String, maxBytes: Long): PickedAttachment? {
    return runCatching {
        require(maxBytes in 1L..Int.MAX_VALUE.toLong())
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
        if (knownSize <= 0L) {
            knownSize = contentResolver.openAssetFileDescriptor(uri, "r")?.use { descriptor ->
                descriptor.length
            } ?: -1L
        }
        if (knownSize !in 1L..maxBytes) return@runCatching null
        val mimeType = contentResolver.getType(uri) ?: "application/octet-stream"
        PickedAttachment(
            mediaType = mediaType,
            name = AttachmentSavePolicy.sanitizedFileName(name),
            mimeType = mimeType.take(128),
            source = ContentUriAttachmentSource(contentResolver, uri, knownSize)
        )
    }.getOrNull()
}

private const val MAX_PREVIEW_DIMENSION = 4096
private const val MAX_PREVIEW_PIXELS = 16_000_000L

private fun previewSampleSize(width: Int, height: Int): Int {
    if (width <= 0 || height <= 0) return 1
    var sample = 1
    while (
        width / sample > MAX_PREVIEW_DIMENSION ||
        height / sample > MAX_PREVIEW_DIMENSION ||
        (width.toLong() / sample.toLong()) * (height.toLong() / sample.toLong()) > MAX_PREVIEW_PIXELS
    ) {
        sample = sample shl 1
    }
    return sample
}

private fun decodeBoundedPreviewBitmap(bytes: ByteArray): android.graphics.Bitmap? {
    if (bytes.isEmpty()) return null
    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
    BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
    if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
    val options = BitmapFactory.Options().apply {
        inSampleSize = previewSampleSize(bounds.outWidth, bounds.outHeight)
        inPreferredConfig = android.graphics.Bitmap.Config.ARGB_8888
    }
    return runCatching { BitmapFactory.decodeByteArray(bytes, 0, bytes.size, options) }.getOrNull()
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
private const val MAX_VIDEO_PREPARE_MS = 15_000L

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
        presence = listOf(UserPresence("SilentFox482", true, ByteArray(608))),
        directTrust = DirectTrustStatus(),
        onBack = {},
        onSendMessage = { _, _, _ -> },
        onSendAttachmentSource = { _, _, _, source, _, _, _, _, _ -> source.destroy() },
        onMessageVisible = {},
        onViewAttachment = {},
        onSaveAttachment = { _, _ -> },
        onDismissAttachmentPreview = {},
        onExternalSystemUiStart = { 1L },
        onExternalSystemUiEnd = { true },
        onUserActivity = {},
        onVerifyToken = { false }
    )
}

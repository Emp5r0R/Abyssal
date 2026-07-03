package com.abyssal.chat.presentation.screens

import android.content.Context
import android.graphics.BitmapFactory
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.Checkbox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.foundation.Image
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.abyssal.chat.domain.model.ChatSession
import com.abyssal.chat.domain.model.DecryptedAttachment
import com.abyssal.chat.domain.model.Message
import com.abyssal.chat.domain.model.ServerStatus
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

@Composable
fun ChatScreen(viewModel: ChatViewModel, sessionId: String) {
    val messages by viewModel.activeMessages.collectAsState()
    val sessions by viewModel.sessions.collectAsState()
    val status by viewModel.serverStatus.collectAsState()
    val attachmentPreview by viewModel.attachmentPreview.collectAsState()
    val attachmentError = viewModel.attachmentError.value
    val currentSession = remember(sessions, sessionId) { sessions.find { it.id == sessionId } }

    ChatContent(
        session = currentSession,
        messages = messages,
        status = status,
        attachmentPreview = attachmentPreview,
        attachmentError = attachmentError,
        onBack = { viewModel.navigateTo(Screen.Dashboard) },
        onSendMessage = viewModel::sendMessage,
        onSendAttachment = viewModel::sendAttachment,
        onMessageVisible = viewModel::markMessageAsRead,
        onViewAttachment = viewModel::viewAttachment,
        onSaveAttachment = viewModel::saveAttachment,
        onDismissAttachmentPreview = viewModel::dismissAttachmentPreview,
        onExternalSystemUiStart = viewModel::beginExternalSystemUi,
        onExternalSystemUiEnd = viewModel::endExternalSystemUi
    )
}

@Composable
private fun ChatContent(
    session: ChatSession?,
    messages: List<Message>,
    status: ServerStatus,
    attachmentPreview: DecryptedAttachment?,
    attachmentError: String?,
    onBack: () -> Unit,
    onSendMessage: (String, Int) -> Unit,
    onSendAttachment: (String, String, String, ByteArray, Int, Boolean, Boolean) -> Unit,
    onMessageVisible: (String) -> Unit,
    onViewAttachment: (Message) -> Unit,
    onSaveAttachment: (Message, Uri) -> Unit,
    onDismissAttachmentPreview: () -> Unit,
    onExternalSystemUiStart: () -> Unit,
    onExternalSystemUiEnd: () -> Unit
) {
    var textInput by remember { mutableStateOf("") }
    var selectedTimerSec by remember(session) { mutableIntStateOf(session?.selfDestructTimerSec ?: 5) }
    var showAttachmentDialog by remember { mutableStateOf(false) }
    var saveTargetMessage by remember { mutableStateOf<Message?>(null) }
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
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f)
                        .padding(horizontal = 14.dp, vertical = 10.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    items(messages, key = { it.id }) { message ->
                        MessageBubbleItem(
                            message = message,
                            onBecomeVisible = { onMessageVisible(message.id) },
                            onViewAttachment = { onViewAttachment(message) },
                            onSaveAttachment = {
                                saveTargetMessage = message
                                onExternalSystemUiStart()
                                saveLauncher.launch(message.attachmentName ?: "attachment")
                            }
                        )
                    }
                }
            }

            RetentionPicker(
                selectedTimerSec = selectedTimerSec,
                onSelected = { selectedTimerSec = it }
            )

            ChatInputBar(
                value = textInput,
                onValueChange = { textInput = it },
                onAttach = { showAttachmentDialog = true },
                onSend = {
                    val trimmed = textInput.trim()
                    if (trimmed.isNotEmpty()) {
                        onSendMessage(trimmed, selectedTimerSec)
                        textInput = ""
                    }
                },
                canSend = textInput.isNotBlank()
            )
        }

        if (showAttachmentDialog) {
            AttachmentDialog(
                session = session,
                selectedTimerSec = selectedTimerSec,
                attachmentError = attachmentError,
                onDismiss = { showAttachmentDialog = false },
                onSendAttachment = { type, name, mime, bytes, oneTime, deleteAfterDownload ->
                    onSendAttachment(type, name, mime, bytes, selectedTimerSec, oneTime, deleteAfterDownload)
                    showAttachmentDialog = false
                },
                onExternalSystemUiStart = onExternalSystemUiStart,
                onExternalSystemUiEnd = onExternalSystemUiEnd
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
                text = "Retention",
                color = SteelMuted,
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.padding(start = 7.dp)
            )
        }
        Row(horizontalArrangement = Arrangement.spacedBy(7.dp)) {
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

@Composable
private fun ChatInputBar(
    value: String,
    onValueChange: (String) -> Unit,
    onAttach: () -> Unit,
    onSend: () -> Unit,
    canSend: Boolean
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
            onClick = onAttach
        ) {
            PaperclipIcon(modifier = Modifier.size(20.dp), color = SteelMuted)
        }

        OutlinedTextField(
            value = value,
            onValueChange = onValueChange,
            placeholder = {
                Text("Message", color = SteelMuted.copy(alpha = 0.65f), fontSize = 14.sp)
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
            singleLine = true,
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
            keyboardActions = KeyboardActions(onSend = { if (canSend) onSend() }),
            modifier = Modifier
                .weight(1f)
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
            val picked = withContext(Dispatchers.IO) { context.readPickedAttachment(uri, mediaType) }
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
            text = "Encrypted upload. ${selectedTimerSec}s retention after read.",
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
                detail = "Pick image from device",
                enabled = imagesOk,
                onClick = {
                    onExternalSystemUiStart()
                    imagePicker.launch("image/*")
                }
            )
            AttachmentRow(
                label = "Video",
                detail = "Pick video from device",
                enabled = videosOk,
                onClick = {
                    onExternalSystemUiStart()
                    videoPicker.launch("video/*")
                }
            )
            AttachmentRow(
                label = "Document",
                detail = "Pick file up to 100 MB",
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
private fun MessageBubbleItem(
    message: Message,
    onBecomeVisible: () -> Unit,
    onViewAttachment: () -> Unit,
    onSaveAttachment: () -> Unit
) {
    val isMine = message.sender == "You"

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
                modifier = Modifier.padding(start = 8.dp, bottom = 4.dp)
            )
        }

        AnimatedVisibility(
            visible = visible,
            enter = fadeIn(tween(220)),
            exit = fadeOut(tween(220))
        ) {
            GlassSurface(
                modifier = Modifier
                    .fillMaxWidth(0.86f)
                    .alpha(alpha),
                borderColor = accent.copy(alpha = 0.42f)
            ) {
                Column(modifier = Modifier.padding(13.dp)) {
                    if (message.isMedia) {
                        MediaMessageContent(
                            message = message,
                            onViewAttachment = onViewAttachment,
                            onSaveAttachment = onSaveAttachment
                        )
                    } else {
                        Text(
                            text = message.content,
                            color = PureWhite,
                            fontSize = 15.sp,
                            lineHeight = 21.sp
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
        }
    }
}

@Composable
private fun MediaMessageContent(
    message: Message,
    onViewAttachment: () -> Unit,
    onSaveAttachment: () -> Unit
) {
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
                    text = "Save",
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
            text = "${String.format("%.1f", millisRemaining / 1000f)}s",
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
        val bitmap = remember(attachment.bytes, attachment.mimeType) {
            if (attachment.mimeType.startsWith("image/")) {
                BitmapFactory.decodeByteArray(attachment.bytes, 0, attachment.bytes.size)
            } else {
                null
            }
        }
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

private data class PickedAttachment(
    val mediaType: String,
    val name: String,
    val mimeType: String,
    val bytes: ByteArray
)

private fun Context.readPickedAttachment(uri: Uri, mediaType: String): PickedAttachment? {
    val name = contentResolver.query(uri, null, null, null, null)?.use { cursor ->
        val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
        if (cursor.moveToFirst() && index >= 0) cursor.getString(index) else null
    } ?: "attachment"
    val mimeType = contentResolver.getType(uri) ?: "application/octet-stream"
    val bytes = contentResolver.openInputStream(uri)?.use { input ->
        input.readBytes()
    } ?: return null
    if (bytes.size > 100 * 1024 * 1024) return null
    return PickedAttachment(mediaType, name, mimeType, bytes)
}

@Preview
@Composable
private fun ChatContentPreview() {
    ChatContent(
        session = ChatSession("room", "operations", true, null, 0, 5),
        messages = listOf(
            Message("1", "NebulaTiger93", null, "Keys rotated for the room.", 0L, 5),
            Message("2", "You", null, "Confirmed.", 0L, 10, readTimestampMs = System.currentTimeMillis())
        ),
        status = ServerStatus("CONNECTED", "Node-Alpha", 24),
        attachmentPreview = null,
        attachmentError = null,
        onBack = {},
        onSendMessage = { _, _ -> },
        onSendAttachment = { _, _, _, _, _, _, _ -> },
        onMessageVisible = {},
        onViewAttachment = {},
        onSaveAttachment = { _, _ -> },
        onDismissAttachmentPreview = {},
        onExternalSystemUiStart = {},
        onExternalSystemUiEnd = {}
    )
}

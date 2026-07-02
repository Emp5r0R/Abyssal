package com.abyssal.chat.presentation.screens

import androidx.compose.foundation.BorderStroke
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
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.TabRowDefaults
import androidx.compose.material3.TabRowDefaults.tabIndicatorOffset
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.abyssal.chat.domain.model.ChatSession
import com.abyssal.chat.domain.model.DisguiseSettings
import com.abyssal.chat.domain.model.Message
import com.abyssal.chat.domain.model.ServerStatus
import com.abyssal.chat.domain.model.User
import com.abyssal.chat.domain.model.UserPresence
import com.abyssal.chat.presentation.viewmodel.ChatViewModel
import com.abyssal.chat.presentation.viewmodel.Screen
import com.abyssal.chat.theme.BorderCyan
import com.abyssal.chat.theme.DeepBlack
import com.abyssal.chat.theme.GlassBorder
import com.abyssal.chat.theme.MutedWhite
import com.abyssal.chat.theme.NeonCyan
import com.abyssal.chat.theme.NeonGreen
import com.abyssal.chat.theme.PureWhite
import com.abyssal.chat.theme.SelfDestructAmber
import com.abyssal.chat.theme.SteelMuted

@Composable
fun DashboardScreen(viewModel: ChatViewModel) {
    val currentUser by viewModel.currentUser.collectAsState()
    val sessions by viewModel.sessions.collectAsState()
    val status by viewModel.serverStatus.collectAsState()
    val disguiseSet by viewModel.disguiseSettings.collectAsState()
    val presence by viewModel.presence.collectAsState()
    val showCamouflagePinPrompt = viewModel.showCamouflagePinPrompt.value

    DashboardContent(
        currentUser = currentUser,
        sessions = sessions,
        status = status,
        presence = presence,
        disguiseSettings = disguiseSet,
        onOpenChat = { viewModel.navigateTo(Screen.Chat(it)) },
        onUpdateDisguise = viewModel::updateDisguiseSettings,
        onCreateForum = viewModel::createForum,
        onWipe = viewModel::executeAdminClearAll
    )

    if (showCamouflagePinPrompt) {
        CamouflagePinSetupDialog(onSave = viewModel::completeCamouflagePinSetup)
    }
}

@Composable
private fun DashboardContent(
    currentUser: User?,
    sessions: List<ChatSession>,
    status: ServerStatus,
    presence: List<UserPresence>,
    disguiseSettings: DisguiseSettings,
    onOpenChat: (String) -> Unit,
    onUpdateDisguise: (Boolean, String) -> Unit,
    onCreateForum: (String, Int, Int, Boolean, Boolean, Boolean) -> Unit,
    onWipe: () -> Unit
) {
    var selectedTab by remember { mutableIntStateOf(0) }
    var showSettingsDialog by remember { mutableStateOf(false) }
    var showCreateForumDialog by remember { mutableStateOf(false) }
    var showWipeDialog by remember { mutableStateOf(false) }

    val filteredSessions = remember(sessions, selectedTab) {
        sessions.filter { it.isForum == (selectedTab == 0) }
    }

    MirageBackground {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .navigationBarsPadding()
        ) {
            DashboardHeader(
                currentUser = currentUser,
                status = status,
                onSettings = { showSettingsDialog = true }
            )

            TabRow(
                selectedTabIndex = selectedTab,
                containerColor = Color.Transparent,
                contentColor = NeonCyan,
                indicator = { tabPositions ->
                    TabRowDefaults.SecondaryIndicator(
                        modifier = Modifier.tabIndicatorOffset(tabPositions[selectedTab]),
                        color = NeonCyan,
                        height = 2.dp
                    )
                },
                divider = {
                    Spacer(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(1.dp)
                            .background(SteelMuted.copy(alpha = 0.12f))
                    )
                }
            ) {
                Tab(
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 },
                    text = { Text("Rooms", fontWeight = FontWeight.Bold) }
                )
                Tab(
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    text = { Text("Direct", fontWeight = FontWeight.Bold) }
                )
            }

            PresenceStrip(
                users = presence,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 10.dp)
            )

            if (filteredSessions.isEmpty()) {
                EmptyState(
                    title = if (selectedTab == 0) "No active rooms" else "No direct messages",
                    detail = "New encrypted conversations appear here while they are available in memory.",
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f)
                )
            } else {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f)
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    items(filteredSessions, key = { it.id }) { session ->
                        ChatSessionItem(session = session, onClick = { onOpenChat(session.id) })
                    }
                }
            }
        }

        if (currentUser?.isAdmin == true) {
            Column(
                modifier = Modifier
                    .align(Alignment.BottomEnd)
                    .navigationBarsPadding()
                    .padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                if (selectedTab == 0) {
                    FloatingActionButton(
                        onClick = { showCreateForumDialog = true },
                        containerColor = NeonCyan,
                        contentColor = DeepBlack,
                        shape = CircleShape
                    ) {
                        Text("+", fontSize = 24.sp, fontWeight = FontWeight.Bold)
                    }
                }
                FloatingActionButton(
                    onClick = { showWipeDialog = true },
                    containerColor = SelfDestructAmber,
                    contentColor = PureWhite,
                    shape = CircleShape
                ) {
                    HazardIcon(modifier = Modifier.size(24.dp), color = PureWhite)
                }
            }
        }

        if (showSettingsDialog) {
            SettingsDialog(
                initialSettings = disguiseSettings,
                onDismiss = { showSettingsDialog = false },
                onSave = { enabled, pin ->
                    onUpdateDisguise(enabled, pin)
                    showSettingsDialog = false
                }
            )
        }

        if (showCreateForumDialog) {
            CreateForumDialog(
                onDismiss = { showCreateForumDialog = false },
                onCreate = { name, readExpiry, overallExpiry, images, videos, files ->
                    onCreateForum(name, readExpiry, overallExpiry, images, videos, files)
                    showCreateForumDialog = false
                }
            )
        }

        if (showWipeDialog) {
            ConfirmWipeDialog(
                onDismiss = { showWipeDialog = false },
                onConfirm = {
                    showWipeDialog = false
                    onWipe()
                }
            )
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun DashboardHeader(
    currentUser: User?,
    status: ServerStatus,
    onSettings: () -> Unit
) {
    FlowRow(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 20.dp, vertical = 18.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalArrangement = Arrangement.spacedBy(12.dp),
        maxItemsInEachRow = 2
    ) {
        Column(modifier = Modifier.weight(1f, fill = false)) {
            SectionLabel("IDENTITY", color = NeonGreen)
            Text(
                text = currentUser?.username ?: "Anonymous",
                color = PureWhite,
                fontSize = 20.sp,
                fontWeight = FontWeight.Bold,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Text(
                text = if (currentUser?.isAdmin == true) "Admin controls enabled" else "Ephemeral session",
                color = SteelMuted,
                fontSize = 12.sp,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }

        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            StatusPill("${status.state} ${status.latencyMs}ms")
            MirageIconButton(
                contentDescription = "Open security settings",
                onClick = onSettings
            ) {
                SettingsIcon(modifier = Modifier.size(18.dp), color = SteelMuted)
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun PresenceStrip(
    users: List<UserPresence>,
    modifier: Modifier = Modifier
) {
    if (users.isEmpty()) {
        return
    }

    FlowRow(
        modifier = modifier,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        users.sortedBy { it.username }.forEach { user ->
            Row(
                modifier = Modifier
                    .clip(RoundedCornerShape(8.dp))
                    .background(Color.White.copy(alpha = 0.04f))
                    .border(BorderStroke(1.dp, GlassBorder), RoundedCornerShape(8.dp))
                    .padding(horizontal = 10.dp, vertical = 7.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(7.dp)
            ) {
                Box(
                    modifier = Modifier
                        .size(8.dp)
                        .clip(CircleShape)
                        .background(if (user.connected) NeonGreen else SteelMuted)
                )
                Text(
                    text = user.username,
                    color = PureWhite,
                    fontSize = 12.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = if (user.connected) "online" else "offline",
                    color = if (user.connected) NeonGreen else SteelMuted,
                    fontSize = 11.sp,
                    maxLines = 1
                )
            }
        }
    }
}

@Composable
private fun SettingsDialog(
    initialSettings: DisguiseSettings,
    onDismiss: () -> Unit,
    onSave: (Boolean, String) -> Unit
) {
    var disguiseEnabled by remember(initialSettings) { mutableStateOf(initialSettings.isDisguised) }
    var pinCode by remember(initialSettings) { mutableStateOf(initialSettings.pin) }

    MirageDialog(title = "Security", onDismiss = onDismiss) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text("Calculator disguise", color = PureWhite, fontSize = 15.sp, fontWeight = FontWeight.Bold)
                Text("Show a calculator cover when the app locks.", color = SteelMuted, fontSize = 12.sp)
            }
            Switch(
                checked = disguiseEnabled,
                onCheckedChange = { disguiseEnabled = it },
                colors = SwitchDefaults.colors(
                    checkedThumbColor = NeonCyan,
                    checkedTrackColor = NeonCyan.copy(alpha = 0.28f),
                    uncheckedThumbColor = SteelMuted,
                    uncheckedTrackColor = SteelMuted.copy(alpha = 0.2f)
                )
            )
        }

        if (disguiseEnabled) {
            OutlinedTextField(
                value = pinCode,
                onValueChange = { if (it.length <= 12) pinCode = it },
                label = { Text("Unlock PIN or expression") },
                colors = mirageTextFieldColors(),
                singleLine = true,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 16.dp)
            )
            Text(
                text = "Enter this sequence and tap = on the calculator cover to unlock Abyssal.",
                color = SteelMuted,
                fontSize = 12.sp,
                lineHeight = 17.sp,
                modifier = Modifier.padding(top = 8.dp)
            )
        }

        DialogButtons(
            cancel = "Cancel",
            confirm = "Save",
            onCancel = onDismiss,
            onConfirm = { onSave(disguiseEnabled, pinCode.ifBlank { "2026" }) }
        )
    }
}

@Composable
private fun CamouflagePinSetupDialog(
    onSave: (String) -> Unit
) {
    var pinCode by remember { mutableStateOf("") }
    val canSave = pinCode.length >= 4

    MirageDialog(title = "Calculator PIN", onDismiss = {}) {
        Text(
            text = "Choose a calculator cover PIN for this device session. Remember it; Abyssal will not save it to disk.",
            color = SteelMuted,
            fontSize = 13.sp,
            lineHeight = 18.sp
        )
        OutlinedTextField(
            value = pinCode,
            onValueChange = { if (it.length <= 32) pinCode = it },
            label = { Text("Camouflage PIN") },
            colors = mirageTextFieldColors(),
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii),
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 16.dp)
        )
        MiragePrimaryButton(
            text = "Remember and continue",
            onClick = { onSave(pinCode) },
            enabled = canSave,
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 18.dp)
        )
    }
}

@Composable
private fun CreateForumDialog(
    onDismiss: () -> Unit,
    onCreate: (String, Int, Int, Boolean, Boolean, Boolean) -> Unit
) {
    var forumName by remember { mutableStateOf("") }
    var readExpiryText by remember { mutableStateOf("5") }
    var overallExpiryText by remember { mutableStateOf("0") }
    var imagesAllowed by remember { mutableStateOf(true) }
    var videosAllowed by remember { mutableStateOf(true) }
    var filesAllowed by remember { mutableStateOf(true) }

    MirageDialog(title = "Create room", onDismiss = onDismiss) {
        OutlinedTextField(
            value = forumName,
            onValueChange = { forumName = it.take(36) },
            label = { Text("Room name") },
            colors = mirageTextFieldColors(),
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 12.dp),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            OutlinedTextField(
                value = readExpiryText,
                onValueChange = { readExpiryText = it.filter(Char::isDigit).take(4) },
                label = { Text("Read timer") },
                colors = mirageTextFieldColors(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                singleLine = true,
                modifier = Modifier.weight(1f)
            )
            OutlinedTextField(
                value = overallExpiryText,
                onValueChange = { overallExpiryText = it.filter(Char::isDigit).take(4) },
                label = { Text("Absolute timer") },
                colors = mirageTextFieldColors(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                singleLine = true,
                modifier = Modifier.weight(1f)
            )
        }

        Text(
            text = "Absolute timer uses seconds after send. Use 0 to disable.",
            color = SteelMuted,
            fontSize = 12.sp,
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 8.dp)
        )

        Column(modifier = Modifier.padding(top = 16.dp)) {
            SectionLabel("ALLOWED PAYLOADS")
            PayloadCheckbox("Images and GIFs", imagesAllowed) { imagesAllowed = it }
            PayloadCheckbox("Video files", videosAllowed) { videosAllowed = it }
            PayloadCheckbox("Documents up to 100 MB", filesAllowed) { filesAllowed = it }
        }

        DialogButtons(
            cancel = "Cancel",
            confirm = "Create",
            confirmEnabled = forumName.isNotBlank(),
            onCancel = onDismiss,
            onConfirm = {
                onCreate(
                    forumName.trim(),
                    readExpiryText.toIntOrNull()?.coerceAtLeast(1) ?: 5,
                    overallExpiryText.toIntOrNull()?.coerceAtLeast(0) ?: 0,
                    imagesAllowed,
                    videosAllowed,
                    filesAllowed
                )
            }
        )
    }
}

@Composable
private fun ConfirmWipeDialog(
    onDismiss: () -> Unit,
    onConfirm: () -> Unit
) {
    MirageDialog(
        title = "Wipe local sessions",
        onDismiss = onDismiss,
        accent = SelfDestructAmber,
        icon = { HazardIcon(modifier = Modifier.size(34.dp), color = SelfDestructAmber) }
    ) {
        Text(
            text = "This sends the wipe command and clears local session data on clients that honor it. This cannot force deletion on modified clients.",
            color = MutedWhite,
            fontSize = 14.sp,
            lineHeight = 20.sp,
            textAlign = TextAlign.Center
        )
        DialogButtons(
            cancel = "Cancel",
            confirm = "Confirm wipe",
            danger = true,
            onCancel = onDismiss,
            onConfirm = onConfirm
        )
    }
}

@Composable
private fun PayloadCheckbox(
    label: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onCheckedChange(!checked) }
    ) {
        Checkbox(
            checked = checked,
            onCheckedChange = onCheckedChange,
            colors = CheckboxDefaults.colors(checkedColor = NeonCyan, uncheckedColor = SteelMuted)
        )
        Text(label, color = PureWhite, fontSize = 14.sp)
    }
}

@Composable
private fun DialogButtons(
    cancel: String,
    confirm: String,
    onCancel: () -> Unit,
    onConfirm: () -> Unit,
    confirmEnabled: Boolean = true,
    danger: Boolean = false
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 24.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        MirageSecondaryButton(text = cancel, onClick = onCancel, modifier = Modifier.weight(1f))
        MiragePrimaryButton(
            text = confirm,
            onClick = onConfirm,
            enabled = confirmEnabled,
            danger = danger,
            modifier = Modifier.weight(1f)
        )
    }
}

@Composable
private fun ChatSessionItem(session: ChatSession, onClick: () -> Unit) {
    val accent = if (session.isForum) NeonCyan else NeonGreen

    GlassSurface(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        borderColor = accent.copy(alpha = 0.26f)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Row(
                modifier = Modifier.weight(1f),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    contentAlignment = Alignment.Center,
                    modifier = Modifier
                        .size(46.dp)
                        .clip(CircleShape)
                        .background(DeepBlack.copy(alpha = 0.78f))
                        .border(BorderStroke(1.dp, accent.copy(alpha = 0.38f)), CircleShape)
                ) {
                    Text(
                        text = if (session.isForum) "#" else session.name.take(2).uppercase(),
                        color = accent,
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace
                    )
                }

                Spacer(modifier = Modifier.width(12.dp))

                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = if (session.isForum) "#${session.name}" else session.name,
                        color = PureWhite,
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Bold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        text = session.lastMessage?.content ?: "No active messages.",
                        color = SteelMuted,
                        fontSize = 13.sp,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.padding(top = 3.dp)
                    )
                }
            }

            Column(horizontalAlignment = Alignment.End) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    TimerIcon(modifier = Modifier.size(12.dp), color = SelfDestructAmber)
                    Text(
                        text = if (session.overallExpirySec > 0) "${session.overallExpirySec}s" else "${session.selfDestructTimerSec}s",
                        color = SelfDestructAmber,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace,
                        modifier = Modifier.padding(start = 4.dp)
                    )
                }
                if (session.unreadCount > 0) {
                    Box(
                        contentAlignment = Alignment.Center,
                        modifier = Modifier
                            .padding(top = 8.dp)
                            .size(20.dp)
                            .clip(CircleShape)
                            .background(NeonCyan)
                    ) {
                        Text(
                            text = session.unreadCount.toString(),
                            color = DeepBlack,
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun mirageTextFieldColors() = OutlinedTextFieldDefaults.colors(
    focusedBorderColor = NeonCyan,
    unfocusedBorderColor = GlassBorder,
    cursorColor = NeonCyan,
    focusedTextColor = PureWhite,
    unfocusedTextColor = PureWhite,
    focusedLabelColor = NeonCyan,
    unfocusedLabelColor = SteelMuted
)

@Preview
@Composable
private fun DashboardContentPreview() {
    val sampleMessage = Message(
        id = "m1",
        sender = "NebulaTiger93",
        receiver = null,
        content = "Room keys rotated.",
        timestampMs = 0L,
        selfDestructDurationSec = 5
    )
    DashboardContent(
        currentUser = User("SilentVector482", ByteArray(32), isAdmin = true),
        sessions = listOf(
            ChatSession("room", "operations", true, sampleMessage, 3, 5),
            ChatSession("dm", "LunarNode231", false, null, 0, 10)
        ),
        status = ServerStatus("CONNECTED", "Node-Alpha", 24),
        presence = listOf(
            UserPresence("SilentVector482", true),
            UserPresence("LunarNode231", false)
        ),
        disguiseSettings = DisguiseSettings(),
        onOpenChat = {},
        onUpdateDisguise = { _, _ -> },
        onCreateForum = { _, _, _, _, _, _ -> },
        onWipe = {}
    )
}

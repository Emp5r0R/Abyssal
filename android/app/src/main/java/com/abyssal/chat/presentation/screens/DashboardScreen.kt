package com.abyssal.chat.presentation.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
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
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.ExtendedFloatingActionButton
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
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.abyssal.chat.domain.model.ChatSession
import com.abyssal.chat.domain.model.DisguiseSettings
import com.abyssal.chat.domain.model.Message
import com.abyssal.chat.domain.model.PendingMlsJoinSummary
import com.abyssal.chat.domain.model.PendingMlsLeaveSummary
import com.abyssal.chat.domain.model.ServerStatus
import com.abyssal.chat.domain.model.SessionSecurityState
import com.abyssal.chat.domain.model.User
import com.abyssal.chat.domain.model.UserPresence
import com.abyssal.chat.data.repository.isValidCamouflageConfiguration
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
    val sessionSecurity by viewModel.sessionSecurity.collectAsState()
    val roomCreationLimit by viewModel.roomCreationLimit.collectAsState()
    val pendingMlsJoins by viewModel.pendingMlsJoins.collectAsState()
    val pendingMlsLeaves by viewModel.pendingMlsLeaves.collectAsState()
    val showCamouflagePinPrompt = viewModel.showCamouflagePinPrompt.value

    DashboardContent(
        currentUser = currentUser,
        sessions = sessions,
        status = status,
        presence = presence,
        sessionSecurity = sessionSecurity,
        roomCreationLimit = roomCreationLimit,
        disguiseSettings = disguiseSet,
        onOpenChat = { viewModel.navigateTo(Screen.Chat(it)) },
        onOpenDirect = viewModel::openDirect,
        onUpdateDisguise = viewModel::updateDisguiseSettings,
        onCreateForum = viewModel::createForum,
        onDeleteForum = viewModel::deleteForum,
        onLeaveForum = viewModel::leaveRoom,
        pendingMlsJoins = pendingMlsJoins,
        pendingMlsLeaves = pendingMlsLeaves,
        onJoinRoom = viewModel::requestJoinRoom,
        onAcceptJoin = viewModel::acceptMlsJoin,
        onRejectJoin = viewModel::rejectMlsJoin,
        onAcceptLeave = viewModel::acceptMlsLeave,
        onRejectLeave = viewModel::rejectMlsLeave,
        onWipe = viewModel::executeClearAll,
        onLock = viewModel::lockApp,
        onEndSession = viewModel::endSession
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
    sessionSecurity: SessionSecurityState,
    roomCreationLimit: Int,
    disguiseSettings: DisguiseSettings,
    onOpenChat: (String) -> Unit,
    onOpenDirect: (String) -> Unit,
    onUpdateDisguise: (Boolean, String, String) -> Unit,
    onCreateForum: (String, Int, Int, Boolean, Boolean, Boolean, Boolean, Int, Int, Boolean, Int, Int, Boolean, Int, Int, Boolean) -> Unit,
    onDeleteForum: (String) -> Unit,
    onLeaveForum: (String) -> Unit,
    pendingMlsJoins: List<PendingMlsJoinSummary>,
    pendingMlsLeaves: List<PendingMlsLeaveSummary>,
    onJoinRoom: (String) -> Unit,
    onAcceptJoin: (String) -> Unit,
    onRejectJoin: (String) -> Unit,
    onAcceptLeave: (String) -> Unit,
    onRejectLeave: (String) -> Unit,
    onWipe: () -> Unit,
    onLock: () -> Unit,
    onEndSession: () -> Unit
) {
    var selectedTab by remember { mutableIntStateOf(0) }
    var showSettingsDialog by remember { mutableStateOf(false) }
    var showCreateForumDialog by remember { mutableStateOf(false) }
    var showWipeDialog by remember { mutableStateOf(false) }
    var showJoinDialog by remember { mutableStateOf(false) }
    var showPendingJoins by remember { mutableStateOf(false) }

    val filteredSessions = remember(sessions, selectedTab) {
        sessions.filter { it.isForum == (selectedTab == 0) }
    }
    val ownedRoomCount = remember(sessions, currentUser?.username) {
        sessions.count { it.isForum && it.ownerUsername == currentUser?.username }
    }
    val canCreateRoom = ownedRoomCount < roomCreationLimit

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
                sessionSecurity = sessionSecurity,
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
                    text = {
                        Text(
                            "Rooms ${sessions.count { it.isForum }}",
                            fontWeight = FontWeight.Bold
                        )
                    }
                )
                Tab(
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    text = {
                        Text(
                            "Direct ${sessions.count { !it.isForum }}",
                            fontWeight = FontWeight.Bold
                        )
                    }
                )
            }

            if (selectedTab == 0) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 9.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    SectionLabel("YOUR ROOMS", color = NeonGreen)
                    Text(
                        text = "$ownedRoomCount / $roomCreationLimit",
                        color = if (canCreateRoom) NeonGreen else SelfDestructAmber,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }

            PresenceStrip(
                users = presence,
                currentUsername = currentUser?.username,
                onOpenDirect = onOpenDirect,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 10.dp)
            )

            if (status.state == "CONNECTING" && sessions.isEmpty()) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f)
                        .padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    AbyssalMarkLoader(
                        size = AbyssalMarkLoaderSize.Large,
                        description = "Connecting to node"
                    )
                    Text(
                        text = "Connecting to node",
                        color = PureWhite,
                        fontSize = 17.sp,
                        fontWeight = FontWeight.SemiBold,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(top = 18.dp)
                    )
                    Text(
                        text = "Loading active rooms and conversations.",
                        color = SteelMuted,
                        fontSize = 13.sp,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(top = 8.dp)
                    )
                }
            } else if (filteredSessions.isEmpty()) {
                EmptyState(
                    title = if (selectedTab == 0) "No active rooms" else "No direct messages",
                    detail = if (selectedTab == 0) {
                        "Rooms created on this node appear here."
                    } else {
                        "Direct conversations appear here while active."
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f),
                    actionLabel = if (selectedTab == 0 && canCreateRoom) "Create room" else null,
                    onAction = if (selectedTab == 0 && canCreateRoom) {
                        { showCreateForumDialog = true }
                    } else {
                        null
                    }
                )
            } else {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f)
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                    contentPadding = PaddingValues(bottom = if (selectedTab == 0) 280.dp else 104.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    items(filteredSessions, key = { it.id }) { session ->
                        ChatSessionItem(
                            session = session,
                            canDelete = session.isForum,
                            onClick = { onOpenChat(session.id) },
                            onDelete = {
                                if (session.ownerUsername == currentUser?.username) onDeleteForum(session.id)
                                else onLeaveForum(session.id)
                            }
                        )
                    }
                }
            }
        }

        Column(
            modifier = Modifier
                .align(Alignment.BottomEnd)
                .navigationBarsPadding()
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
            horizontalAlignment = Alignment.End
        ) {
            if (selectedTab == 0 && (pendingMlsJoins.isNotEmpty() || pendingMlsLeaves.isNotEmpty())) {
                ExtendedFloatingActionButton(
                    onClick = { showPendingJoins = true },
                    containerColor = NeonGreen,
                    contentColor = DeepBlack,
                    shape = RoundedCornerShape(8.dp)
                ) { Text("Requests ${pendingMlsJoins.size + pendingMlsLeaves.size}", fontWeight = FontWeight.Bold) }
            }
            if (selectedTab == 0) {
                ExtendedFloatingActionButton(
                    onClick = { showJoinDialog = true },
                    containerColor = GlassBorder,
                    contentColor = PureWhite,
                    shape = RoundedCornerShape(8.dp)
                ) { Text("Join room", fontWeight = FontWeight.Bold) }
            }
            if (selectedTab == 0 && filteredSessions.isNotEmpty() && canCreateRoom) {
                ExtendedFloatingActionButton(
                    onClick = { showCreateForumDialog = true },
                    containerColor = NeonCyan,
                    contentColor = DeepBlack,
                    shape = RoundedCornerShape(8.dp),
                    icon = { PlusIcon(modifier = Modifier.size(20.dp), color = DeepBlack) },
                    text = { Text("New room $ownedRoomCount/$roomCreationLimit", fontWeight = FontWeight.Bold) }
                )
            }
            ExtendedFloatingActionButton(
                onClick = { showWipeDialog = true },
                containerColor = SelfDestructAmber,
                contentColor = PureWhite,
                shape = RoundedCornerShape(8.dp),
                icon = { HazardIcon(modifier = Modifier.size(20.dp), color = PureWhite) },
                text = { Text("Wipe node", fontWeight = FontWeight.Bold) }
            )
        }

        if (showSettingsDialog) {
            SettingsDialog(
                initialSettings = disguiseSettings,
                sessionSecurity = sessionSecurity,
                directoryCheckpoint = presence.firstOrNull()?.directoryDigest,
                onDismiss = { showSettingsDialog = false },
                onSave = { enabled, pin, duressPin ->
                    onUpdateDisguise(enabled, pin, duressPin)
                    showSettingsDialog = false
                },
                onLock = {
                    showSettingsDialog = false
                    onLock()
                },
                onEndSession = {
                    showSettingsDialog = false
                    onEndSession()
                }
            )
        }
        if (showJoinDialog) {
            JoinRoomDialog(
                onDismiss = { showJoinDialog = false },
                onJoin = { onJoinRoom(it); showJoinDialog = false }
            )
        }
        if (showPendingJoins) {
            PendingJoinDialog(
                joins = pendingMlsJoins,
                leaves = pendingMlsLeaves,
                onDismiss = { showPendingJoins = false },
                onAccept = onAcceptJoin,
                onReject = onRejectJoin,
                onAcceptLeave = onAcceptLeave,
                onRejectLeave = onRejectLeave
            )
        }

        if (showCreateForumDialog) {
            CreateForumDialog(
                onDismiss = { showCreateForumDialog = false },
                onCreate = { name, readExpiry, overallExpiry, textAbsolute, images, videos, files, imageRead, imageAbsolute, imageEnforce, videoRead, videoAbsolute, videoEnforce, fileRead, fileAbsolute, fileEnforce ->
                    onCreateForum(
                        name,
                        readExpiry,
                        overallExpiry,
                        textAbsolute,
                        images,
                        videos,
                        files,
                        imageRead,
                        imageAbsolute,
                        imageEnforce,
                        videoRead,
                        videoAbsolute,
                        videoEnforce,
                        fileRead,
                        fileAbsolute,
                        fileEnforce
                    )
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

@Composable
private fun DashboardHeader(
    currentUser: User?,
    status: ServerStatus,
    sessionSecurity: SessionSecurityState,
    onSettings: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 18.dp, vertical = 16.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            MirageLogo(modifier = Modifier.size(38.dp))
            Column(
                modifier = Modifier
                    .weight(1f)
                    .padding(start = 12.dp)
            ) {
                Text(
                    text = "Abyssal",
                    color = PureWhite,
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = currentUser?.username ?: "Anonymous",
                    color = NeonGreen,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
            MirageIconButton(
                contentDescription = "Open security settings",
                onClick = onSettings
            ) {
                SettingsIcon(modifier = Modifier.size(18.dp), color = SteelMuted)
            }
        }

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 14.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            StatusPill(
                label = if (status.state == "CONNECTED") {
                    "CONNECTED ${status.latencyMs}ms"
                } else {
                    status.state
                },
                color = if (status.state == "CONNECTED") NeonGreen else SelfDestructAmber,
                modifier = Modifier.weight(1f)
            )
            StatusPill(
                label = sessionStatusLabel(sessionSecurity),
                color = NeonCyan,
                modifier = Modifier.weight(1f)
            )
        }
    }
}

@Composable
private fun PresenceStrip(
    users: List<UserPresence>,
    currentUsername: String?,
    onOpenDirect: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    if (users.isEmpty()) {
        return
    }

    LazyRow(
        modifier = modifier,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        contentPadding = PaddingValues(end = 8.dp)
    ) {
        items(users.sortedBy { it.username }, key = { it.username }) { user ->
            val isCurrentUser = user.username.equals(currentUsername, ignoreCase = true)
            Row(
                modifier = Modifier
                    .clip(RoundedCornerShape(8.dp))
                    .background(Color.White.copy(alpha = 0.04f))
                    .border(BorderStroke(1.dp, GlassBorder), RoundedCornerShape(8.dp))
                    .then(
                        if (isCurrentUser) Modifier else Modifier.clickable { onOpenDirect(user.username) }
                    )
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
                    text = if (isCurrentUser) "you" else if (user.connected) "message" else "offline",
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
    sessionSecurity: SessionSecurityState,
    directoryCheckpoint: String?,
    onDismiss: () -> Unit,
    onSave: (Boolean, String, String) -> Unit,
    onLock: () -> Unit,
    onEndSession: () -> Unit
) {
    var disguiseEnabled by remember(initialSettings) { mutableStateOf(initialSettings.isDisguised) }
    var pinCode by remember(initialSettings) { mutableStateOf("") }
    var duressPin by remember(initialSettings) { mutableStateOf("") }
    val canSaveDisguise = isValidCamouflageConfiguration(
        enabled = disguiseEnabled,
        unlockPin = pinCode.trim(),
        duressPin = duressPin.trim()
    )

    MirageDialog(title = "Security", onDismiss = onDismiss) {
        SectionLabel(
            text = "ACTIVE SESSION",
            modifier = Modifier.fillMaxWidth(),
            color = NeonGreen
        )
        Text(
            text = if (sessionSecurity.retainedInBackground) {
                "Remembered in RAM · ${formatDuration(sessionSecurity.remainingSec)} idle time left"
            } else {
                "Foreground only · ${formatDuration(sessionSecurity.remainingSec)} idle time left"
            },
            color = PureWhite,
            fontSize = 13.sp,
            lineHeight = 18.sp,
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 8.dp)
        )
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 14.dp, bottom = 22.dp),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            if (initialSettings.isDisguised) {
                MirageSecondaryButton(
                    text = "Lock now",
                    onClick = onLock,
                    modifier = Modifier.weight(1f)
                )
            }
            MiragePrimaryButton(
                text = "End session",
                onClick = onEndSession,
                danger = true,
                modifier = Modifier.weight(1f)
            )
        }

        if (!directoryCheckpoint.isNullOrBlank()) {
            SectionLabel(
                text = "DIRECTORY CHECKPOINT",
                modifier = Modifier.fillMaxWidth(),
                color = NeonCyan
            )
            Text(
                text = directoryCheckpoint.chunked(4).joinToString(" "),
                color = PureWhite,
                fontSize = 11.sp,
                lineHeight = 17.sp,
                fontFamily = FontFamily.Monospace,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp, bottom = 22.dp)
            )
        }

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
                onValueChange = { pinCode = it.filter(::isCamouflageInput).take(32) },
                label = { Text("Unlock PIN or expression") },
                colors = mirageTextFieldColors(),
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii),
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
            OutlinedTextField(
                value = duressPin,
                onValueChange = { duressPin = it.filter(::isCamouflageInput).take(32) },
                label = { Text("Duress PIN") },
                colors = mirageTextFieldColors(),
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 14.dp)
            )
            Text(
                text = "Entering the duress sequence on the calculator cover wipes local memory and attempts a relay wipe.",
                color = SelfDestructAmber,
                fontSize = 12.sp,
                lineHeight = 17.sp,
                modifier = Modifier.padding(top = 8.dp)
            )
        }

        DialogButtons(
            cancel = "Cancel",
            confirm = "Save",
            onCancel = onDismiss,
            onConfirm = { onSave(disguiseEnabled, pinCode.trim(), duressPin.trim()) },
            confirmEnabled = canSaveDisguise
        )
    }
}

@Composable
private fun CamouflagePinSetupDialog(
    onSave: (String, String) -> Unit
) {
    var pinCode by remember { mutableStateOf("") }
    var duressPin by remember { mutableStateOf("") }
    val canSave = isValidCamouflageConfiguration(
        enabled = true,
        unlockPin = pinCode.trim(),
        duressPin = duressPin.trim()
    )

    MirageDialog(title = "Calculator PIN", onDismiss = {}) {
        Text(
            text = "Choose a calculator cover PIN for this device session. Remember it; Abyssal will not save it to disk.",
            color = SteelMuted,
            fontSize = 13.sp,
            lineHeight = 18.sp
        )
        OutlinedTextField(
            value = pinCode,
            onValueChange = { pinCode = it.filter(::isCamouflageInput).take(32) },
            label = { Text("Camouflage PIN") },
            colors = mirageTextFieldColors(),
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii),
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 16.dp)
        )
        OutlinedTextField(
            value = duressPin,
            onValueChange = { duressPin = it.filter(::isCamouflageInput).take(32) },
            label = { Text("Duress PIN") },
            colors = mirageTextFieldColors(),
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii),
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 12.dp)
        )
        Text(
            text = "Optional. This sequence performs a silent memory wipe from the calculator cover.",
            color = SelfDestructAmber,
            fontSize = 12.sp,
            lineHeight = 17.sp,
            modifier = Modifier.padding(top = 8.dp)
        )
        MiragePrimaryButton(
            text = "Remember and continue",
            onClick = { onSave(pinCode, duressPin) },
            enabled = canSave,
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 18.dp)
        )
    }
}

@Composable
private fun JoinRoomDialog(onDismiss: () -> Unit, onJoin: (String) -> Unit) {
    var roomId by remember { mutableStateOf("") }
    val valid = Regex("^[A-Za-z0-9_-]{1,128}$").matches(roomId)
    MirageDialog(title = "Join encrypted room", onDismiss = onDismiss) {
        OutlinedTextField(
            value = roomId,
            onValueChange = { roomId = it.trim().take(128) },
            label = { Text("Room ID") },
            colors = mirageTextFieldColors(),
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
        DialogButtons("Cancel", "Request access", onDismiss, { onJoin(roomId) }, valid)
    }
}

@Composable
private fun PendingJoinDialog(
    joins: List<PendingMlsJoinSummary>,
    leaves: List<PendingMlsLeaveSummary>,
    onDismiss: () -> Unit,
    onAccept: (String) -> Unit,
    onReject: (String) -> Unit,
    onAcceptLeave: (String) -> Unit,
    onRejectLeave: (String) -> Unit
) {
    MirageDialog(title = "Room join requests", onDismiss = onDismiss) {
        joins.forEach { join ->
            Column(modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
                Text(join.username, color = PureWhite, fontWeight = FontWeight.Bold)
                Text(join.roomId, color = SteelMuted, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
                DialogButtons("Reject", "Accept", { onReject(join.requestId) }, { onAccept(join.requestId) })
            }
        }
        leaves.forEach { leave ->
            Column(modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
                Text("${leave.username} wants to leave", color = PureWhite, fontWeight = FontWeight.Bold)
                Text(leave.roomId, color = SteelMuted, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
                DialogButtons("Reject", "Approve", { onRejectLeave(leave.requestId) }, { onAcceptLeave(leave.requestId) })
            }
        }
    }
}

@Composable
private fun CreateForumDialog(
    onDismiss: () -> Unit,
    onCreate: (String, Int, Int, Boolean, Boolean, Boolean, Boolean, Int, Int, Boolean, Int, Int, Boolean, Int, Int, Boolean) -> Unit
) {
    var forumName by remember { mutableStateOf("") }
    var readExpiryText by remember { mutableStateOf("5") }
    var overallExpiryText by remember { mutableStateOf("0") }
    var textAbsoluteEnforced by remember { mutableStateOf(false) }
    var imagesAllowed by remember { mutableStateOf(true) }
    var videosAllowed by remember { mutableStateOf(true) }
    var filesAllowed by remember { mutableStateOf(true) }
    var imageReadText by remember { mutableStateOf("5") }
    var imageAbsoluteText by remember { mutableStateOf("0") }
    var imageAbsoluteEnforced by remember { mutableStateOf(false) }
    var videoReadText by remember { mutableStateOf("5") }
    var videoAbsoluteText by remember { mutableStateOf("0") }
    var videoAbsoluteEnforced by remember { mutableStateOf(false) }
    var fileReadText by remember { mutableStateOf("5") }
    var fileAbsoluteText by remember { mutableStateOf("0") }
    var fileAbsoluteEnforced by remember { mutableStateOf(false) }

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
            text = "Read timer 0 means never. Absolute timers use seconds after send and cannot be overridden in the room.",
            color = SteelMuted,
            fontSize = 12.sp,
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 8.dp)
        )
        PayloadCheckbox("Enforce text absolute timer", textAbsoluteEnforced) { textAbsoluteEnforced = it }

        Column(modifier = Modifier.padding(top = 16.dp)) {
            SectionLabel("ALLOWED PAYLOADS")
            MediaRuleEditor(
                label = "Images and GIFs",
                allowed = imagesAllowed,
                onAllowedChange = { imagesAllowed = it },
                readText = imageReadText,
                onReadTextChange = { imageReadText = it },
                absoluteText = imageAbsoluteText,
                onAbsoluteTextChange = { imageAbsoluteText = it },
                absoluteEnforced = imageAbsoluteEnforced,
                onAbsoluteEnforcedChange = { imageAbsoluteEnforced = it }
            )
            MediaRuleEditor(
                label = "Video files",
                allowed = videosAllowed,
                onAllowedChange = { videosAllowed = it },
                readText = videoReadText,
                onReadTextChange = { videoReadText = it },
                absoluteText = videoAbsoluteText,
                onAbsoluteTextChange = { videoAbsoluteText = it },
                absoluteEnforced = videoAbsoluteEnforced,
                onAbsoluteEnforcedChange = { videoAbsoluteEnforced = it }
            )
            MediaRuleEditor(
                label = "Documents up to 200 MB",
                allowed = filesAllowed,
                onAllowedChange = { filesAllowed = it },
                readText = fileReadText,
                onReadTextChange = { fileReadText = it },
                absoluteText = fileAbsoluteText,
                onAbsoluteTextChange = { fileAbsoluteText = it },
                absoluteEnforced = fileAbsoluteEnforced,
                onAbsoluteEnforcedChange = { fileAbsoluteEnforced = it }
            )
        }

        DialogButtons(
            cancel = "Cancel",
            confirm = "Create",
            confirmEnabled = forumName.isNotBlank(),
            onCancel = onDismiss,
            onConfirm = {
                onCreate(
                    forumName.trim(),
                    readExpiryText.toIntOrNull()?.coerceIn(0, 86_400) ?: 5,
                    overallExpiryText.toIntOrNull()?.coerceAtLeast(0) ?: 0,
                    textAbsoluteEnforced,
                    imagesAllowed,
                    videosAllowed,
                    filesAllowed,
                    imageReadText.toIntOrNull()?.coerceIn(0, 86_400) ?: 5,
                    imageAbsoluteText.toIntOrNull()?.coerceAtLeast(0) ?: 0,
                    imageAbsoluteEnforced,
                    videoReadText.toIntOrNull()?.coerceIn(0, 86_400) ?: 5,
                    videoAbsoluteText.toIntOrNull()?.coerceAtLeast(0) ?: 0,
                    videoAbsoluteEnforced,
                    fileReadText.toIntOrNull()?.coerceIn(0, 86_400) ?: 5,
                    fileAbsoluteText.toIntOrNull()?.coerceAtLeast(0) ?: 0,
                    fileAbsoluteEnforced
                )
            }
        )
    }
}

@Composable
private fun MediaRuleEditor(
    label: String,
    allowed: Boolean,
    onAllowedChange: (Boolean) -> Unit,
    readText: String,
    onReadTextChange: (String) -> Unit,
    absoluteText: String,
    onAbsoluteTextChange: (String) -> Unit,
    absoluteEnforced: Boolean,
    onAbsoluteEnforcedChange: (Boolean) -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 8.dp)
            .clip(RoundedCornerShape(8.dp))
            .background(Color.White.copy(alpha = 0.035f))
            .border(BorderStroke(1.dp, GlassBorder), RoundedCornerShape(8.dp))
            .padding(10.dp)
    ) {
        PayloadCheckbox(label, allowed, onAllowedChange)
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            OutlinedTextField(
                value = readText,
                onValueChange = { onReadTextChange(it.filter(Char::isDigit).take(4)) },
                label = { Text("Read sec") },
                colors = mirageTextFieldColors(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                singleLine = true,
                enabled = allowed,
                modifier = Modifier.weight(1f)
            )
            OutlinedTextField(
                value = absoluteText,
                onValueChange = { onAbsoluteTextChange(it.filter(Char::isDigit).take(4)) },
                label = { Text("Abs sec") },
                colors = mirageTextFieldColors(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                singleLine = true,
                enabled = allowed,
                modifier = Modifier.weight(1f)
            )
        }
        PayloadCheckbox("Enforce absolute timer", absoluteEnforced && allowed) {
            onAbsoluteEnforcedChange(it && allowed)
        }
    }
}

@Composable
private fun ConfirmWipeDialog(
    onDismiss: () -> Unit,
    onConfirm: () -> Unit
) {
    MirageDialog(
        title = "Wipe relay memory",
        onDismiss = onDismiss,
        accent = SelfDestructAmber,
        icon = { HazardIcon(modifier = Modifier.size(34.dp), color = SelfDestructAmber) }
    ) {
        Text(
            text = "This clears relay accounts, codes, rooms, queued messages, and attachments, then asks connected clients to clear local memory. This cannot force deletion on modified clients.",
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
private fun ChatSessionItem(
    session: ChatSession,
    canDelete: Boolean,
    onClick: () -> Unit,
    onDelete: () -> Unit
) {
    val accent = if (session.isForum) NeonCyan else NeonGreen

    GlassSurface(
        modifier = Modifier.fillMaxWidth(),
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
                modifier = Modifier
                    .weight(1f)
                    .clickable(onClick = onClick),
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
                if (canDelete) {
                    MirageIconButton(
                        contentDescription = "Delete ${session.name}",
                        onClick = onDelete,
                        accent = SelfDestructAmber.copy(alpha = 0.45f),
                        size = 34.dp,
                        modifier = Modifier.padding(top = 8.dp)
                    ) {
                        DeleteIcon(modifier = Modifier.size(16.dp))
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

private fun sessionStatusLabel(state: SessionSecurityState): String {
    val mode = if (state.retainedInBackground) "RAM" else "FOREGROUND"
    return "$mode ${formatDuration(state.remainingSec)}"
}

private fun formatDuration(totalSeconds: Int): String {
    val safeSeconds = totalSeconds.coerceAtLeast(0)
    val minutes = safeSeconds / 60
    val seconds = safeSeconds % 60
    return "%d:%02d".format(minutes, seconds)
}

private fun isCamouflageInput(value: Char): Boolean = value in "0123456789.+-*/()"

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
        currentUser = User("SilentVector482", ByteArray(608)),
        sessions = listOf(
            ChatSession("room", "operations", true, sampleMessage, 3, 5, ownerUsername = "SilentVector482"),
            ChatSession("dm", "LunarNode231", false, null, 0, 10)
        ),
        status = ServerStatus("CONNECTED", "Node-Alpha", 24),
        presence = listOf(
            UserPresence("SilentVector482", true, ByteArray(608)),
            UserPresence("LunarNode231", false, ByteArray(608))
        ),
        sessionSecurity = SessionSecurityState(
            active = true,
            retainedInBackground = true,
            inactivityTimeoutSec = 900,
            remainingSec = 842
        ),
        roomCreationLimit = 5,
        disguiseSettings = DisguiseSettings(),
        onOpenChat = {},
        onOpenDirect = {},
        onUpdateDisguise = { _, _, _ -> },
        onCreateForum = { _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _ -> },
        onDeleteForum = {},
        onLeaveForum = {},
        pendingMlsJoins = emptyList(),
        pendingMlsLeaves = emptyList(),
        onJoinRoom = {},
        onAcceptJoin = {},
        onRejectJoin = {},
        onAcceptLeave = {},
        onRejectLeave = {},
        onWipe = {},
        onLock = {},
        onEndSession = {}
    )
}

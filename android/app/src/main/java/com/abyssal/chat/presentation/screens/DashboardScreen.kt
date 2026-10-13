package com.abyssal.chat.presentation.screens

import android.os.Build
import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.abyssal.chat.domain.model.ChatSession
import com.abyssal.chat.domain.model.DisguiseSettings
import com.abyssal.chat.domain.model.Message
import com.abyssal.chat.domain.model.MessageAttentionPolicy
import com.abyssal.chat.domain.model.MlsPublicRoomSummary
import com.abyssal.chat.domain.model.MlsRoomVisibility
import com.abyssal.chat.domain.model.PendingMlsJoinSummary
import com.abyssal.chat.domain.model.PendingMlsLeaveSummary
import com.abyssal.chat.domain.model.ServerStatus
import com.abyssal.chat.domain.model.SessionSecurityState
import com.abyssal.chat.domain.model.User
import com.abyssal.chat.domain.model.UserPresence
import com.abyssal.chat.domain.model.conversationEntries
import com.abyssal.chat.domain.model.filterConversations
import com.abyssal.chat.domain.model.peerLabel
import com.abyssal.chat.domain.model.roomLabel
import com.abyssal.chat.domain.model.shortAccountId
import com.abyssal.chat.domain.model.shortRoomId
import com.abyssal.chat.presentation.viewmodel.ChatViewModel
import com.abyssal.chat.presentation.viewmodel.Screen
import com.abyssal.chat.theme.Accent
import com.abyssal.chat.theme.Danger
import com.abyssal.chat.theme.Outline
import com.abyssal.chat.theme.Success
import com.abyssal.chat.theme.SurfaceRaised
import com.abyssal.chat.theme.TextMuted
import com.abyssal.chat.theme.TextPrimary
import com.abyssal.chat.theme.TextSubtle
import com.abyssal.chat.theme.Warning

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
    val publicMlsRooms by viewModel.publicMlsRooms.collectAsState()
    val roomActionNotice by viewModel.roomActionNotice.collectAsState()
    val displayNames by viewModel.knownDisplayNames.collectAsState()
    val showCamouflagePinPrompt = viewModel.showCamouflagePinPrompt.value
    val preferences by viewModel.workspacePreferences.collectAsState()
    val notificationsAllowed by viewModel.notificationsAllowed.collectAsState()

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
        publicMlsRooms = publicMlsRooms,
        onJoinRoom = viewModel::requestJoinRoom,
        onAcceptJoin = viewModel::acceptMlsJoin,
        onRejectJoin = viewModel::rejectMlsJoin,
        onAcceptLeave = viewModel::acceptMlsLeave,
        onRejectLeave = viewModel::rejectMlsLeave,
        onWipe = viewModel::executeClearAll,
        onLock = viewModel::lockApp,
        onEndSession = viewModel::endSession,
        roomActionNotice = roomActionNotice,
        onDismissRoomActionNotice = viewModel::dismissRoomActionNotice,
        displayNames = displayNames,
        preferenceControls = WorkspacePreferenceControls(
            preferences = preferences,
            notificationsAllowed = notificationsAllowed,
            onBlurChange = viewModel::setBlurEnabled,
            onBackgroundActionChange = viewModel::setBackgroundAction,
            onNotificationLevelChange = viewModel::setNotificationLevel,
            onNotificationPermissionResult = viewModel::refreshNotificationPermission,
            onExternalSystemUiStart = viewModel::beginExternalSystemUi,
            onExternalSystemUiEnd = viewModel::endExternalSystemUi
        )
    )

    if (showCamouflagePinPrompt) {
        CamouflagePinSetupDialog(onSave = viewModel::completeCamouflagePinSetup)
    }
}

/** A room waiting for a delete or leave confirmation. */
private data class RoomRemoval(val session: ChatSession, val isOwner: Boolean)

@Composable
internal fun DashboardContent(
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
    onCreateForum: (String, Int, Int, Boolean, Boolean, Boolean, Boolean, Int, Int, Boolean, Int, Int, Boolean, Int, Int, Boolean, MlsRoomVisibility) -> Unit,
    onDeleteForum: (String) -> Unit,
    onLeaveForum: (String) -> Unit,
    pendingMlsJoins: List<PendingMlsJoinSummary>,
    pendingMlsLeaves: List<PendingMlsLeaveSummary>,
    publicMlsRooms: List<MlsPublicRoomSummary>,
    onJoinRoom: (String) -> Unit,
    onAcceptJoin: (String) -> Unit,
    onRejectJoin: (String) -> Unit,
    onAcceptLeave: (String) -> Unit,
    onRejectLeave: (String) -> Unit,
    onWipe: () -> Unit,
    onLock: () -> Unit,
    onEndSession: () -> Unit,
    roomActionNotice: String? = null,
    onDismissRoomActionNotice: () -> Unit = {},
    displayNames: Map<String, String> = emptyMap(),
    preferenceControls: WorkspacePreferenceControls = WorkspacePreferenceControls()
) {
    var selectedTab by rememberSaveable { mutableIntStateOf(0) }
    var query by rememberSaveable { mutableStateOf("") }
    var showSettings by remember { mutableStateOf(false) }
    var showCreateRoom by remember { mutableStateOf(false) }
    var showJoinRoom by remember { mutableStateOf(false) }
    var pendingRemoval by remember { mutableStateOf<RoomRemoval?>(null) }

    val username = currentUser?.username
    val rooms = remember(sessions) { sessions.filter { it.isForum } }
    val directs = remember(sessions) { sessions.filterNot { it.isForum } }
    val matchingIds = remember(sessions, displayNames, query) {
        filterConversations(conversationEntries(sessions, displayNames), query).mapTo(mutableSetOf()) { it.id }
    }
    val ownedRoomCount = rooms.count { it.ownerUsername == username }
    val canCreateRoom = ownedRoomCount < roomCreationLimit
    val joinedRoomIds = remember(rooms) { rooms.mapTo(mutableSetOf()) { it.id } }
    val listedRooms = remember(publicMlsRooms, joinedRoomIds, query) {
        publicMlsRooms.filter { it.roomId !in joinedRoomIds && it.roomId.contains(query.trim(), ignoreCase = true) }.take(32)
    }
    val directPeers = remember(presence, username, directs) {
        directPeersForDirectory(presence, username, directs.mapTo(mutableSetOf()) { it.name })
    }
    val visiblePeers = remember(directPeers, displayNames, query) {
        val needle = query.trim()
        if (needle.isEmpty()) {
            directPeers
        } else {
            directPeers.filter {
                it.username.contains(needle, ignoreCase = true) ||
                    peerLabel(it.username, displayNames).contains(needle, ignoreCase = true)
            }
        }
    }
    val onlineCount = presence.count { it.connected && !it.username.equals(username, ignoreCase = true) }
    val connecting = status.state == "CONNECTING" && sessions.isEmpty()

    MirageBackground {
        Column(modifier = Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding().imePadding()) {
            DashboardTopBar(
                status = status,
                canLock = disguiseSettings.isDisguised,
                onLock = onLock,
                onSettings = { showSettings = true }
            )
            LazyColumn(
                modifier = Modifier.fillMaxWidth().weight(1f),
                contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 4.dp, bottom = 24.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                item(key = "greeting") { Greeting(currentUser, onlineCount, sessionSecurity) }
                ConnectionStatusCopy.rejectionNotice(status.state)?.let { notice ->
                    item(key = "rejection") { NoticeBanner(notice, Tone.Danger, icon = AppIcons.Alert) }
                }
                roomActionNotice?.let { notice ->
                    item(key = "notice") { NoticeBanner(notice, Tone.Accent, onDismiss = onDismissRoomActionNotice) }
                }
                item(key = "search") { SearchField(query = query, onQueryChange = { query = it.take(64) }) }
                item(key = "tabs") {
                    SegmentedControl(
                        options = listOf(
                            "Rooms" + if (rooms.isEmpty()) "" else " · ${rooms.size}",
                            "Direct" + if (directs.isEmpty()) "" else " · ${directs.size}"
                        ),
                        selectedIndex = selectedTab,
                        onSelect = { selectedTab = it },
                        modifier = Modifier.fillMaxWidth()
                    )
                }
                if (pendingMlsJoins.isNotEmpty() || pendingMlsLeaves.isNotEmpty()) {
                    item(key = "attention") {
                        AttentionCard(
                            joins = pendingMlsJoins,
                            leaves = pendingMlsLeaves,
                            rooms = rooms,
                            displayNames = displayNames,
                            onAcceptJoin = onAcceptJoin,
                            onRejectJoin = onRejectJoin,
                            onAcceptLeave = onAcceptLeave,
                            onRejectLeave = onRejectLeave
                        )
                    }
                }
                if (connecting) {
                    item(key = "connecting") { ConnectingState() }
                } else if (selectedTab == 0) {
                    item(key = "rooms") {
                        RoomsCard(
                            rooms = rooms.filter { it.id in matchingIds },
                            hasRooms = rooms.isNotEmpty(),
                            username = username,
                            displayNames = displayNames,
                            ownedRoomCount = ownedRoomCount,
                            roomCreationLimit = roomCreationLimit,
                            canCreateRoom = canCreateRoom,
                            onOpen = onOpenChat,
                            onCreate = { showCreateRoom = true },
                            onJoinById = { showJoinRoom = true },
                            onRemove = { session -> pendingRemoval = RoomRemoval(session, session.ownerUsername == username) }
                        )
                    }
                    if (listedRooms.isNotEmpty()) {
                        item(key = "public") { PublicRoomsCard(listedRooms, onJoinRoom) }
                    }
                } else {
                    item(key = "directs") {
                        DirectsCard(
                            directs = directs.filter { it.id in matchingIds },
                            username = username,
                            presence = presence,
                            hasDirects = directs.isNotEmpty(),
                            peerCount = directPeers.size,
                            displayNames = displayNames,
                            onOpen = onOpenChat
                        )
                    }
                    item(key = "people") { PeopleCard(visiblePeers, onlineCount, displayNames, onOpenDirect) }
                }
            }
        }

        if (showSettings) {
            SettingsScreen(
                currentUser = currentUser,
                disguiseSettings = disguiseSettings,
                sessionSecurity = sessionSecurity,
                directoryCheckpoint = presence.firstOrNull()?.directoryDigest,
                preferenceControls = preferenceControls,
                onDismiss = { showSettings = false },
                onSaveDisguise = onUpdateDisguise,
                onLock = { showSettings = false; onLock() },
                onEndSession = { showSettings = false; onEndSession() },
                onWipe = { showSettings = false; onWipe() }
            )
        }
        if (showJoinRoom) {
            JoinRoomDialog(onDismiss = { showJoinRoom = false }, onJoin = { onJoinRoom(it); showJoinRoom = false })
        }
        if (showCreateRoom) {
            CreateForumDialog(
                onDismiss = { showCreateRoom = false },
                onCreate = { name, readExpiry, overallExpiry, textAbsolute, images, videos, files, imageRead, imageAbsolute, imageEnforce, videoRead, videoAbsolute, videoEnforce, fileRead, fileAbsolute, fileEnforce, visibility ->
                    onCreateForum(
                        name, readExpiry, overallExpiry, textAbsolute, images, videos, files,
                        imageRead, imageAbsolute, imageEnforce, videoRead, videoAbsolute, videoEnforce,
                        fileRead, fileAbsolute, fileEnforce, visibility
                    )
                    showCreateRoom = false
                }
            )
        }
        pendingRemoval?.let { removal ->
            val label = roomLabel(removal.session.id, removal.session.name)
            ConfirmDialog(
                title = if (removal.isOwner) "Delete $label?" else "Leave $label?",
                message = if (removal.isOwner) {
                    "The room is deleted for everyone and its messages are removed from the relay. This cannot be undone."
                } else {
                    "You stop receiving this room's messages. To come back, ask to join again."
                },
                confirmLabel = if (removal.isOwner) "Delete room" else "Leave room",
                onConfirm = {
                    pendingRemoval = null
                    if (removal.isOwner) onDeleteForum(removal.session.id) else onLeaveForum(removal.session.id)
                },
                onDismiss = { pendingRemoval = null }
            )
        }
    }
}

@Composable
private fun DashboardTopBar(status: ServerStatus, canLock: Boolean, onLock: () -> Unit, onSettings: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(start = 16.dp, end = 6.dp, top = 6.dp, bottom = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        MirageLogo(modifier = Modifier.size(28.dp))
        Text(
            "Abyssal",
            color = TextPrimary,
            fontSize = 20.sp,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.padding(start = 10.dp).weight(1f)
        )
        StatusPill(
            label = ConnectionStatusCopy.statusLabel(status.state),
            color = when {
                ConnectionStatusCopy.isLive(status.state) -> Success
                status.state == "CONNECTING" -> Warning
                else -> Danger
            }
        )
        if (canLock) IconAction(AppIcons.Lock, "Lock now", onLock)
        IconAction(AppIcons.Settings, "Open settings", onSettings)
    }
}

@Composable
private fun Greeting(currentUser: User?, onlineCount: Int, sessionSecurity: SessionSecurityState) {
    Column(modifier = Modifier.padding(top = 4.dp, bottom = 2.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Signed in as ", color = TextMuted, fontSize = 14.sp)
            PrivacyBlurred(modifier = Modifier.weight(1f, fill = false)) {
                Text(
                    currentUser?.displayName ?: currentUser?.username?.let(::shortAccountId) ?: "—",
                    color = TextPrimary,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
        Text(
            text = "${if (onlineCount == 1) "1 person" else "$onlineCount people"} online · " +
                "idle sign-out in ${formatDuration(sessionSecurity.remainingSec)}",
            color = TextSubtle,
            fontSize = 13.sp,
            modifier = Modifier.padding(top = 2.dp)
        )
    }
}

@Composable
private fun SearchField(query: String, onQueryChange: (String) -> Unit) {
    val focusManager = LocalFocusManager.current
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .height(46.dp)
            .clip(RoundedCornerShape(100.dp))
            .background(SurfaceRaised)
            .padding(start = 14.dp, end = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        AppIcon(AppIcons.Search, tint = TextSubtle, size = 18.dp)
        Box(modifier = Modifier.weight(1f).padding(horizontal = 10.dp), contentAlignment = Alignment.CenterStart) {
            if (query.isEmpty()) Text("Search conversations and people", color = TextSubtle, fontSize = 14.sp, maxLines = 1)
            BasicTextField(
                value = query,
                onValueChange = onQueryChange,
                singleLine = true,
                textStyle = TextStyle(color = TextPrimary, fontSize = 15.sp),
                cursorBrush = SolidColor(Accent),
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                keyboardActions = KeyboardActions(onSearch = { focusManager.clearFocus() }),
                modifier = Modifier.fillMaxWidth().semantics { contentDescription = "Search conversations" }
            )
        }
        if (query.isNotEmpty()) {
            IconAction(AppIcons.Close, "Clear search", { onQueryChange("") }, size = 36.dp, iconSize = 16.dp)
        }
    }
}

private data class PendingRequest(val requestId: String, val username: String, val detail: String, val isJoin: Boolean)

@Composable
private fun AttentionCard(
    joins: List<PendingMlsJoinSummary>,
    leaves: List<PendingMlsLeaveSummary>,
    rooms: List<ChatSession>,
    displayNames: Map<String, String>,
    onAcceptJoin: (String) -> Unit,
    onRejectJoin: (String) -> Unit,
    onAcceptLeave: (String) -> Unit,
    onRejectLeave: (String) -> Unit
) {
    fun roomName(roomId: String) =
        rooms.firstOrNull { it.id == roomId }?.let { roomLabel(it.id, it.name) } ?: "Room ${shortRoomId(roomId)}"
    val requests = joins.map { PendingRequest(it.requestId, it.username, "wants to join ${roomName(it.roomId)}", true) } +
        leaves.map { PendingRequest(it.requestId, it.username, "wants to leave ${roomName(it.roomId)}", false) }
    SectionCard(
        title = "Needs your attention",
        icon = AppIcons.Bell,
        titleColor = Warning,
        borderColor = Warning.copy(alpha = 0.4f),
        trailing = "${requests.size}"
    ) {
        requests.forEachIndexed { index, request ->
            if (index > 0) RowDivider()
            val label = peerLabel(request.username, displayNames)
            Column(Modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Avatar(label, size = 36.dp, tone = Tone.Warning)
                    Column(Modifier.weight(1f).padding(start = 12.dp)) {
                        PrivacyBlurred(revealOnTap = false) { RowTitle(label) }
                        RowSubtitle(request.detail)
                    }
                }
                Row(
                    modifier = Modifier.fillMaxWidth().padding(top = 10.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End)
                ) {
                    MirageSecondaryButton(
                        text = "Decline",
                        onClick = { if (request.isJoin) onRejectJoin(request.requestId) else onRejectLeave(request.requestId) },
                        compact = true
                    )
                    MiragePrimaryButton(
                        text = if (request.isJoin) "Accept" else "Approve",
                        onClick = { if (request.isJoin) onAcceptJoin(request.requestId) else onAcceptLeave(request.requestId) },
                        compact = true
                    )
                }
            }
        }
    }
}

@Composable
private fun ConnectingState() {
    Column(
        modifier = Modifier.fillMaxWidth().padding(vertical = 48.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        AbyssalMarkLoader(size = AbyssalMarkLoaderSize.Large, description = "Connecting to relay")
        Text(
            "Connecting to the relay",
            color = TextPrimary,
            fontSize = 16.sp,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.padding(top = 18.dp)
        )
        Text("Loading your rooms and conversations.", color = TextMuted, fontSize = 14.sp, modifier = Modifier.padding(top = 4.dp))
    }
}

@Composable
private fun RoomsCard(
    rooms: List<ChatSession>,
    hasRooms: Boolean,
    username: String?,
    displayNames: Map<String, String>,
    ownedRoomCount: Int,
    roomCreationLimit: Int,
    canCreateRoom: Boolean,
    onOpen: (String) -> Unit,
    onCreate: () -> Unit,
    onJoinById: () -> Unit,
    onRemove: (ChatSession) -> Unit
) {
    SectionCard(title = "Your rooms", icon = AppIcons.Hash, trailing = "$ownedRoomCount of $roomCreationLimit owned") {
        when {
            !hasRooms -> EmptyState(
                title = "No rooms yet",
                detail = "Create a room, join a public one, or ask an owner for a room ID.",
                modifier = Modifier.fillMaxWidth()
            )
            rooms.isEmpty() -> Text("No rooms match your search.", color = TextMuted, fontSize = 14.sp, modifier = Modifier.padding(16.dp))
            else -> rooms.forEachIndexed { index, room ->
                if (index > 0) RowDivider(inset = 68.dp)
                RoomRow(room, username, isOwner = room.ownerUsername == username, displayNames, onOpen, onRemove)
            }
        }
        HorizontalDivider(color = Outline)
        Row(modifier = Modifier.fillMaxWidth().padding(12.dp), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            MiragePrimaryButton(
                text = if (canCreateRoom) "New room" else "Limit reached",
                onClick = onCreate,
                enabled = canCreateRoom,
                icon = AppIcons.Plus,
                modifier = Modifier.weight(1f)
            )
            MirageSecondaryButton("Join by ID", onJoinById, icon = AppIcons.LogIn, modifier = Modifier.weight(1f))
        }
    }
}

@Composable
private fun RoomRow(
    room: ChatSession,
    username: String?,
    isOwner: Boolean,
    displayNames: Map<String, String>,
    onOpen: (String) -> Unit,
    onRemove: (ChatSession) -> Unit
) {
    val isPublic = room.roomVisibility == MlsRoomVisibility.PUBLIC
    val owner = when {
        isOwner -> "You own this"
        room.ownerUsername != null -> "Owner ${peerLabel(room.ownerUsername, displayNames)}"
        else -> null
    }
    ListRow(
        onClick = { onOpen(room.id) },
        onClickLabel = "Open room",
        leading = {
            Avatar(
                "",
                tone = if (isPublic) Tone.Success else Tone.Accent,
                icon = if (isPublic) AppIcons.Globe else AppIcons.Hash
            )
        },
        title = { PrivacyBlurred(revealOnTap = false) { RowTitle(roomLabel(room.id, room.name)) } },
        subtitle = {
            room.lastMessage?.let { conversationPreview(it, username) }?.let { preview ->
                PrivacyBlurred(revealOnTap = false) {
                    RowSubtitle(preview, color = if (room.unreadCount > 0) TextPrimary else TextMuted)
                }
            }
            RowSubtitle(
                listOfNotNull(owner, if (isPublic) "Public" else "Private").joinToString(" · "),
                color = TextSubtle
            )
            if (room.lastMessage == null) room.roomPolicySummary()?.let { RowSubtitle(it, color = TextSubtle) }
        },
        trailing = {
            if (room.unreadCount > 0) CountBadge(room.unreadCount)
            RoomMenu(room, isOwner, onRemove)
        }
    )
}

@Composable
private fun RoomMenu(room: ChatSession, isOwner: Boolean, onRemove: (ChatSession) -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    val label = roomLabel(room.id, room.name)
    Box {
        IconAction(AppIcons.MoreVertical, "Options for $label", { expanded = true }, size = 40.dp, iconSize = 18.dp)
        DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }, modifier = Modifier.background(SurfaceRaised)) {
            DropdownMenuItem(
                text = { Text("Copy room ID", color = TextPrimary) },
                leadingIcon = { AppIcon(AppIcons.Copy, size = 18.dp) },
                onClick = {
                    expanded = false
                    clipboard.setText(AnnotatedString(room.id))
                    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
                        Toast.makeText(context, "Room ID copied", Toast.LENGTH_SHORT).show()
                    }
                }
            )
            DropdownMenuItem(
                text = { Text(if (isOwner) "Delete room" else "Leave room", color = Danger) },
                leadingIcon = { AppIcon(if (isOwner) AppIcons.Trash else AppIcons.LogOut, tint = Danger, size = 18.dp) },
                modifier = Modifier.semantics { contentDescription = roomActionContentDescription(isOwner, label) },
                onClick = { expanded = false; onRemove(room) }
            )
        }
    }
}

@Composable
private fun PublicRoomsCard(rooms: List<MlsPublicRoomSummary>, onJoin: (String) -> Unit) {
    SectionCard(title = "Public rooms", icon = AppIcons.Globe, trailing = "${rooms.size} listed") {
        rooms.forEachIndexed { index, room ->
            if (index > 0) RowDivider(inset = 68.dp)
            ListRow(
                leading = { Avatar("", tone = Tone.Success, icon = AppIcons.Users) },
                title = { RowTitle("Room ${shortRoomId(room.roomId)}") },
                subtitle = { RowSubtitle("Owner ${shortAccountId(room.ownerUsername)}", color = TextSubtle) },
                trailing = {
                    MirageSecondaryButton(
                        text = "Join",
                        onClick = { onJoin(room.roomId) },
                        compact = true,
                        modifier = Modifier.semantics { contentDescription = "Join public room ${room.roomId}" }
                    )
                }
            )
        }
    }
}

@Composable
private fun DirectsCard(
    directs: List<ChatSession>,
    username: String?,
    presence: List<UserPresence>,
    hasDirects: Boolean,
    peerCount: Int,
    displayNames: Map<String, String>,
    onOpen: (String) -> Unit
) {
    SectionCard(title = "Direct messages", icon = AppIcons.Message, trailing = if (hasDirects) "${directs.size}" else null) {
        when {
            !hasDirects -> EmptyState(
                title = directConversationEmptyStateTitle(),
                detail = directConversationEmptyStateDetail(peerCount),
                modifier = Modifier.fillMaxWidth()
            )
            directs.isEmpty() -> Text(
                "No conversations match your search.",
                color = TextMuted,
                fontSize = 14.sp,
                modifier = Modifier.padding(16.dp)
            )
            else -> directs.forEachIndexed { index, direct ->
                if (index > 0) RowDivider(inset = 68.dp)
                val label = peerLabel(direct.name, displayNames)
                ListRow(
                    onClick = { onOpen(direct.id) },
                    onClickLabel = "Open conversation",
                    leading = { Avatar(label) },
                    title = {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            PrivacyBlurred(revealOnTap = false, modifier = Modifier.weight(1f, fill = false)) { RowTitle(label) }
                            if (label != shortAccountId(direct.name)) {
                                Text(
                                    shortAccountId(direct.name),
                                    color = TextSubtle,
                                    fontSize = 12.sp,
                                    fontFamily = FontFamily.Monospace,
                                    maxLines = 1,
                                    modifier = Modifier.padding(start = 6.dp)
                                )
                            }
                        }
                    },
                    subtitle = {
                        // The dashboard never sees message content; show reachability instead.
                        val preview = direct.lastMessage?.let { conversationPreview(it, username) }
                        val online = presence.any { it.connected && it.username.equals(direct.name, ignoreCase = true) }
                        if (preview != null) {
                            PrivacyBlurred(revealOnTap = false) {
                                RowSubtitle(preview, color = if (direct.unreadCount > 0) TextPrimary else TextMuted)
                            }
                        } else {
                            RowSubtitle(
                                when {
                                    direct.unreadCount > 0 -> "New messages"
                                    online -> "Online"
                                    else -> "Offline"
                                },
                                color = when {
                                    direct.unreadCount > 0 -> Accent
                                    online -> Success
                                    else -> TextSubtle
                                }
                            )
                        }
                    },
                    trailing = { if (direct.unreadCount > 0) CountBadge(direct.unreadCount) }
                )
            }
        }
    }
}

@Composable
private fun PeopleCard(
    people: List<UserPresence>,
    onlineCount: Int,
    displayNames: Map<String, String>,
    onOpenDirect: (String) -> Unit
) {
    SectionCard(title = "People", icon = AppIcons.Users, trailing = "$onlineCount online") {
        if (people.isEmpty()) {
            Text(peopleDirectoryEmptyStateLabel(), color = TextMuted, fontSize = 14.sp, modifier = Modifier.padding(16.dp))
        }
        people.forEachIndexed { index, user ->
            if (index > 0) RowDivider(inset = 68.dp)
            val label = peerLabel(user.username, displayNames)
            ListRow(
                modifier = Modifier.semantics(mergeDescendants = true) {
                    contentDescription = peopleDirectoryEntryLabel(user.username, user.connected)
                },
                onClick = { onOpenDirect(user.username) },
                leading = { Avatar(label, online = user.connected) },
                title = { PrivacyBlurred(revealOnTap = false) { RowTitle(label) } },
                subtitle = {
                    RowSubtitle(
                        presenceStatusLabel(isCurrentUser = false, connected = user.connected) +
                            if (label != shortAccountId(user.username)) " · ${shortAccountId(user.username)}" else "",
                        color = if (user.connected) Success else TextSubtle
                    )
                },
                trailing = { AppIcon(AppIcons.MessagePlus, tint = Accent, size = 20.dp) }
            )
        }
    }
}

/** One-line preview of a conversation's latest message. */
internal fun conversationPreview(message: Message, currentUsername: String? = null): String {
    val from = if (message.sender == "You") "You: " else ""
    val body = when {
        !message.isMedia -> mentionsAsYou(message.content, currentUsername)
        message.reactionShortcode != null -> "GIF ${message.reactionShortcode}"
        message.oneTimeView -> "One-time media"
        else -> when (message.mediaType) {
            "IMAGE" -> "Photo"
            "VIDEO" -> "Video"
            else -> "File"
        } + (message.attachmentName?.let { " · $it" } ?: "")
    }
    return from + body.lineSequence().firstOrNull().orEmpty()
}

/** Replaces mentions of the reader with "@you", as message bubbles show them. */
internal fun mentionsAsYou(content: String, currentUsername: String?): String {
    val ranges = MessageAttentionPolicy.mentionRanges(content, currentUsername)
    if (ranges.isEmpty()) return content
    val out = StringBuilder()
    var cursor = 0
    ranges.forEach { range ->
        out.append(content, cursor, range.first).append("@you")
        cursor = range.last + 1
    }
    return out.append(content, cursor, content.length).toString()
}

internal fun roomActionContentDescription(isOwner: Boolean, roomName: String): String {
    val action = if (isOwner) "Delete room" else "Leave room"
    return "$action $roomName"
}

internal fun presenceStatusLabel(isCurrentUser: Boolean, connected: Boolean): String {
    val status = if (connected) "Online" else "Offline"
    return if (isCurrentUser) "You · $status" else status
}

@Preview
@Composable
private fun DashboardContentPreview() {
    DashboardContent(
        currentUser = User("SilentVector482", ByteArray(0)),
        sessions = listOf(ChatSession("room", "operations", true, null, 3, 5, ownerUsername = "SilentVector482")),
        status = ServerStatus("CONNECTED", "Node-Alpha", 24),
        presence = listOf(UserPresence("LunarNode231", true, ByteArray(0))),
        sessionSecurity = SessionSecurityState(true, true, 900, 842),
        roomCreationLimit = 5,
        disguiseSettings = DisguiseSettings(),
        onOpenChat = {},
        onOpenDirect = {},
        onUpdateDisguise = { _, _, _ -> },
        onCreateForum = { _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _ -> },
        onDeleteForum = {},
        onLeaveForum = {},
        pendingMlsJoins = emptyList(),
        pendingMlsLeaves = emptyList(),
        publicMlsRooms = emptyList(),
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

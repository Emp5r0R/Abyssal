package com.abyssal.chat.presentation.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.TextButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.abyssal.chat.presentation.viewmodel.ChatViewModel
import com.abyssal.chat.theme.DeepBlack
import com.abyssal.chat.theme.GlassBorder
import com.abyssal.chat.theme.NeonCyan
import com.abyssal.chat.theme.NeonGreen
import com.abyssal.chat.theme.PureWhite
import com.abyssal.chat.theme.SelfDestructAmber
import com.abyssal.chat.theme.SteelMuted
import java.nio.charset.StandardCharsets
import com.abyssal.chat.BuildConfig
import com.abyssal.chat.data.qr.InviteQrDecoder
import com.abyssal.chat.data.qr.LocalQrImageReader
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver

@Composable
fun EntranceScreen(viewModel: ChatViewModel) {
    EntranceContent(
        isVerifying = viewModel.isVerifyingInvite.value,
        error = viewModel.inviteError.value,
        onInputChanged = viewModel::clearAccountError,
        onSubmit = viewModel::submitAccount
    )
}

@Composable
private fun EntranceContent(
    isVerifying: Boolean,
    error: String?,
    onInputChanged: () -> Unit,
    onSubmit: (String, ByteArray, Boolean) -> Unit
) {
    var invite by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var passwordVisible by remember { mutableStateOf(false) }
    var rememberSession by remember { mutableStateOf(true) }
    var scanning by remember { mutableStateOf(false) }
    var readingImage by remember { mutableStateOf(false) }
    var imageError by remember { mutableStateOf(false) }
    val context = LocalContext.current
    val lifecycle = LocalLifecycleOwner.current
    val scope = rememberCoroutineScope()
    var imageJob by remember { mutableStateOf<Job?>(null) }
    DisposableEffect(lifecycle) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP) imageJob?.cancel()
        }
        lifecycle.lifecycle.addObserver(observer)
        onDispose { lifecycle.lifecycle.removeObserver(observer); imageJob?.cancel() }
    }
    val imagePicker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null && !readingImage && !isVerifying) {
            readingImage = true
            imageError = false
            imageJob = scope.launch {
                try {
                    val value = LocalQrImageReader.read(context.contentResolver, uri)
                    require(InviteQrDecoder.isVerifiedInvite(value, BuildConfig.DEBUG))
                    invite = value
                    onInputChanged()
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
    val passwordFocusRequester = remember { FocusRequester() }
    val focusManager = LocalFocusManager.current
    val clipboard = LocalClipboardManager.current
    val canSubmit = invite.isNotBlank() &&
        password.length in MIN_PASSWORD_CHARS..MAX_PASSWORD_CHARS &&
        !isVerifying && !readingImage && !scanning

    fun submit() {
        if (!canSubmit) return
        focusManager.clearFocus()
        val passwordBytes = password.toByteArray(StandardCharsets.UTF_8)
        password = ""
        passwordVisible = false
        onSubmit(invite, passwordBytes, rememberSession)
    }

    if (scanning) InviteQrScanner(
        onScanned = { invite = it; scanning = false; onInputChanged() },
        onDismiss = { scanning = false }
    )

    MirageBackground {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .navigationBarsPadding()
                .imePadding()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .widthIn(max = 500.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(14.dp)
                ) {
                    MirageLogo(modifier = Modifier.size(52.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "ABYSSAL",
                            color = PureWhite,
                            fontSize = 28.sp,
                            fontWeight = FontWeight.Bold,
                            maxLines = 1
                        )
                        Text(
                            text = "Private node access",
                            color = SteelMuted,
                            fontSize = 13.sp,
                            modifier = Modifier.padding(top = 2.dp)
                        )
                    }
                    StatusPill(label = "RAM ONLY", color = NeonGreen)
                }

                Text(
                    text = "Enter Abyssal",
                    color = PureWhite,
                    fontSize = 22.sp,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 34.dp, bottom = 14.dp)
                )

                GlassSurface(
                    modifier = Modifier.fillMaxWidth(),
                    borderColor = if (error == null) GlassBorder else SelfDestructAmber.copy(alpha = 0.55f)
                ) {
                    Column(modifier = Modifier.padding(18.dp)) {
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            TextButton(onClick = { scanning = true }, enabled = !isVerifying && !readingImage) { Text("Scan invite") }
                            TextButton(onClick = { imagePicker.launch("image/*") }, enabled = !isVerifying && !readingImage) {
                                if (readingImage) AbyssalMarkLoader(size = AbyssalMarkLoaderSize.Inline)
                                Text(if (readingImage) "Reading image" else "Open QR image")
                            }
                        }
                        if (imageError) Text("QR image not accepted.", color = SelfDestructAmber)
                        InviteEntryField(
                            value = invite,
                            onValueChange = {
                                invite = it.take(MAX_INVITE_TEXT_CHARS)
                                onInputChanged()
                            },
                            colors = entranceTextFieldColors(),
                            enabled = !isVerifying && !readingImage && !scanning,
                            isError = error != null,
                            onNext = { passwordFocusRequester.requestFocus() },
                            modifier = Modifier.fillMaxWidth()
                        )

                        TextButton(
                            onClick = {
                                invite = clipboard.getText()?.text
                                    ?.take(MAX_INVITE_TEXT_CHARS)
                                    .orEmpty()
                                onInputChanged()
                            },
                            enabled = !isVerifying && !readingImage && !scanning,
                            modifier = Modifier
                                .align(Alignment.End)
                                .padding(top = 4.dp)
                        ) {
                            Text("Paste invite")
                        }

                        OutlinedTextField(
                            value = password,
                            onValueChange = {
                                password = it.take(MAX_PASSWORD_CHARS)
                                onInputChanged()
                            },
                            label = { Text("Password") },
                            placeholder = { Text("Minimum 8 characters") },
                            colors = entranceTextFieldColors(accent = NeonGreen),
                            enabled = !isVerifying,
                            singleLine = true,
                            visualTransformation = if (passwordVisible) {
                                VisualTransformation.None
                            } else {
                                PasswordVisualTransformation()
                            },
                            trailingIcon = {
                                IconButton(onClick = { passwordVisible = !passwordVisible }) {
                                    EyeIcon(
                                        modifier = Modifier.size(20.dp),
                                        color = if (passwordVisible) NeonGreen else SteelMuted,
                                        crossedOut = !passwordVisible
                                    )
                                }
                            },
                            isError = error != null,
                            keyboardOptions = KeyboardOptions(
                                capitalization = KeyboardCapitalization.None,
                                keyboardType = KeyboardType.Password,
                                imeAction = ImeAction.Done
                            ),
                            keyboardActions = KeyboardActions(onDone = { submit() }),
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 12.dp)
                                .focusRequester(passwordFocusRequester)
                        )

                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 14.dp)
                                .clickable(
                                    enabled = !isVerifying,
                                    role = Role.Checkbox,
                                    onClick = { rememberSession = !rememberSession }
                                )
                                .padding(vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Checkbox(
                                checked = rememberSession,
                                onCheckedChange = { rememberSession = it },
                                enabled = !isVerifying,
                                colors = CheckboxDefaults.colors(
                                    checkedColor = NeonCyan,
                                    checkmarkColor = DeepBlack,
                                    uncheckedColor = SteelMuted
                                )
                            )
                            Column(
                                modifier = Modifier
                                    .weight(1f)
                                    .padding(start = 6.dp)
                            ) {
                                Text(
                                    text = "Keep session behind privacy cover",
                                    color = PureWhite,
                                    fontSize = 14.sp,
                                    fontWeight = FontWeight.SemiBold
                                )
                                Text(
                                    text = if (rememberSession) {
                                        "Keep it in process memory when Abyssal is covered"
                                    } else {
                                        "End it when Abyssal leaves the foreground"
                                    },
                                    color = SteelMuted,
                                    fontSize = 12.sp,
                                    lineHeight = 17.sp,
                                    modifier = Modifier.padding(top = 2.dp)
                                )
                            }
                        }

                        if (error != null) {
                            Text(
                                text = error,
                                color = SelfDestructAmber,
                                fontSize = 12.sp,
                                textAlign = TextAlign.Start,
                                modifier = Modifier.padding(top = 10.dp)
                            )
                        }

                        MiragePrimaryButton(
                            text = "Enter Abyssal",
                            onClick = ::submit,
                            enabled = canSubmit,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 18.dp)
                        ) {
                            if (isVerifying) {
                                AbyssalMarkLoader(
                                    size = AbyssalMarkLoaderSize.Inline,
                                    description = "Verifying node access"
                                )
                            } else {
                                Text(
                                    text = "Enter Abyssal",
                                    fontWeight = FontWeight.Bold,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }
                        }
                    }
                }

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.Center
                ) {
                    LockIcon(modifier = Modifier.size(14.dp), color = SteelMuted)
                    Text(
                        text = "Session state is never written to app storage",
                        color = SteelMuted,
                        fontSize = 11.sp,
                        modifier = Modifier.padding(start = 8.dp)
                    )
                }
            }
        }
    }
}

@Composable
private fun entranceTextFieldColors(accent: Color = NeonCyan) = OutlinedTextFieldDefaults.colors(
    focusedBorderColor = accent,
    unfocusedBorderColor = GlassBorder,
    errorBorderColor = SelfDestructAmber,
    cursorColor = accent,
    focusedTextColor = PureWhite,
    unfocusedTextColor = PureWhite,
    focusedLabelColor = accent,
    unfocusedLabelColor = SteelMuted,
    focusedPlaceholderColor = SteelMuted.copy(alpha = 0.55f),
    unfocusedPlaceholderColor = SteelMuted.copy(alpha = 0.45f)
)

private const val MAX_INVITE_TEXT_CHARS = 2_048
private const val MIN_PASSWORD_CHARS = 8
private const val MAX_PASSWORD_CHARS = 128

@Preview(showBackground = true)
@Composable
private fun EntranceContentPreview() {
    EntranceContent(
        isVerifying = false,
        error = null,
        onInputChanged = {},
        onSubmit = { _, _, _ -> }
    )
}

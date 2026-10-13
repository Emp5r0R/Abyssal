@file:OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)

package com.abyssal.chat.presentation.screens

import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Box
import com.abyssal.chat.theme.TextSubtle
import com.abyssal.chat.theme.OnAccent
import com.abyssal.chat.data.qr.ClipboardQrImage
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
import com.abyssal.chat.theme.Background
import com.abyssal.chat.theme.Outline
import com.abyssal.chat.theme.Accent
import com.abyssal.chat.theme.Success
import com.abyssal.chat.theme.TextPrimary
import com.abyssal.chat.theme.Danger
import com.abyssal.chat.theme.TextMuted
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
internal fun EntranceContent(
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
    val readImage: (android.net.Uri) -> Unit = { uri ->
        if (!readingImage && !isVerifying) {
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
    val imagePicker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) readImage(uri)
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

    val inputsEnabled = !isVerifying && !readingImage && !scanning
    MirageBackground {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .navigationBarsPadding()
                .imePadding()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 20.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Column(modifier = Modifier.fillMaxWidth().widthIn(max = 480.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    MirageLogo(modifier = Modifier.size(36.dp))
                    Column(modifier = Modifier.padding(start = 12.dp)) {
                        Text("Abyssal", color = TextPrimary, fontSize = 20.sp, fontWeight = FontWeight.SemiBold)
                        Text("Ephemeral encrypted chat", color = TextMuted, fontSize = 13.sp)
                    }
                }
                Text(
                    text = "Private conversations that leave no trace.",
                    color = TextPrimary,
                    fontSize = 24.sp,
                    lineHeight = 30.sp,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.padding(top = 28.dp, bottom = 22.dp)
                )

                SectionCard {
                    Column(modifier = Modifier.padding(18.dp)) {
                        Text("Sign in", color = TextPrimary, fontSize = 22.sp, fontWeight = FontWeight.SemiBold)
                        Text(
                            "Use the invite from your node operator. A new invite creates your account; a used one signs you back in.",
                            color = TextMuted,
                            fontSize = 14.sp,
                            lineHeight = 20.sp,
                            modifier = Modifier.padding(top = 4.dp, bottom = 16.dp)
                        )
                        InviteEntryField(
                            value = invite,
                            onValueChange = {
                                invite = it.take(MAX_INVITE_TEXT_CHARS)
                                onInputChanged()
                            },
                            colors = appTextFieldColors(),
                            enabled = inputsEnabled,
                            isError = error != null,
                            onNext = { passwordFocusRequester.requestFocus() },
                            trailingIcon = {
                                IconAction(
                                    AppIcons.ClipboardPaste,
                                    "Paste invite",
                                    {
                                        invite = clipboard.getText()?.text?.take(MAX_INVITE_TEXT_CHARS).orEmpty()
                                        onInputChanged()
                                    },
                                    enabled = inputsEnabled,
                                    tint = Accent
                                )
                            },
                            modifier = Modifier.fillMaxWidth()
                        )
                        FlowRow(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 10.dp),
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            MirageSecondaryButton(
                                "Scan QR",
                                { scanning = true },
                                enabled = !isVerifying && !readingImage,
                                icon = AppIcons.ScanLine,
                                compact = true
                            )
                            MirageSecondaryButton(
                                if (readingImage) "Reading…" else "Open image",
                                { imagePicker.launch("image/*") },
                                enabled = !isVerifying && !readingImage,
                                icon = AppIcons.Image,
                                compact = true
                            )
                            MirageSecondaryButton(
                                "Paste QR image",
                                {
                                    val uri = ClipboardQrImage.imageUri(context)
                                    if (uri == null) imageError = true else readImage(uri)
                                },
                                enabled = !isVerifying && !readingImage,
                                icon = AppIcons.ClipboardPaste,
                                compact = true
                            )
                        }
                        if (imageError) {
                            Text(
                                "No valid invite QR found. Copy a screenshot of the QR code, then paste it.",
                                color = Danger,
                                fontSize = 13.sp,
                                lineHeight = 18.sp,
                                modifier = Modifier.padding(top = 8.dp)
                            )
                        }

                        AppTextField(
                            value = password,
                            onValueChange = {
                                password = it.take(MAX_PASSWORD_CHARS)
                                onInputChanged()
                            },
                            label = "Password",
                            placeholder = "At least 8 characters",
                            enabled = !isVerifying,
                            isError = error != null,
                            visualTransformation = if (passwordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                            trailingIcon = {
                                IconAction(
                                    if (passwordVisible) AppIcons.EyeOff else AppIcons.Eye,
                                    if (passwordVisible) "Hide password" else "Show password",
                                    { passwordVisible = !passwordVisible }
                                )
                            },
                            keyboardOptions = KeyboardOptions(
                                capitalization = KeyboardCapitalization.None,
                                keyboardType = KeyboardType.Password,
                                imeAction = ImeAction.Done
                            ),
                            keyboardActions = KeyboardActions(onDone = { submit() }),
                            modifier = Modifier
                                .padding(top = 16.dp)
                                .focusRequester(passwordFocusRequester)
                        )

                        Box(modifier = Modifier.padding(top = 14.dp)) {
                            PreferenceSwitch(
                                label = "Keep me signed in while hidden",
                                detail = if (rememberSession) {
                                    "Your session stays in memory when Abyssal is covered or in the background."
                                } else {
                                    "Your session ends as soon as Abyssal leaves the screen."
                                },
                                checked = rememberSession,
                                onCheckedChange = { if (!isVerifying) rememberSession = it }
                            )
                        }

                        if (error != null) {
                            NoticeBanner(error, Tone.Danger, icon = AppIcons.Alert, modifier = Modifier.padding(top = 14.dp))
                        }

                        MiragePrimaryButton(
                            text = "Sign in",
                            onClick = ::submit,
                            enabled = canSubmit,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 18.dp)
                        ) {
                            if (isVerifying) {
                                AbyssalMarkLoader(size = AbyssalMarkLoaderSize.Inline, description = "Verifying node access")
                                Text("Verifying…", fontWeight = FontWeight.SemiBold, fontSize = 15.sp, modifier = Modifier.padding(start = 8.dp))
                            } else {
                                AppIcon(AppIcons.LogIn, tint = OnAccent, size = 18.dp)
                                Text("Sign in", fontWeight = FontWeight.SemiBold, fontSize = 15.sp, modifier = Modifier.padding(start = 8.dp))
                            }
                        }
                    }
                }

                Row(
                    modifier = Modifier.fillMaxWidth().padding(top = 16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.Center
                ) {
                    AppIcon(AppIcons.Lock, tint = TextSubtle, size = 14.dp)
                    Text(
                        text = "Nothing is written to storage. Your session lives in memory only.",
                        color = TextSubtle,
                        fontSize = 12.sp,
                        modifier = Modifier.padding(start = 6.dp)
                    )
                }
            }
        }
    }
}

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

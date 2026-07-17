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
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalFocusManager
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
import java.util.Locale

@Composable
fun EntranceScreen(viewModel: ChatViewModel) {
    EntranceContent(
        isVerifying = viewModel.isVerifyingCode.value,
        error = viewModel.inviteCodeError.value,
        onInputChanged = viewModel::clearAccountError,
        onSubmit = viewModel::submitAccount
    )
}

@Composable
private fun EntranceContent(
    isVerifying: Boolean,
    error: String?,
    onInputChanged: () -> Unit,
    onSubmit: (String, String, String, Boolean) -> Unit
) {
    var nodeUrl by remember { mutableStateOf("") }
    var inviteCode by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var passwordVisible by remember { mutableStateOf(false) }
    var rememberSession by remember { mutableStateOf(true) }
    val codeFocusRequester = remember { FocusRequester() }
    val passwordFocusRequester = remember { FocusRequester() }
    val focusManager = LocalFocusManager.current
    val canSubmit = inviteCode.length >= 12 &&
        nodeUrl.isNotBlank() &&
        password.length >= 8 &&
        !isVerifying

    fun submit() {
        if (!canSubmit) return
        focusManager.clearFocus()
        onSubmit(inviteCode, nodeUrl, password, rememberSession)
    }

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
                    text = "Enter node",
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
                        OutlinedTextField(
                            value = nodeUrl,
                            onValueChange = {
                                nodeUrl = it.trim()
                                onInputChanged()
                            },
                            label = { Text("Node URL") },
                            placeholder = { Text("https://node.example.com") },
                            colors = entranceTextFieldColors(),
                            enabled = !isVerifying,
                            singleLine = true,
                            isError = error != null,
                            keyboardOptions = KeyboardOptions(
                                capitalization = KeyboardCapitalization.None,
                                keyboardType = KeyboardType.Uri,
                                imeAction = ImeAction.Next
                            ),
                            keyboardActions = KeyboardActions(
                                onNext = { codeFocusRequester.requestFocus() }
                            ),
                            modifier = Modifier.fillMaxWidth()
                        )

                        OutlinedTextField(
                            value = inviteCode,
                            onValueChange = {
                                inviteCode = formatInviteCode(it)
                                onInputChanged()
                            },
                            label = { Text("Invite code") },
                            placeholder = { Text("ABY7-KQ29-X4PZ") },
                            colors = entranceTextFieldColors(accent = NeonCyan),
                            enabled = !isVerifying,
                            singleLine = true,
                            isError = error != null,
                            keyboardOptions = KeyboardOptions(
                                capitalization = KeyboardCapitalization.Characters,
                                keyboardType = KeyboardType.Ascii,
                                imeAction = ImeAction.Next
                            ),
                            keyboardActions = KeyboardActions(
                                onNext = { passwordFocusRequester.requestFocus() }
                            ),
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 12.dp)
                                .focusRequester(codeFocusRequester)
                        )

                        OutlinedTextField(
                            value = password,
                            onValueChange = {
                                password = it
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
                                    text = "Remember this session",
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
                                CircularProgressIndicator(
                                    modifier = Modifier.size(21.dp),
                                    color = DeepBlack,
                                    strokeWidth = 2.dp
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

private fun formatInviteCode(input: String): String {
    return input
        .filter { it.isLetterOrDigit() || it == '-' }
        .take(64)
        .uppercase(Locale.ROOT)
}

@Preview(showBackground = true)
@Composable
private fun EntranceContentPreview() {
    EntranceContent(
        isVerifying = false,
        error = null,
        onInputChanged = {},
        onSubmit = { _, _, _, _ -> }
    )
}

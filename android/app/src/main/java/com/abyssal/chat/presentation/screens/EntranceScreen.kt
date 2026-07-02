package com.abyssal.chat.presentation.screens

import androidx.compose.foundation.BorderStroke
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.abyssal.chat.domain.model.ServerStatus
import com.abyssal.chat.presentation.viewmodel.ChatViewModel
import com.abyssal.chat.theme.DeepBlack
import com.abyssal.chat.theme.GlassBorder
import com.abyssal.chat.theme.MutedWhite
import com.abyssal.chat.theme.NeonCyan
import com.abyssal.chat.theme.NeonGreen
import com.abyssal.chat.theme.PureWhite
import com.abyssal.chat.theme.SelfDestructAmber
import com.abyssal.chat.theme.SteelMuted
import java.util.Locale

@Composable
fun EntranceScreen(viewModel: ChatViewModel) {
    val isVerifying = viewModel.isVerifyingCode.value
    val error = viewModel.inviteCodeError.value
    val status by viewModel.serverStatus.collectAsState()

    EntranceContent(
        isVerifying = isVerifying,
        error = error,
        status = status,
        onSubmit = viewModel::submitAccount
    )
}

@Composable
private fun EntranceContent(
    isVerifying: Boolean,
    error: String?,
    status: ServerStatus,
    onSubmit: (String, String, String, Boolean) -> Unit
) {
    var inviteCode by remember { mutableStateOf("") }
    var nodeUrl by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var createAccount by remember { mutableStateOf(true) }
    val canSubmit = inviteCode.length >= 12 && nodeUrl.isNotBlank() && password.length >= 8 && !isVerifying

    MirageBackground {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .navigationBarsPadding()
                .imePadding()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 22.dp, vertical = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            MirageLogo(modifier = Modifier.size(64.dp))
            Spacer(modifier = Modifier.height(18.dp))

            Text(
                text = "ABYSSAL",
                color = NeonCyan,
                fontSize = 36.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
                textAlign = TextAlign.Center
            )
            Text(
                text = "Private access for RAM-only rooms",
                color = SteelMuted,
                fontSize = 13.sp,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(top = 6.dp, bottom = 34.dp)
            )

            GlassSurface(modifier = Modifier.fillMaxWidth(), borderColor = GlassBorder) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    modifier = Modifier.padding(20.dp)
                ) {
                    SectionLabel("ACCESS CODE")
                    Text(
                        text = "Use your node code and password to create or enter a RAM-only account.",
                        color = SteelMuted,
                        fontSize = 13.sp,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(top = 8.dp, bottom = 18.dp)
                    )

                    OutlinedTextField(
                        value = inviteCode,
                        onValueChange = {
                            inviteCode = formatInviteCode(it)
                        },
                        placeholder = {
                            Text(
                                "ABY7-KQ29-X4PZ",
                                color = SteelMuted.copy(alpha = 0.45f),
                                fontFamily = FontFamily.Monospace,
                                textAlign = TextAlign.Center,
                                modifier = Modifier.fillMaxWidth()
                            )
                        },
                        textStyle = TextStyle(
                            color = NeonCyan,
                            fontSize = 18.sp,
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Bold,
                            textAlign = TextAlign.Center
                        ),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = NeonCyan,
                            unfocusedBorderColor = GlassBorder,
                            cursorColor = NeonCyan,
                            focusedTextColor = NeonCyan,
                            unfocusedTextColor = NeonCyan
                        ),
                        singleLine = true,
                        isError = error != null,
                        keyboardOptions = KeyboardOptions(
                            capitalization = KeyboardCapitalization.Characters,
                            keyboardType = KeyboardType.Ascii,
                            imeAction = ImeAction.Done
                        ),
                        keyboardActions = KeyboardActions(
                            onDone = {
                                if (canSubmit) onSubmit(inviteCode, nodeUrl, password, createAccount)
                            }
                        ),
                        modifier = Modifier.fillMaxWidth()
                    )

                    Spacer(modifier = Modifier.height(14.dp))

                    SectionLabel("NODE URL")
                    OutlinedTextField(
                        value = nodeUrl,
                        onValueChange = { nodeUrl = it.trim() },
                        placeholder = {
                            Text(
                                "https://your-node.example.com",
                                color = SteelMuted.copy(alpha = 0.45f),
                                fontFamily = FontFamily.Monospace,
                                textAlign = TextAlign.Center,
                                modifier = Modifier.fillMaxWidth()
                            )
                        },
                        textStyle = TextStyle(
                            color = PureWhite,
                            fontSize = 14.sp,
                            fontFamily = FontFamily.Monospace,
                            textAlign = TextAlign.Center
                        ),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = NeonGreen,
                            unfocusedBorderColor = GlassBorder,
                            cursorColor = NeonGreen,
                            focusedTextColor = PureWhite,
                            unfocusedTextColor = PureWhite
                        ),
                        singleLine = true,
                        isError = error != null,
                        keyboardOptions = KeyboardOptions(
                            capitalization = KeyboardCapitalization.None,
                            keyboardType = KeyboardType.Uri,
                            imeAction = ImeAction.Done
                        ),
                        keyboardActions = KeyboardActions(
                            onDone = {
                                if (canSubmit) onSubmit(inviteCode, nodeUrl, password, createAccount)
                            }
                        ),
                        modifier = Modifier.fillMaxWidth()
                    )

                    Spacer(modifier = Modifier.height(14.dp))

                    SectionLabel("PASSWORD")
                    OutlinedTextField(
                        value = password,
                        onValueChange = { password = it },
                        placeholder = {
                            Text(
                                "Minimum 8 characters",
                                color = SteelMuted.copy(alpha = 0.45f),
                                fontFamily = FontFamily.Monospace,
                                textAlign = TextAlign.Center,
                                modifier = Modifier.fillMaxWidth()
                            )
                        },
                        textStyle = TextStyle(
                            color = PureWhite,
                            fontSize = 14.sp,
                            fontFamily = FontFamily.Monospace,
                            textAlign = TextAlign.Center
                        ),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = NeonGreen,
                            unfocusedBorderColor = GlassBorder,
                            cursorColor = NeonGreen,
                            focusedTextColor = PureWhite,
                            unfocusedTextColor = PureWhite
                        ),
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        isError = error != null,
                        keyboardOptions = KeyboardOptions(
                            capitalization = KeyboardCapitalization.None,
                            keyboardType = KeyboardType.Password,
                            imeAction = ImeAction.Done
                        ),
                        keyboardActions = KeyboardActions(
                            onDone = {
                                if (canSubmit) onSubmit(inviteCode, nodeUrl, password, createAccount)
                            }
                        ),
                        modifier = Modifier.fillMaxWidth()
                    )

                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 16.dp),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        ModeChip(
                            label = "Create",
                            selected = createAccount,
                            modifier = Modifier.weight(1f),
                            onClick = { createAccount = true }
                        )
                        ModeChip(
                            label = "Login",
                            selected = !createAccount,
                            modifier = Modifier.weight(1f),
                            onClick = { createAccount = false }
                        )
                    }

                    if (error != null) {
                        Text(
                            text = error,
                            color = SelfDestructAmber,
                            fontSize = 12.sp,
                            textAlign = TextAlign.Center,
                            modifier = Modifier.padding(top = 12.dp)
                        )
                    }

                    MiragePrimaryButton(
                        text = if (createAccount) "Create account" else "Login",
                        onClick = { onSubmit(inviteCode, nodeUrl, password, createAccount) },
                        enabled = canSubmit,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 22.dp)
                    ) {
                        if (isVerifying) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(22.dp),
                                color = DeepBlack,
                                strokeWidth = 2.dp
                            )
                        } else {
                            Text(
                                text = if (createAccount) "Create account" else "Login",
                                fontWeight = FontWeight.Bold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                    }
                }
            }

            StatusPill(
                label = "${status.state}  ${status.latencyMs}ms  ${status.nodeId}",
                color = if (status.state == "CONNECTED") NeonGreen else SelfDestructAmber,
                modifier = Modifier.fillMaxWidth()
            )
        }
    }
}

private fun formatInviteCode(input: String): String {
    return input
        .filter { it.isLetterOrDigit() || it == '-' }
        .take(24)
        .uppercase(Locale.ROOT)
}

@Composable
private fun ModeChip(
    label: String,
    selected: Boolean,
    modifier: Modifier = Modifier,
    onClick: () -> Unit
) {
    val borderColor = if (selected) NeonCyan else GlassBorder
    val background = if (selected) NeonCyan.copy(alpha = 0.16f) else Color.White.copy(alpha = 0.03f)
    Box(
        contentAlignment = Alignment.Center,
        modifier = modifier
            .height(44.dp)
            .clip(RoundedCornerShape(8.dp))
            .background(background)
            .border(BorderStroke(1.dp, borderColor), RoundedCornerShape(8.dp))
            .clickable(onClick = onClick)
    ) {
        Text(
            text = label,
            color = if (selected) NeonCyan else SteelMuted,
            fontSize = 13.sp,
            fontWeight = FontWeight.Bold,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}

@Preview
@Composable
private fun EntranceContentPreview() {
    EntranceContent(
        isVerifying = false,
        error = null,
        status = ServerStatus("CONNECTED", "Node-Alpha", 24),
        onSubmit = { _, _, _, _ -> }
    )
}

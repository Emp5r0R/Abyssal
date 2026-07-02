package com.abyssal.chat.presentation.screens

import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
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
import androidx.compose.foundation.shape.CircleShape
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
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
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
        onSubmit = viewModel::submitInviteCode
    )
}

@Composable
private fun EntranceContent(
    isVerifying: Boolean,
    error: String?,
    status: ServerStatus,
    onSubmit: (String, String) -> Unit
) {
    var inviteCode by remember { mutableStateOf("") }
    var nodeUrl by remember { mutableStateOf("") }
    val canSubmit = inviteCode.length == 14 && nodeUrl.isNotBlank() && !isVerifying

    val infiniteTransition = rememberInfiniteTransition(label = "biometric_pulse")
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 0.98f,
        targetValue = 1.04f,
        animationSpec = infiniteRepeatable(tween(1600), RepeatMode.Reverse),
        label = "biometric_scale"
    )
    val pulseAlpha by infiniteTransition.animateFloat(
        initialValue = 0.55f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(1600), RepeatMode.Reverse),
        label = "biometric_alpha"
    )

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
                text = "MIRAGE",
                color = NeonCyan,
                fontSize = 36.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
                textAlign = TextAlign.Center
            )
            Text(
                text = "Private access for ephemeral rooms",
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
                        text = "Use your invite code and node URL to create a temporary identity.",
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
                                "MIRA-4729-ZX00",
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
                                if (canSubmit) onSubmit(inviteCode, nodeUrl)
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
                                if (canSubmit) onSubmit(inviteCode, nodeUrl)
                            }
                        ),
                        modifier = Modifier.fillMaxWidth()
                    )

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
                        text = "Create identity",
                        onClick = { onSubmit(inviteCode, nodeUrl) },
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
                                text = "Create identity",
                                fontWeight = FontWeight.Bold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                    }
                }
            }

            Text(
                text = "or",
                color = SteelMuted,
                fontSize = 13.sp,
                modifier = Modifier.padding(top = 26.dp, bottom = 18.dp)
            )

            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .scale(pulseScale)
                    .size(82.dp)
                    .clip(CircleShape)
                    .background(Color.White.copy(alpha = 0.06f))
                    .border(BorderStroke(1.dp, NeonGreen.copy(alpha = 0.75f)), CircleShape)
                    .semantics { contentDescription = "Authenticate with biometrics" }
                    .clickable(role = Role.Button) {
                        if (nodeUrl.isNotBlank()) onSubmit("BIOM-ETRI-CAUT", nodeUrl)
                    }
            ) {
                Box(
                    modifier = Modifier
                        .size(68.dp)
                        .alpha(pulseAlpha)
                        .clip(CircleShape)
                        .border(BorderStroke(2.dp, NeonGreen.copy(alpha = 0.32f)), CircleShape)
                )
                BiometricScannerIcon(modifier = Modifier.size(36.dp))
            }

            Text(
                text = "Biometric shortcut",
                color = SteelMuted,
                fontSize = 12.sp,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(top = 14.dp, bottom = 28.dp)
            )

            StatusPill(
                label = "${status.state}  ${status.latencyMs}ms  ${status.nodeId}",
                color = if (status.state == "CONNECTED") NeonGreen else SelfDestructAmber,
                modifier = Modifier.fillMaxWidth()
            )
        }
    }
}

private fun formatInviteCode(input: String): String {
    val clean = input
        .filter { it.isLetterOrDigit() }
        .take(12)
        .uppercase(Locale.ROOT)

    return buildString {
        clean.forEachIndexed { index, char ->
            if (index == 4 || index == 8) append("-")
            append(char)
        }
    }
}

@Preview
@Composable
private fun EntranceContentPreview() {
    EntranceContent(
        isVerifying = false,
        error = null,
        status = ServerStatus("CONNECTED", "Node-Alpha", 24),
        onSubmit = { _, _ -> }
    )
}

package com.abyssal.chat.presentation.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import com.abyssal.chat.theme.BorderCyan
import com.abyssal.chat.theme.DeepBlack
import com.abyssal.chat.theme.DeepBlue
import com.abyssal.chat.theme.GlassCardBg
import com.abyssal.chat.theme.GlassBorder
import com.abyssal.chat.theme.MutedWhite
import com.abyssal.chat.theme.NeonCyan
import com.abyssal.chat.theme.NeonGreen
import com.abyssal.chat.theme.PureWhite
import com.abyssal.chat.theme.SelfDestructAmber
import com.abyssal.chat.theme.SteelMuted

private val MirageShape = RoundedCornerShape(8.dp)

@Composable
fun MirageBackground(
    modifier: Modifier = Modifier,
    content: @Composable BoxScope.() -> Unit
) {
    Box(
        modifier = modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    listOf(
                        DeepBlack,
                        Color(0xFF07111D),
                        DeepBlue
                    )
                )
            )
    ) {
        content()
    }
}

@Composable
fun GlassSurface(
    modifier: Modifier = Modifier,
    borderColor: Color = GlassBorder,
    backgroundColor: Color = GlassCardBg,
    content: @Composable () -> Unit
) {
    Surface(
        modifier = modifier,
        shape = MirageShape,
        color = backgroundColor,
        border = BorderStroke(1.dp, borderColor),
        tonalElevation = 0.dp,
        shadowElevation = 0.dp,
        content = content
    )
}

@Composable
fun MiragePrimaryButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    danger: Boolean = false,
    content: (@Composable RowScope.() -> Unit)? = null
) {
    Button(
        onClick = onClick,
        enabled = enabled,
        shape = MirageShape,
        colors = ButtonDefaults.buttonColors(
            containerColor = if (danger) SelfDestructAmber else NeonCyan,
            contentColor = if (danger) PureWhite else DeepBlack,
            disabledContainerColor = SteelMuted.copy(alpha = 0.16f),
            disabledContentColor = SteelMuted
        ),
        modifier = modifier.height(48.dp)
    ) {
        if (content == null) {
            Text(
                text = text,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.SansSerif,
                fontSize = 14.sp,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        } else {
            content()
        }
    }
}

@Composable
fun MirageSecondaryButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    TextButton(
        onClick = onClick,
        shape = MirageShape,
        colors = ButtonDefaults.textButtonColors(contentColor = MutedWhite),
        modifier = modifier.height(48.dp)
    ) {
        Text(text = text, fontWeight = FontWeight.Bold, fontSize = 14.sp)
    }
}

@Composable
fun MirageIconButton(
    contentDescription: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    accent: Color = GlassBorder,
    enabled: Boolean = true,
    content: @Composable () -> Unit
) {
    Box(
        contentAlignment = Alignment.Center,
        modifier = modifier
            .size(48.dp)
            .clip(CircleShape)
            .background(GlassCardBg)
            .border(BorderStroke(1.dp, accent), CircleShape)
            .alpha(if (enabled) 1f else 0.42f)
            .semantics { this.contentDescription = contentDescription }
            .clickable(enabled = enabled, role = Role.Button, onClick = onClick)
    ) {
        content()
    }
}

@Composable
fun StatusPill(
    label: String,
    modifier: Modifier = Modifier,
    color: Color = NeonGreen
) {
    Row(
        modifier = modifier
            .clip(RoundedCornerShape(100.dp))
            .background(GlassCardBg)
            .border(BorderStroke(1.dp, color.copy(alpha = 0.24f)), RoundedCornerShape(100.dp))
            .padding(horizontal = 12.dp, vertical = 7.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            modifier = Modifier
                .size(6.dp)
                .clip(CircleShape)
                .background(color)
        )
        Text(
            text = label,
            color = color,
            fontSize = 11.sp,
            fontWeight = FontWeight.SemiBold,
            fontFamily = FontFamily.Monospace,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.padding(start = 8.dp)
        )
    }
}

@Composable
fun TimerChip(
    text: String,
    selected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Box(
        contentAlignment = Alignment.Center,
        modifier = modifier
            .height(36.dp)
            .clip(MirageShape)
            .background(if (selected) SelfDestructAmber else DeepBlack.copy(alpha = 0.72f))
            .border(
                BorderStroke(1.dp, if (selected) SelfDestructAmber else GlassBorder),
                MirageShape
            )
            .clickable(role = Role.Button, onClick = onClick)
            .padding(horizontal = 12.dp)
    ) {
        Text(
            text = text,
            color = if (selected) DeepBlack else MutedWhite,
            fontSize = 12.sp,
            fontWeight = FontWeight.Bold,
            fontFamily = FontFamily.Monospace
        )
    }
}

@Composable
fun MirageDialog(
    title: String,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
    accent: Color = BorderCyan,
    icon: (@Composable () -> Unit)? = null,
    content: @Composable () -> Unit
) {
    Dialog(onDismissRequest = onDismiss) {
        GlassSurface(
            borderColor = accent,
            backgroundColor = DeepBlue.copy(alpha = 0.98f),
            modifier = modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier
                    .padding(22.dp)
                    .verticalScroll(rememberScrollState()),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                if (icon != null) {
                    icon()
                    Spacer(modifier = Modifier.height(14.dp))
                }
                Text(
                    text = title,
                    color = if (accent == SelfDestructAmber) SelfDestructAmber else NeonCyan,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold,
                    textAlign = TextAlign.Center
                )
                Spacer(modifier = Modifier.height(18.dp))
                content()
            }
        }
    }
}

@Composable
fun EmptyState(
    title: String,
    detail: String,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier.padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            text = title,
            color = PureWhite,
            fontSize = 17.sp,
            fontWeight = FontWeight.SemiBold,
            textAlign = TextAlign.Center
        )
        Text(
            text = detail,
            color = SteelMuted,
            fontSize = 13.sp,
            textAlign = TextAlign.Center,
            lineHeight = 18.sp,
            modifier = Modifier.padding(top = 8.dp)
        )
    }
}

@Composable
fun SectionLabel(
    text: String,
    modifier: Modifier = Modifier,
    color: Color = NeonCyan
) {
    Text(
        text = text,
        color = color,
        fontSize = 11.sp,
        fontWeight = FontWeight.Bold,
        fontFamily = FontFamily.Monospace,
        modifier = modifier
    )
}

@Preview
@Composable
private fun MirageComponentsPreview() {
    MirageBackground {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            StatusPill("CONNECTED 24ms")
            GlassSurface(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    SectionLabel("MIRAGE")
                    Text("Reusable glass surface", color = PureWhite)
                }
            }
            MiragePrimaryButton(text = "Continue", onClick = {}, modifier = Modifier.fillMaxWidth())
        }
    }
}

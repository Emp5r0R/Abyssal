package com.abyssal.chat.presentation.screens

import com.abyssal.chat.domain.model.accountInitials
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.SwitchColors
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextFieldColors
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.abyssal.chat.theme.Accent
import com.abyssal.chat.theme.AccentSoft
import com.abyssal.chat.theme.Background
import com.abyssal.chat.theme.Danger
import com.abyssal.chat.theme.DangerSoft
import com.abyssal.chat.theme.OnAccent
import com.abyssal.chat.theme.Outline
import com.abyssal.chat.theme.OutlineStrong
import com.abyssal.chat.theme.Success
import com.abyssal.chat.theme.SuccessSoft
import com.abyssal.chat.theme.SurfaceBase
import com.abyssal.chat.theme.SurfaceHigh
import com.abyssal.chat.theme.SurfaceRaised
import com.abyssal.chat.theme.TextMuted
import com.abyssal.chat.theme.TextPrimary
import com.abyssal.chat.theme.TextSubtle
import com.abyssal.chat.theme.Warning
import com.abyssal.chat.theme.WarningSoft

internal val CardShape = RoundedCornerShape(14.dp)
internal val ControlShape = RoundedCornerShape(12.dp)

/** Tone of a banner, badge or dialog. */
internal enum class Tone(val color: Color, val soft: Color) {
    Accent(com.abyssal.chat.theme.Accent, AccentSoft),
    Success(com.abyssal.chat.theme.Success, SuccessSoft),
    Warning(com.abyssal.chat.theme.Warning, WarningSoft),
    Danger(com.abyssal.chat.theme.Danger, DangerSoft),
    Neutral(TextMuted, SurfaceRaised)
}

@Composable
fun MirageBackground(
    modifier: Modifier = Modifier,
    content: @Composable BoxScope.() -> Unit
) {
    Box(modifier = modifier.fillMaxSize().background(Background)) { content() }
}

@Composable
fun GlassSurface(
    modifier: Modifier = Modifier,
    borderColor: Color = Outline,
    backgroundColor: Color = SurfaceBase,
    content: @Composable () -> Unit
) {
    Surface(
        modifier = modifier,
        shape = CardShape,
        color = backgroundColor,
        border = BorderStroke(1.dp, borderColor),
        content = content
    )
}

/** A titled card, the Android counterpart of the web dashboard's panels. */
@Composable
internal fun SectionCard(
    modifier: Modifier = Modifier,
    title: String? = null,
    icon: ImageVector? = null,
    trailing: String? = null,
    borderColor: Color = Outline,
    titleColor: Color = TextPrimary,
    content: @Composable ColumnScope.() -> Unit
) {
    GlassSurface(modifier = modifier.fillMaxWidth(), borderColor = borderColor) {
        Column {
            if (title != null) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(start = 16.dp, end = 16.dp, top = 14.dp, bottom = 10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    if (icon != null) {
                        AppIcon(icon, tint = if (titleColor == TextPrimary) Accent else titleColor, size = 18.dp)
                        Spacer(Modifier.width(10.dp))
                    }
                    Text(
                        text = title,
                        color = titleColor,
                        fontSize = 15.sp,
                        fontWeight = FontWeight.SemiBold,
                        modifier = Modifier.weight(1f)
                    )
                    if (trailing != null) {
                        Text(trailing, color = TextSubtle, fontSize = 12.sp)
                    }
                }
                HorizontalDivider(color = Outline)
            }
            content()
        }
    }
}

@Composable
fun MiragePrimaryButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    danger: Boolean = false,
    icon: ImageVector? = null,
    compact: Boolean = false,
    content: (@Composable RowScope.() -> Unit)? = null
) {
    Button(
        onClick = onClick,
        enabled = enabled,
        shape = ControlShape,
        colors = ButtonDefaults.buttonColors(
            containerColor = if (danger) Danger else Accent,
            contentColor = if (danger) Background else OnAccent,
            disabledContainerColor = if (danger) Danger.copy(alpha = 0.3f) else Accent.copy(alpha = 0.3f),
            disabledContentColor = OnAccent.copy(alpha = 0.7f)
        ),
        contentPadding = PaddingValues(horizontal = if (compact) 14.dp else 18.dp),
        modifier = modifier.heightIn(min = if (compact) 38.dp else 48.dp)
    ) {
        if (content == null) {
            if (icon != null) {
                AppIcon(icon, tint = if (danger) Background else OnAccent, size = if (compact) 16.dp else 18.dp)
                Spacer(Modifier.width(if (compact) 6.dp else 8.dp))
            }
            Text(
                text = text,
                fontWeight = FontWeight.SemiBold,
                fontSize = if (compact) 13.sp else 15.sp,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        } else {
            content()
        }
    }
}

/** Outlined, lower-emphasis button (web `.button-secondary`). */
@Composable
fun MirageSecondaryButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    icon: ImageVector? = null,
    danger: Boolean = false,
    compact: Boolean = false
) {
    val content = if (danger) Danger else TextPrimary
    OutlinedButton(
        onClick = onClick,
        enabled = enabled,
        shape = ControlShape,
        border = BorderStroke(1.dp, if (danger) Danger.copy(alpha = 0.45f) else OutlineStrong),
        colors = ButtonDefaults.outlinedButtonColors(
            containerColor = SurfaceRaised,
            contentColor = content,
            disabledContentColor = TextSubtle
        ),
        contentPadding = PaddingValues(horizontal = if (compact) 12.dp else 16.dp),
        modifier = modifier.heightIn(min = if (compact) 38.dp else 48.dp)
    ) {
        if (icon != null) {
            AppIcon(icon, tint = if (enabled) content else TextSubtle, size = if (compact) 16.dp else 18.dp)
            Spacer(Modifier.width(if (compact) 6.dp else 8.dp))
        }
        Text(
            text = text,
            fontWeight = FontWeight.SemiBold,
            fontSize = if (compact) 13.sp else 15.sp,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}

@Composable
internal fun MirageTextButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    color: Color = Accent,
    enabled: Boolean = true
) {
    TextButton(onClick = onClick, enabled = enabled, shape = ControlShape, modifier = modifier) {
        Text(text, color = if (enabled) color else TextSubtle, fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
    }
}

/** Round icon button; borderless unless [accent] is given. */
@Composable
fun MirageIconButton(
    contentDescription: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    accent: Color? = null,
    enabled: Boolean = true,
    size: Dp = 44.dp,
    background: Color = Color.Transparent,
    content: @Composable () -> Unit
) {
    Box(
        contentAlignment = Alignment.Center,
        modifier = modifier
            .size(size)
            .clip(CircleShape)
            .background(background)
            .then(if (accent != null) Modifier.border(BorderStroke(1.dp, accent), CircleShape) else Modifier)
            .alpha(if (enabled) 1f else 0.4f)
            .semantics { this.contentDescription = contentDescription }
            .clickable(enabled = enabled, role = Role.Button, onClick = onClick)
    ) {
        content()
    }
}

@Composable
internal fun IconAction(
    icon: ImageVector,
    contentDescription: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    tint: Color = TextMuted,
    enabled: Boolean = true,
    size: Dp = 44.dp,
    iconSize: Dp = 20.dp,
    background: Color = Color.Transparent
) {
    MirageIconButton(
        contentDescription = contentDescription,
        onClick = onClick,
        modifier = modifier,
        enabled = enabled,
        size = size,
        background = background
    ) {
        AppIcon(icon, tint = tint, size = iconSize)
    }
}

@Composable
fun StatusPill(
    label: String,
    modifier: Modifier = Modifier,
    color: Color = Success
) {
    Row(
        modifier = modifier
            .clip(RoundedCornerShape(100.dp))
            .background(color.copy(alpha = 0.12f))
            .padding(horizontal = 10.dp, vertical = 5.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(modifier = Modifier.size(7.dp).clip(CircleShape).background(color))
        Text(
            text = label,
            color = color,
            fontSize = 12.sp,
            fontWeight = FontWeight.SemiBold,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.padding(start = 6.dp)
        )
    }
}

/** Small rounded label such as "Not verified" or "Public". */
@Composable
internal fun ToneBadge(
    text: String,
    tone: Tone,
    modifier: Modifier = Modifier,
    icon: ImageVector? = null,
    onClick: (() -> Unit)? = null
) {
    Row(
        modifier = modifier
            .clip(RoundedCornerShape(100.dp))
            .background(tone.soft)
            .then(if (onClick != null) Modifier.clickable(role = Role.Button, onClick = onClick) else Modifier)
            .padding(horizontal = 8.dp, vertical = 3.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        if (icon != null) {
            AppIcon(icon, tint = tone.color, size = 13.dp)
            Spacer(Modifier.width(4.dp))
        }
        Text(text, color = tone.color, fontSize = 12.sp, fontWeight = FontWeight.SemiBold, maxLines = 1)
    }
}

@Composable
internal fun CountBadge(count: Int, modifier: Modifier = Modifier) {
    Box(
        contentAlignment = Alignment.Center,
        modifier = modifier
            .heightIn(min = 20.dp)
            .widthIn(min = 20.dp)
            .clip(RoundedCornerShape(100.dp))
            .background(Accent)
            .padding(horizontal = 6.dp)
            .semantics { contentDescription = "$count unread" }
    ) {
        Text(if (count > 99) "99+" else count.toString(), color = OnAccent, fontSize = 11.sp, fontWeight = FontWeight.Bold)
    }
}

/** Circle with two-character initials or an icon, like the web avatars. */
@Composable
internal fun Avatar(
    label: String,
    modifier: Modifier = Modifier,
    size: Dp = 40.dp,
    tone: Tone = Tone.Accent,
    icon: ImageVector? = null,
    online: Boolean? = null
) {
    Box(modifier = modifier.size(size)) {
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier.size(size).clip(CircleShape).background(tone.soft)
        ) {
            if (icon != null) {
                AppIcon(icon, tint = tone.color, size = size * 0.45f)
            } else {
                Text(
                    accountInitials(label),
                    color = tone.color,
                    fontSize = (size.value * 0.36f).sp,
                    fontWeight = FontWeight.Bold
                )
            }
        }
        if (online != null) {
            Box(
                modifier = Modifier
                    .align(Alignment.BottomEnd)
                    .size(size * 0.3f)
                    .clip(CircleShape)
                    .background(Background)
                    .padding(2.dp)
                    .clip(CircleShape)
                    .background(if (online) Success else TextSubtle)
            )
        }
    }
}

/** Segmented choice, e.g. Rooms/Direct or disappearing-message timers. */
@Composable
internal fun SegmentedControl(
    options: List<String>,
    selectedIndex: Int,
    onSelect: (Int) -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    compact: Boolean = false
) {
    Row(
        modifier = modifier
            .clip(ControlShape)
            .background(SurfaceRaised)
            .border(1.dp, Outline, ControlShape)
            .padding(3.dp),
        horizontalArrangement = Arrangement.spacedBy(2.dp)
    ) {
        options.forEachIndexed { index, option ->
            val selected = index == selectedIndex
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .weight(1f)
                    .clip(RoundedCornerShape(9.dp))
                    .background(if (selected) Accent else Color.Transparent)
                    .selectable(selected = selected, enabled = enabled, role = Role.Tab, onClick = { onSelect(index) })
                    .padding(vertical = if (compact) 6.dp else 9.dp, horizontal = 6.dp)
            ) {
                Text(
                    option,
                    color = when {
                        selected -> OnAccent
                        enabled -> TextMuted
                        else -> TextSubtle
                    },
                    fontSize = if (compact) 13.sp else 14.sp,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1
                )
            }
        }
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
            .height(32.dp)
            .clip(RoundedCornerShape(9.dp))
            .background(if (selected) Accent else SurfaceRaised)
            .border(1.dp, if (selected) Accent else Outline, RoundedCornerShape(9.dp))
            .clickable(role = Role.Button, onClick = onClick)
            .padding(horizontal = 12.dp)
    ) {
        Text(
            text = text,
            color = if (selected) OnAccent else TextMuted,
            fontSize = 13.sp,
            fontWeight = FontWeight.SemiBold
        )
    }
}

/** A dismissible inline message. */
@Composable
internal fun NoticeBanner(
    text: String,
    tone: Tone,
    modifier: Modifier = Modifier,
    icon: ImageVector = AppIcons.Info,
    onDismiss: (() -> Unit)? = null
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .clip(ControlShape)
            .background(tone.soft)
            .border(1.dp, tone.color.copy(alpha = 0.35f), ControlShape)
            .padding(start = 12.dp, end = 4.dp, top = 4.dp, bottom = 4.dp)
            .heightIn(min = 40.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        AppIcon(icon, tint = tone.color, size = 18.dp)
        Text(
            text = text,
            color = TextPrimary,
            fontSize = 13.sp,
            lineHeight = 18.sp,
            modifier = Modifier.weight(1f).padding(horizontal = 10.dp, vertical = 6.dp)
        )
        if (onDismiss != null) {
            IconAction(AppIcons.Close, "Dismiss", onDismiss, size = 36.dp, iconSize = 16.dp)
        }
    }
}

@Composable
fun MirageDialog(
    title: String,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
    accent: Color = Accent,
    icon: (@Composable () -> Unit)? = null,
    content: @Composable () -> Unit
) {
    Dialog(onDismissRequest = onDismiss, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Surface(
            shape = RoundedCornerShape(20.dp),
            color = SurfaceBase,
            border = BorderStroke(1.dp, Outline),
            modifier = modifier.fillMaxWidth().padding(horizontal = 20.dp).widthIn(max = 520.dp)
        ) {
            Column(
                modifier = Modifier
                    .padding(horizontal = 20.dp, vertical = 20.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                    if (icon != null) {
                        icon()
                        Spacer(Modifier.width(12.dp))
                    }
                    Text(
                        text = title,
                        color = if (accent == Danger) Danger else TextPrimary,
                        fontSize = 19.sp,
                        fontWeight = FontWeight.SemiBold,
                        modifier = Modifier.weight(1f)
                    )
                }
                Spacer(modifier = Modifier.height(14.dp))
                content()
            }
        }
    }
}

/** Two-button footer for dialogs: cancel on the left, the action on the right. */
@Composable
internal fun DialogButtons(
    cancel: String,
    confirm: String,
    onCancel: () -> Unit,
    onConfirm: () -> Unit,
    confirmEnabled: Boolean = true,
    danger: Boolean = false
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(top = 22.dp),
        horizontalArrangement = Arrangement.spacedBy(10.dp)
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
internal fun ConfirmDialog(
    title: String,
    message: String,
    confirmLabel: String,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
    danger: Boolean = true
) {
    MirageDialog(
        title = title,
        onDismiss = onDismiss,
        accent = if (danger) Danger else Accent,
        icon = if (danger) {
            { Avatar("", size = 40.dp, tone = Tone.Danger, icon = AppIcons.Alert) }
        } else null
    ) {
        Text(message, color = TextMuted, fontSize = 14.sp, lineHeight = 20.sp)
        DialogButtons("Cancel", confirmLabel, onDismiss, onConfirm, danger = danger)
    }
}

@Composable
fun EmptyState(
    title: String,
    detail: String,
    modifier: Modifier = Modifier,
    actionLabel: String? = null,
    onAction: (() -> Unit)? = null,
    icon: ImageVector? = null
) {
    Column(
        modifier = modifier.padding(horizontal = 32.dp, vertical = 28.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        if (icon != null) {
            Avatar("", size = 56.dp, tone = Tone.Neutral, icon = icon)
            Spacer(Modifier.height(16.dp))
        }
        Text(
            text = title,
            color = TextPrimary,
            fontSize = 17.sp,
            fontWeight = FontWeight.SemiBold,
            textAlign = TextAlign.Center
        )
        Text(
            text = detail,
            color = TextMuted,
            fontSize = 14.sp,
            textAlign = TextAlign.Center,
            lineHeight = 20.sp,
            modifier = Modifier.padding(top = 6.dp)
        )
        if (actionLabel != null && onAction != null) {
            MiragePrimaryButton(
                text = actionLabel,
                onClick = onAction,
                icon = AppIcons.Plus,
                modifier = Modifier.padding(top = 20.dp)
            )
        }
    }
}

/** Small uppercase heading, like the web sidebar's "ROOMS" and "PEOPLE". */
@Composable
fun SectionLabel(
    text: String,
    modifier: Modifier = Modifier,
    color: Color = TextSubtle
) {
    Text(
        text = text.uppercase(),
        color = color,
        fontSize = 12.sp,
        fontWeight = FontWeight.SemiBold,
        letterSpacing = 0.6.sp,
        modifier = modifier
    )
}

@Composable
internal fun appTextFieldColors(accent: Color = Accent): TextFieldColors = OutlinedTextFieldDefaults.colors(
    focusedBorderColor = accent,
    unfocusedBorderColor = OutlineStrong,
    disabledBorderColor = Outline,
    errorBorderColor = Danger,
    cursorColor = accent,
    focusedTextColor = TextPrimary,
    unfocusedTextColor = TextPrimary,
    disabledTextColor = TextMuted,
    focusedLabelColor = accent,
    unfocusedLabelColor = TextMuted,
    focusedPlaceholderColor = TextSubtle,
    unfocusedPlaceholderColor = TextSubtle,
    focusedContainerColor = SurfaceRaised,
    unfocusedContainerColor = SurfaceRaised,
    disabledContainerColor = SurfaceBase,
    errorContainerColor = SurfaceRaised
)

@Composable
internal fun AppTextField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    placeholder: String? = null,
    supportingText: String? = null,
    enabled: Boolean = true,
    isError: Boolean = false,
    singleLine: Boolean = true,
    textStyle: TextStyle? = null,
    keyboardOptions: KeyboardOptions = KeyboardOptions.Default,
    keyboardActions: KeyboardActions = KeyboardActions.Default,
    visualTransformation: VisualTransformation = VisualTransformation.None,
    trailingIcon: (@Composable () -> Unit)? = null
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        placeholder = placeholder?.let { { Text(it) } },
        supportingText = supportingText?.let { { Text(it, color = if (isError) Danger else TextSubtle) } },
        enabled = enabled,
        isError = isError,
        singleLine = singleLine,
        textStyle = textStyle ?: TextStyle(fontSize = 15.sp, color = TextPrimary),
        keyboardOptions = keyboardOptions,
        keyboardActions = keyboardActions,
        visualTransformation = visualTransformation,
        trailingIcon = trailingIcon,
        shape = ControlShape,
        colors = appTextFieldColors(),
        modifier = modifier.fillMaxWidth()
    )
}

@Composable
internal fun appSwitchColors(): SwitchColors = SwitchDefaults.colors(
    checkedThumbColor = OnAccent,
    checkedTrackColor = Accent,
    checkedBorderColor = Accent,
    uncheckedThumbColor = TextMuted,
    uncheckedTrackColor = SurfaceHigh,
    uncheckedBorderColor = OutlineStrong
)

/** Clickable list row with leading content, title, subtitle and trailing content. */
@Composable
internal fun ListRow(
    title: @Composable () -> Unit,
    modifier: Modifier = Modifier,
    subtitle: (@Composable () -> Unit)? = null,
    leading: (@Composable () -> Unit)? = null,
    trailing: (@Composable RowScope.() -> Unit)? = null,
    onClick: (() -> Unit)? = null,
    onClickLabel: String? = null
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .then(
                if (onClick != null) Modifier.clickable(onClickLabel = onClickLabel, role = Role.Button, onClick = onClick)
                else Modifier
            )
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        if (leading != null) {
            leading()
            Spacer(Modifier.width(12.dp))
        }
        Column(modifier = Modifier.weight(1f)) {
            title()
            if (subtitle != null) {
                Spacer(Modifier.height(2.dp))
                subtitle()
            }
        }
        if (trailing != null) {
            Spacer(Modifier.width(8.dp))
            Row(verticalAlignment = Alignment.CenterVertically, content = trailing)
        }
    }
}

@Composable
internal fun RowTitle(text: String, color: Color = TextPrimary, maxLines: Int = 1) {
    Text(text, color = color, fontSize = 15.sp, fontWeight = FontWeight.SemiBold, maxLines = maxLines, overflow = TextOverflow.Ellipsis)
}

@Composable
internal fun RowSubtitle(text: String, color: Color = TextMuted, maxLines: Int = 1) {
    Text(text, color = color, fontSize = 13.sp, lineHeight = 18.sp, maxLines = maxLines, overflow = TextOverflow.Ellipsis)
}

@Composable
internal fun RowDivider(inset: Dp = 16.dp) {
    HorizontalDivider(color = Outline, modifier = Modifier.padding(start = inset))
}

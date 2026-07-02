package com.abyssal.chat.presentation.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.abyssal.chat.presentation.viewmodel.ChatViewModel
import com.abyssal.chat.theme.DeepBlack
import com.abyssal.chat.theme.PureWhite

@Composable
fun CalculatorScreen(viewModel: ChatViewModel) {
    val display by viewModel.calculatorDisplay.collectAsState()
    CalculatorContent(display = display, onInput = viewModel::onCalculatorInput)
}

@Composable
private fun CalculatorContent(
    display: String,
    onInput: (String) -> Unit
) {
    val buttons = listOf(
        listOf("C", "(", ")", "/"),
        listOf("7", "8", "9", "*"),
        listOf("4", "5", "6", "-"),
        listOf("1", "2", "3", "+"),
        listOf("0", ".", "=")
    )

    BoxWithConstraints(
        modifier = Modifier
            .fillMaxSize()
            .background(DeepBlack)
            .statusBarsPadding()
            .navigationBarsPadding()
            .padding(horizontal = 14.dp, vertical = 16.dp)
    ) {
        val buttonHeight = ((maxHeight - 190.dp) / 5f).coerceIn(56.dp, 82.dp)

        Column(
            modifier = Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.Bottom
        ) {
            Text(
                text = display,
                color = PureWhite,
                fontSize = 52.sp,
                fontWeight = FontWeight.Light,
                textAlign = TextAlign.End,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp, vertical = 20.dp)
                    .semantics { contentDescription = "Calculator display" }
            )

            Spacer(modifier = Modifier.height(8.dp))

            buttons.forEach { row ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 5.dp),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    row.forEach { label ->
                        CalculatorButton(
                            label = label,
                            height = buttonHeight,
                            modifier = Modifier.weight(if (label == "0" && row.size == 3) 2f else 1f),
                            onClick = { onInput(label) }
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun CalculatorButton(
    label: String,
    height: androidx.compose.ui.unit.Dp,
    modifier: Modifier = Modifier,
    onClick: () -> Unit
) {
    val isNumber = label.first().isDigit() || label == "."
    val isAction = label == "C" || label == "(" || label == ")"
    val background = when {
        label == "=" -> Color(0xFFF57C00)
        isAction -> Color(0xFF5C5C5C)
        !isNumber -> Color(0xFFF57C00)
        else -> Color(0xFF2E2E2E)
    }

    Box(
        contentAlignment = Alignment.Center,
        modifier = modifier
            .height(height)
            .clip(CircleShape)
            .background(background)
            .semantics { contentDescription = "Calculator $label" }
            .clickable(role = Role.Button, onClick = onClick)
    ) {
        Text(
            text = label,
            color = PureWhite,
            fontSize = 27.sp,
            fontWeight = FontWeight.Normal
        )
    }
}

@Preview
@Composable
private fun CalculatorContentPreview() {
    CalculatorContent(display = "284.6", onInput = {})
}

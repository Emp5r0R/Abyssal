package com.abyssal.chat.presentation.screens

import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextFieldColors
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation

/** All input sources share password semantics; failures never reveal a capability. */
@Composable
internal fun InviteEntryField(
    value: String,
    onValueChange: (String) -> Unit,
    colors: TextFieldColors,
    enabled: Boolean,
    isError: Boolean,
    onNext: () -> Unit,
    modifier: Modifier = Modifier
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text("Abyssal invite") },
        placeholder = { Text("ABY1-... or abyssal:invite:...") },
        colors = colors,
        enabled = enabled,
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        isError = isError,
        keyboardOptions = KeyboardOptions(
            capitalization = KeyboardCapitalization.None,
            autoCorrect = false,
            keyboardType = KeyboardType.Password,
            imeAction = ImeAction.Next
        ),
        keyboardActions = KeyboardActions(onNext = { onNext() }),
        modifier = modifier
    )
}

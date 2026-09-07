package com.abyssal.chat.presentation.screens

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assert
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.performTextInput
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Rule
import org.junit.Test

class InviteEntryFieldTest {
    @get:Rule val compose = createComposeRule()

    @Test fun typedPastedAndScannedValuesStayMaskedAcrossErrorsAndBusyState() {
        val value = mutableStateOf("")
        val error = mutableStateOf(false)
        val enabled = mutableStateOf(true)
        compose.setContent {
            MaterialTheme {
                InviteEntryField(value.value, { value.value = it }, OutlinedTextFieldDefaults.colors(),
                    enabled.value, error.value, {})
            }
        }
        val field = compose.onNode(hasSetTextAction())
        field.performTextInput("ABY1-TYPED-SECRET")
        compose.runOnIdle { assertEquals("ABY1-TYPED-SECRET", value.value) }
        fun assertMasked() {
            field.assert(SemanticsMatcher.keyIsDefined(SemanticsProperties.Password))
            val visible = field.fetchSemanticsNode().config[SemanticsProperties.EditableText].text
            assertFalse(visible.contains("SECRET"))
        }
        assertMasked()
        for (replacement in listOf("ABY1-PASTED-SECRET", "abyssal:invite:SCANNED-SECRET")) {
            compose.runOnIdle { value.value = replacement }
            assertMasked()
            compose.runOnIdle { error.value = true }
            assertMasked()
        }
        compose.runOnIdle { enabled.value = false }
        field.assertIsNotEnabled()
        assertMasked()
    }
}

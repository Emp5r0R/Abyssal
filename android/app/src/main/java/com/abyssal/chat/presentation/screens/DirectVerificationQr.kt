package com.abyssal.chat.presentation.screens

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.MultiFormatWriter
import com.google.zxing.common.BitMatrix
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

private val VERIFICATION_TOKEN_PATTERN =
    Regex("^abyssal:verify:v1:[A-Za-z0-9_-]{43}$")

internal fun isCanonicalVerificationToken(value: String): Boolean =
    VERIFICATION_TOKEN_PATTERN.matches(value)

internal fun verificationQrMatrix(token: String, size: Int = 224): BitMatrix? {
    if (!isCanonicalVerificationToken(token) || size !in 96..1024) return null
    return runCatching {
        MultiFormatWriter().encode(
            token,
            BarcodeFormat.QR_CODE,
            size,
            size,
            mapOf(
                EncodeHintType.CHARACTER_SET to "UTF-8",
                EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
                EncodeHintType.MARGIN to 1
            )
        )
    }.getOrNull()
}

@Composable
internal fun DirectVerificationQr(token: String, modifier: Modifier = Modifier) {
    val matrix = remember(token) { verificationQrMatrix(token) }
    Canvas(
        modifier = modifier
            .size(224.dp)
            .background(Color(0xFFF4FBFF))
            .semantics { contentDescription = "Direct chat verification QR code" }
    ) {
        matrix?.let(::drawQrMatrix)
    }
}

private fun DrawScope.drawQrMatrix(matrix: BitMatrix) {
    val cellWidth = size.width / matrix.width
    val cellHeight = size.height / matrix.height
    for (y in 0 until matrix.height) {
        for (x in 0 until matrix.width) {
            if (matrix[x, y]) {
                drawRect(
                    color = Color(0xFF05090D),
                    topLeft = androidx.compose.ui.geometry.Offset(x * cellWidth, y * cellHeight),
                    size = androidx.compose.ui.geometry.Size(cellWidth, cellHeight)
                )
            }
        }
    }
}

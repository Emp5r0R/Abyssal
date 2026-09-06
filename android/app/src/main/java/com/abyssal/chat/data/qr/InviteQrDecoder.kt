package com.abyssal.chat.data.qr

import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.NotFoundException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.ReaderException
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import java.nio.ByteBuffer
import uniffi.abyssal_core.decodeQrImage
import uniffi.abyssal_core.parseInviteCapsule

internal object InviteQrDecoder {
    const val MAX_TEXT = 2048
    const val MAX_SIDE = 1280

    fun decodeLuminance(bytes: ByteArray, width: Int, height: Int): String? {
        require(width in 1..MAX_SIDE && height in 1..MAX_SIDE)
        require(bytes.size == width * height)
        val reader = QRCodeReader()
        return try {
            val source = PlanarYUVLuminanceSource(bytes, width, height, 0, 0, width, height, false)
            val bitmap = BinaryBitmap(HybridBinarizer(source))
            val result = try { reader.decode(bitmap) }
            catch (_: NotFoundException) {
                // Dense aligned generator output can miss ordinary detection.
                reader.decode(bitmap, mapOf(DecodeHintType.PURE_BARCODE to true))
            }
            try { result.text?.takeIf { it.length in 1..MAX_TEXT } }
            finally { result.rawBytes?.fill(0) }
        } catch (_: ReaderException) {
            null
        } finally {
            reader.reset()
        }
    }

    fun copyPlane(buffer: ByteBuffer, width: Int, height: Int, rowStride: Int, pixelStride: Int): ByteArray {
        require(width in 1..MAX_SIDE && height in 1..MAX_SIDE && rowStride > 0 && pixelStride > 0)
        require((width - 1L) * pixelStride < rowStride)
        val view = buffer.duplicate()
        val start = view.position()
        val last = start.toLong() + (height - 1L) * rowStride + (width - 1L) * pixelStride
        require(last < view.limit())
        return ByteArray(width * height) { index ->
            view.get(start + (index / width) * rowStride + (index % width) * pixelStride)
        }
    }

    fun decodeImage(bytes: ByteArray, mime: String): String? {
        val raster = decodeQrImage(bytes, mime)
        return try { decodeLuminance(raster.luminance, raster.width.toInt(), raster.height.toInt()) }
        finally { raster.luminance.fill(0) }
    }

    fun isVerifiedInvite(value: String, allowDevelopment: Boolean, nowSeconds: Long = System.currentTimeMillis() / 1000): Boolean {
        if (value.length !in 1..MAX_TEXT || nowSeconds < 0) return false
        return try {
            val parsed = parseInviteCapsule(value, nowSeconds.toULong(), allowDevelopment)
            parsed.capability.fill(0)
            parsed.accountContext.fill(0)
            parsed.nodePublicKey.fill(0)
            true
        } catch (_: Exception) { false }
    }
}

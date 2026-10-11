package com.abyssal.chat.data.qr

import android.content.ClipboardManager
import android.content.ContentResolver
import android.content.Context
import android.net.Uri

/** Finds a QR screenshot the user copied, so it can be scanned without saving it first. */
internal object ClipboardQrImage {
    /** The content URI of the first image on the clipboard, or null when there is none. */
    fun imageUri(context: Context): Uri? {
        val clipboard = context.getSystemService(ClipboardManager::class.java) ?: return null
        val clip = clipboard.primaryClip ?: return null
        val describedAsImage = clip.description?.hasMimeType("image/*") == true
        for (index in 0 until clip.itemCount) {
            val uri = clip.getItemAt(index).uri ?: continue
            if (uri.scheme != ContentResolver.SCHEME_CONTENT) continue
            val type = runCatching { context.contentResolver.getType(uri) }.getOrNull()
            if (describedAsImage || type?.startsWith("image/") == true) return uri
        }
        return null
    }
}

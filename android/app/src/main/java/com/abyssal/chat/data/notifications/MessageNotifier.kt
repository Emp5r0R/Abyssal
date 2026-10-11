package com.abyssal.chat.data.notifications

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.abyssal.chat.R
import com.abyssal.chat.domain.model.NotificationContent

/** The OS notification surface, behind an interface so tests can replace it. */
interface MessageNotifier {
    /** True when the system allows this app to post notifications. */
    fun canNotify(): Boolean
    fun show(chatId: String, content: NotificationContent)
    /** Removes every message notification, for example on lock or sign-out. */
    fun cancelAll()
}

class AndroidMessageNotifier(context: Context) : MessageNotifier {
    private val appContext = context.applicationContext
    private val manager = NotificationManagerCompat.from(appContext)

    override fun canNotify(): Boolean {
        val permitted = Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
            ContextCompat.checkSelfPermission(appContext, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
        return permitted && manager.areNotificationsEnabled()
    }

    override fun show(chatId: String, content: NotificationContent) {
        if (!canNotify()) return
        ensureChannel()
        val launch = appContext.packageManager.getLaunchIntentForPackage(appContext.packageName)
            ?.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        val open = launch?.let {
            PendingIntent.getActivity(appContext, 0, it, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        }
        // The lock screen gets the generic version unless the user unlocks the device.
        val lockScreen = NotificationCompat.Builder(appContext, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("Abyssal")
            .setContentText("New message")
            .build()
        val notification = NotificationCompat.Builder(appContext, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(content.title)
            .setContentText(content.body)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setPublicVersion(lockScreen)
            .setAutoCancel(true)
            .setOnlyAlertOnce(false)
            .apply { if (open != null) setContentIntent(open) }
            .build()
        try {
            manager.notify(TAG, chatId.hashCode(), notification)
        } catch (_: SecurityException) {
            // Permission was revoked between the check and the post.
        }
    }

    override fun cancelAll() {
        manager.cancelAll()
    }

    private fun ensureChannel() {
        val system = appContext.getSystemService(NotificationManager::class.java) ?: return
        if (system.getNotificationChannel(CHANNEL_ID) != null) return
        system.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "Messages", NotificationManager.IMPORTANCE_DEFAULT).apply {
                description = "New messages while Abyssal is in the background"
                lockscreenVisibility = android.app.Notification.VISIBILITY_PRIVATE
            }
        )
    }

    private companion object {
        const val CHANNEL_ID = "abyssal_messages"
        const val TAG = "abyssal"
    }
}

package com.phonelink.receiver

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import com.phonelink.service.ConnectionForegroundService
import com.phonelink.storage.SecureStorage
import com.phonelink.ui.MainActivity

/**
 * AND-9: Android Boot-Persistence & Reboot Recovery.
 *
 * Listens for system boot completion and automatically resumes the connection service
 * if enabled by the user and paired.
 *
 * Security / Compliance Invariants (ARCH-4 / AND-9):
 * 1. Requests only RECEIVE_BOOT_COMPLETED (minimum necessary permission).
 * 2. Never employs undocumented or OEM-specific private hacks to bypass background start restrictions.
 * 3. If OS/OEM restrictions prevent background start, visibly degrades by posting a user prompt notification.
 */
class BootReceiver : BroadcastReceiver() {

    companion object {
        const val BOOT_RECOVERY_CHANNEL_ID = "phonelink_boot_recovery"
        const val BOOT_PROMPT_NOTIFICATION_ID = 1002

        val SUPPORTED_BOOT_ACTIONS = setOf(
            Intent.ACTION_BOOT_COMPLETED,
            "android.intent.action.QUICKBOOT_POWERON",
            Intent.ACTION_MY_PACKAGE_REPLACED
        )
    }

    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        if (action !in SUPPORTED_BOOT_ACTIONS) {
            return
        }

        val secureStorage = SecureStorage.fromContext(context)

        // 1. Check if user enabled auto-start on boot
        if (!secureStorage.isAutoStartOnBoot()) {
            return
        }

        // 2. Check if device has an established pairing or configured relay
        if (!secureStorage.isPaired()) {
            return
        }

        // 3. Attempt to resume ConnectionForegroundService
        try {
            ConnectionForegroundService.start(context)
        } catch (_: Throwable) {
            // Graceful degradation: If OEM or OS background restriction blocks start,
            // prompt the user visibly rather than attempting undocumented workarounds.
            notifyUserToResume(context)
        }
    }

    fun notifyUserToResume(context: Context) {
        val notificationManager =
            context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                BOOT_RECOVERY_CHANNEL_ID,
                "PhoneLink Boot Recovery",
                NotificationManager.IMPORTANCE_DEFAULT
            ).apply {
                description = "Prompts user to reopen PhoneLink when OEM battery restrictions block auto-start"
            }
            notificationManager.createNotificationChannel(channel)
        }

        val openIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            context,
            0,
            openIntent,
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            } else {
                PendingIntent.FLAG_UPDATE_CURRENT
            }
        )

        val notification = NotificationCompat.Builder(context, BOOT_RECOVERY_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentTitle("PhoneLink Connection Paused")
            .setContentText("Tap to reopen PhoneLink and resume background connection.")
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .build()

        notificationManager.notify(BOOT_PROMPT_NOTIFICATION_ID, notification)
    }
}

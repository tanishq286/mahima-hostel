package com.deepwarden.app.intruder

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.admin.DeviceAdminReceiver
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import com.deepwarden.app.R

/**
 * INTRUDER ALERT (the working, honest version of "intruder selfie").
 *
 * As an active Device Admin with the watch-login policy, Android calls
 * [onPasswordFailed] every time someone enters the wrong PIN/pattern/password.
 * We log it and fire an instant alert.
 *
 * Why no photo: since Android 9, apps cannot use the camera from the
 * background or lock screen — the exact rule that stops spyware secretly
 * photographing you. So a true selfie is impossible without root. Detecting
 * and alerting on the intrusion attempt is the real protection we CAN provide.
 */
class DeepWardenAdminReceiver : DeviceAdminReceiver() {

    override fun onPasswordFailed(context: Context, intent: Intent) {
        super.onPasswordFailed(context, intent)
        IntruderLog.recordFailure(context)
        val count = IntruderLog.totalFailures(context)
        notify(
            context,
            "⚠ Failed unlock attempt detected",
            "Someone entered the wrong screen lock ($count in a row). If this wasn't you, your phone may be in someone else's hands.",
        )
    }

    override fun onPasswordSucceeded(context: Context, intent: Intent) {
        super.onPasswordSucceeded(context, intent)
        IntruderLog.resetOnSuccess(context)
    }

    override fun onEnabled(context: Context, intent: Intent) {
        super.onEnabled(context, intent)
        notify(context, "Intruder Alert active", "DeepWarden will alert you to failed unlock attempts.")
    }

    private fun notify(context: Context, title: String, body: String) {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "Intruder alerts", NotificationManager.IMPORTANCE_HIGH).apply {
                description = "Alerts when someone fails to unlock your phone."
            }
        )
        nm.notify(
            INTRUDER_NOTIF_ID,
            NotificationCompat.Builder(context, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(title)
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(body))
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setAutoCancel(true)
                .build()
        )
    }

    companion object {
        private const val CHANNEL_ID = "deepwarden_intruder"
        private const val INTRUDER_NOTIF_ID = 7100
    }
}

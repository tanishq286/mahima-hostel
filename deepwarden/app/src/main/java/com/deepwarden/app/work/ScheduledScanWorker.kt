package com.deepwarden.app.work

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import androidx.core.app.NotificationCompat
import androidx.hilt.work.HiltWorker
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.deepwarden.app.R
import com.deepwarden.app.core.Severity
import com.deepwarden.app.detection.engine.ScanOrchestrator
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import java.util.concurrent.TimeUnit

/**
 * Scheduled background deep scan via WorkManager.
 * Notifies ONLY when something HIGH/CRITICAL is new — no fear-spam.
 */
@HiltWorker
class ScheduledScanWorker @AssistedInject constructor(
    @Assisted appContext: Context,
    @Assisted params: WorkerParameters,
    private val orchestrator: ScanOrchestrator,
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        val result = runCatching { orchestrator.runFullScan(emergency = false) }
            .getOrElse { return Result.retry() }

        val serious = result.findings.count { it.severity >= Severity.HIGH }
        if (serious > 0) notify(serious, result.deviceThreatScore.overall)
        return Result.success()
    }

    private fun notify(seriousCount: Int, score: Int) {
        val nm = applicationContext.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "Scan alerts", NotificationManager.IMPORTANCE_DEFAULT).apply {
                description = "Alerts only when a scheduled scan finds something serious."
            }
        )
        val notification = NotificationCompat.Builder(applicationContext, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle("DeepWarden found $seriousCount item(s) worth attention")
            .setContentText("Device score $score/100. Open for the safe, no-data-loss action plan.")
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .build()
        nm.notify(NOTIFICATION_ID, notification)
    }

    companion object {
        private const val CHANNEL_ID = "deepwarden_scan_alerts"
        private const val NOTIFICATION_ID = 7001
        private const val WORK_NAME = "deepwarden_scheduled_scan"

        /** hours == 0 disables scheduling. */
        fun schedule(context: Context, hours: Int) {
            val wm = WorkManager.getInstance(context)
            if (hours <= 0) {
                wm.cancelUniqueWork(WORK_NAME)
                return
            }
            val request = PeriodicWorkRequestBuilder<ScheduledScanWorker>(hours.toLong(), TimeUnit.HOURS)
                .setConstraints(Constraints.Builder().setRequiresBatteryNotLow(true).build())
                .build()
            wm.enqueueUniquePeriodicWork(WORK_NAME, ExistingPeriodicWorkPolicy.UPDATE, request)
        }
    }
}

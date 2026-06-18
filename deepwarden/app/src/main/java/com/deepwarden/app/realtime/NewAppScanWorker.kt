package com.deepwarden.app.realtime

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import androidx.core.app.NotificationCompat
import androidx.hilt.work.HiltWorker
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.deepwarden.app.R
import com.deepwarden.app.data.cloud.VirusTotalClient
import com.deepwarden.app.data.datastore.SettingsRepository
import com.deepwarden.app.detection.common.InstallerTrust
import com.deepwarden.app.detection.layer2.PermissionScoring
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import kotlinx.coroutines.flow.first
import java.io.File

/**
 * ============================================================================
 *  REAL-TIME PROTECTION — instant check of every newly installed app.
 * ============================================================================
 *
 * Triggered by [NewInstallReceiver] the moment Android reports a new package.
 * This is the headline "live antivirus" behaviour: you don't have to remember
 * to scan — the moment a risky app is installed, you get an alert.
 *
 * It is deliberately LIGHT (runs off a broadcast): trusted-store apps are
 * ignored, and only genuinely risky sideloaded apps raise a notification. If
 * the user enabled cloud reputation, it also does a single VirusTotal lookup
 * for a professional-grade verdict on the new app.
 */
@HiltWorker
class NewAppScanWorker @AssistedInject constructor(
    @Assisted private val appContext: Context,
    @Assisted params: WorkerParameters,
    private val settings: SettingsRepository,
    private val vt: VirusTotalClient,
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        if (!settings.realtimeProtection.first()) return Result.success()
        val pkgName = inputData.getString(KEY_PACKAGE) ?: return Result.success()
        val pm = appContext.packageManager

        val info: PackageInfo = runCatching {
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS).firstOrNull { it.packageName == pkgName }
                ?: pm.getPackageInfo(pkgName, PackageManager.GET_PERMISSIONS)
        }.getOrNull() ?: return Result.success()

        val app = info.applicationInfo ?: return Result.success()
        if (app.flags and ApplicationInfo.FLAG_SYSTEM != 0) return Result.success()
        if (pkgName == appContext.packageName) return Result.success()

        val label = pm.getApplicationLabel(app).toString()
        val source = InstallerTrust.of(appContext, pkgName)

        // Apps from a vetted store are trusted; we don't nag about those.
        if (source.trusted) return Result.success()

        val granted = grantedPermissions(info)
        val score = PermissionScoring.score(granted)
        val hasLauncher = pm.getLaunchIntentForPackage(pkgName) != null
        val hidden = !hasLauncher && granted.any { it in SURVEILLANCE }

        // Optional cloud verdict for the strongest signal.
        var cloudMalicious = 0
        val key = settings.vtApiKey.first()
        if (settings.cloudRepEnabled.first() && key.isNotBlank()) {
            val apk = app.sourceDir?.let { File(it) }
            val hash = apk?.let { vt.sha256(it) }
            if (hash != null) {
                val verdict = vt.lookup(hash, key)
                cloudMalicious = verdict.malicious
            }
        }

        val reasons = buildList {
            if (source.viaAdb) add("installed via USB/ADB (a planting method)")
            else add("installed outside any app store")
            if (score.normalised >= PermissionScoring.BAND_HIGH) add("high-risk permission set (${score.normalised}/100)")
            if (hidden) add("powerful permissions but no app icon")
            if (cloudMalicious > 0) add("flagged by $cloudMalicious antivirus engines")
        }

        val risky = cloudMalicious > 0 ||
            score.normalised >= PermissionScoring.BAND_HIGH ||
            hidden ||
            (source.viaAdb && score.normalised >= PermissionScoring.BAND_MEDIUM)

        if (risky) {
            notify(label, reasons, severe = cloudMalicious > 0 || score.normalised >= PermissionScoring.BAND_EXTREME)
        }
        return Result.success()
    }

    private fun grantedPermissions(pkg: PackageInfo): List<String> {
        val requested = pkg.requestedPermissions ?: return emptyList()
        val flags = pkg.requestedPermissionsFlags ?: return requested.toList()
        return requested.filterIndexed { i, _ ->
            flags.getOrElse(i) { 0 } and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0
        }
    }

    private fun notify(label: String, reasons: List<String>, severe: Boolean) {
        val nm = appContext.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "Real-time protection", NotificationManager.IMPORTANCE_HIGH).apply {
                description = "Alerts the moment a risky app is installed."
            }
        )
        val title = if (severe) "⚠ Dangerous app just installed: $label" else "New app worth checking: $label"
        val body = "Why: ${reasons.joinToString("; ")}. Open DeepWarden to review and remove it safely."
        nm.notify(
            (label.hashCode() and 0xffffff),
            NotificationCompat.Builder(appContext, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(title)
                .setContentText("Tap to review in DeepWarden")
                .setStyle(NotificationCompat.BigTextStyle().bigText(body))
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setAutoCancel(true)
                .build()
        )
    }

    companion object {
        const val KEY_PACKAGE = "package_name"
        private const val CHANNEL_ID = "deepwarden_realtime"
        private val SURVEILLANCE = setOf(
            "android.permission.READ_SMS", "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA", "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission.READ_CALL_LOG",
        )
    }
}

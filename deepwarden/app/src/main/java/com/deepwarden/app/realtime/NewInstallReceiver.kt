package com.deepwarden.app.realtime

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.workDataOf

/**
 * Catches the system's "a new package was installed" broadcast and hands the
 * package off to [NewAppScanWorker] for an instant risk check.
 *
 * We keep the receiver trivial (just enqueue work) so it returns immediately —
 * the real analysis runs in WorkManager, which is the Android-correct way to
 * do background work from a broadcast. Updates/reinstalls (EXTRA_REPLACING)
 * are ignored; we only check genuinely new installs.
 */
class NewInstallReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_PACKAGE_ADDED) return
        if (intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) return
        val pkg = intent.data?.schemeSpecificPart ?: return

        val request = OneTimeWorkRequestBuilder<NewAppScanWorker>()
            .setInputData(workDataOf(NewAppScanWorker.KEY_PACKAGE to pkg))
            .build()
        WorkManager.getInstance(context.applicationContext).enqueue(request)
    }
}

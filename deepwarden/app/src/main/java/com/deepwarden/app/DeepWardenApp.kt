package com.deepwarden.app

import android.app.Application
import androidx.hilt.work.HiltWorkerFactory
import androidx.work.Configuration
import com.deepwarden.app.data.datastore.SettingsRepository
import com.deepwarden.app.data.threatintel.ThreatIntelRepository
import dagger.hilt.android.HiltAndroidApp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * DeepWarden application.
 *
 * "Sees deeper. Deletes nothing."
 *
 * Provides the Hilt-aware WorkManager factory so scheduled deep scans can
 * inject the full detection engine, and refreshes self-updating threat
 * intelligence on launch when the user has enabled it.
 */
@HiltAndroidApp
class DeepWardenApp : Application(), Configuration.Provider {

    @Inject lateinit var workerFactory: HiltWorkerFactory
    @Inject lateinit var threatIntel: ThreatIntelRepository
    @Inject lateinit var settings: SettingsRepository

    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override val workManagerConfiguration: Configuration
        get() = Configuration.Builder()
            .setWorkerFactory(workerFactory)
            .build()

    override fun onCreate() {
        super.onCreate()
        // Pull the latest detection rules in the background (opt-in, no user
        // data sent). Failures are silent — detection still works fully offline.
        appScope.launch {
            if (settings.intelAutoUpdate.first()) {
                runCatching { threatIntel.fetchUpdate() }
            }
        }
    }
}

package com.deepwarden.app

import android.app.Application
import androidx.hilt.work.HiltWorkerFactory
import androidx.work.Configuration
import dagger.hilt.android.HiltAndroidApp
import javax.inject.Inject

/**
 * DeepWarden application.
 *
 * "Sees deeper. Deletes nothing."
 *
 * Provides the Hilt-aware WorkManager factory so scheduled deep scans can
 * inject the full detection engine.
 */
@HiltAndroidApp
class DeepWardenApp : Application(), Configuration.Provider {

    @Inject lateinit var workerFactory: HiltWorkerFactory

    override val workManagerConfiguration: Configuration
        get() = Configuration.Builder()
            .setWorkerFactory(workerFactory)
            .build()
}

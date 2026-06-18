package com.deepwarden.app.data.datastore

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import javax.inject.Inject
import javax.inject.Singleton

private val Context.dataStore by preferencesDataStore(name = "deepwarden_settings")

/**
 * User preferences. Note the defaults — they ARE the product philosophy:
 *   Safe Mode ON, telemetry OFF, intel auto-update OFF, content layer OFF.
 */
@Singleton
class SettingsRepository @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    private object Keys {
        /** Safe Mode (No Data Loss): hides every non-reversible suggestion. DEFAULT ON. */
        val SAFE_MODE = booleanPreferencesKey("safe_mode")
        val ONBOARDING_DONE = booleanPreferencesKey("onboarding_done")
        /** Anonymous IOC contribution — strictly opt-in, default OFF. */
        val CONTRIBUTE_IOC = booleanPreferencesKey("contribute_ioc")
        /** Optional threat-intel fetch — default OFF (100% local otherwise). */
        val INTEL_AUTOUPDATE = booleanPreferencesKey("intel_autoupdate")
        /** Layer 6 content scanning consent — default OFF. */
        val CONTENT_LAYER_ENABLED = booleanPreferencesKey("content_layer")
        /** Scheduled background scan interval in hours; 0 = disabled. */
        val SCHEDULED_SCAN_HOURS = intPreferencesKey("scheduled_scan_hours")
        /** Layer 7 cloud reputation (VirusTotal) — default OFF. */
        val CLOUD_REP_ENABLED = booleanPreferencesKey("cloud_rep_enabled")
        /** User's own VirusTotal API key — stored locally only, never shipped. */
        val VT_API_KEY = stringPreferencesKey("vt_api_key")
        /** Real-time protection: instantly check each newly installed app. Default ON. */
        val REALTIME_PROTECTION = booleanPreferencesKey("realtime_protection")
    }

    val safeMode: Flow<Boolean> = context.dataStore.data.map { it[Keys.SAFE_MODE] ?: true }
    val onboardingDone: Flow<Boolean> = context.dataStore.data.map { it[Keys.ONBOARDING_DONE] ?: false }
    val contributeIoc: Flow<Boolean> = context.dataStore.data.map { it[Keys.CONTRIBUTE_IOC] ?: false }
    val intelAutoUpdate: Flow<Boolean> = context.dataStore.data.map { it[Keys.INTEL_AUTOUPDATE] ?: false }
    val contentLayerEnabled: Flow<Boolean> = context.dataStore.data.map { it[Keys.CONTENT_LAYER_ENABLED] ?: false }
    val scheduledScanHours: Flow<Int> = context.dataStore.data.map { it[Keys.SCHEDULED_SCAN_HOURS] ?: 0 }
    val cloudRepEnabled: Flow<Boolean> = context.dataStore.data.map { it[Keys.CLOUD_REP_ENABLED] ?: false }
    val vtApiKey: Flow<String> = context.dataStore.data.map { it[Keys.VT_API_KEY] ?: "" }
    val realtimeProtection: Flow<Boolean> = context.dataStore.data.map { it[Keys.REALTIME_PROTECTION] ?: true }

    suspend fun setSafeMode(enabled: Boolean) = context.dataStore.edit { it[Keys.SAFE_MODE] = enabled }
    suspend fun setOnboardingDone() = context.dataStore.edit { it[Keys.ONBOARDING_DONE] = true }
    suspend fun setContributeIoc(enabled: Boolean) = context.dataStore.edit { it[Keys.CONTRIBUTE_IOC] = enabled }
    suspend fun setIntelAutoUpdate(enabled: Boolean) = context.dataStore.edit { it[Keys.INTEL_AUTOUPDATE] = enabled }
    suspend fun setContentLayerEnabled(enabled: Boolean) = context.dataStore.edit { it[Keys.CONTENT_LAYER_ENABLED] = enabled }
    suspend fun setScheduledScanHours(hours: Int) = context.dataStore.edit { it[Keys.SCHEDULED_SCAN_HOURS] = hours }
    suspend fun setCloudRepEnabled(enabled: Boolean) = context.dataStore.edit { it[Keys.CLOUD_REP_ENABLED] = enabled }
    suspend fun setVtApiKey(key: String) = context.dataStore.edit { it[Keys.VT_API_KEY] = key.trim() }
    suspend fun setRealtimeProtection(enabled: Boolean) = context.dataStore.edit { it[Keys.REALTIME_PROTECTION] = enabled }
}

package com.deepwarden.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.deepwarden.app.data.datastore.SettingsRepository
import com.deepwarden.app.ui.theme.DwColors
import com.deepwarden.app.work.ScheduledScanWorker
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import android.content.Context
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class SettingsViewModel @Inject constructor(
    private val settings: SettingsRepository,
    @ApplicationContext private val appContext: Context,
) : ViewModel() {
    val safeMode = settings.safeMode.stateIn(viewModelScope, SharingStarted.Eagerly, true)
    val onboardingDone = settings.onboardingDone
    val contributeIoc = settings.contributeIoc.stateIn(viewModelScope, SharingStarted.Eagerly, false)
    val intelAutoUpdate = settings.intelAutoUpdate.stateIn(viewModelScope, SharingStarted.Eagerly, false)
    val contentLayer = settings.contentLayerEnabled.stateIn(viewModelScope, SharingStarted.Eagerly, false)
    val scheduledHours = settings.scheduledScanHours.stateIn(viewModelScope, SharingStarted.Eagerly, 0)

    fun completeOnboarding() = viewModelScope.launch { settings.setOnboardingDone() }
    fun setSafeMode(v: Boolean) = viewModelScope.launch { settings.setSafeMode(v) }
    fun setContributeIoc(v: Boolean) = viewModelScope.launch { settings.setContributeIoc(v) }
    fun setIntelAutoUpdate(v: Boolean) = viewModelScope.launch { settings.setIntelAutoUpdate(v) }
    fun setContentLayer(v: Boolean) = viewModelScope.launch { settings.setContentLayerEnabled(v) }
    fun setScheduledScan(enabled: Boolean) = viewModelScope.launch {
        val hours = if (enabled) 24 else 0
        settings.setScheduledScanHours(hours)
        ScheduledScanWorker.schedule(appContext, hours)
    }
}

/** Settings — every privacy-relevant toggle defaults to the protective side. */
@Composable
fun SettingsScreen(vm: SettingsViewModel = hiltViewModel()) {
    val safeMode by vm.safeMode.collectAsState()
    val contribute by vm.contributeIoc.collectAsState()
    val autoUpdate by vm.intelAutoUpdate.collectAsState()
    val contentLayer by vm.contentLayer.collectAsState()
    val scheduled by vm.scheduledHours.collectAsState()

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(18.dp),
    ) {
        Text("Settings", style = MaterialTheme.typography.headlineMedium)

        Toggle(
            "Safe Mode (No Data Loss)", safeMode, vm::setSafeMode,
            "ON: only fully reversible actions are ever suggested. Destructive options (uninstall, clear data) are hidden and replaced with safe equivalents. Recommended for everyone.",
        )
        Toggle(
            "Daily background deep scan", scheduled > 0, vm::setScheduledScan,
            "Scans once a day on battery-friendly conditions. Notifies you ONLY for high/critical findings.",
        )
        Toggle(
            "Message analysis (Layer 6)", contentLayer, vm::setContentLayer,
            "Optional on-device SMS phishing scan. Message text never leaves the phone and is never stored. Requires the SMS permission, revocable anytime.",
        )
        Toggle(
            "Threat-intel auto-update", autoUpdate, vm::setIntelAutoUpdate,
            "OFF by default — DeepWarden is 100% local. When ON: fetches a signed rules file (no device data is sent; a plain HTTPS download).",
        )
        Toggle(
            "Anonymous IOC contribution", contribute, vm::setContributeIoc,
            "OFF by default. When ON: shares ONLY anonymous indicator hashes of confirmed threats (never apps lists, never content, never identifiers) to improve the shared rules.",
        )

        Text(
            "DeepWarden never sells data, has no accounts, and works fully offline. The two network toggles above are the only network features in the app.",
            style = MaterialTheme.typography.bodySmall, color = DwColors.TextSecondary,
        )
    }
}

@Composable
private fun Toggle(title: String, value: Boolean, onChange: (Boolean) -> Unit, description: String) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text(title, style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
            Switch(checked = value, onCheckedChange = onChange)
        }
        Text(description, style = MaterialTheme.typography.bodySmall, color = DwColors.TextSecondary)
    }
}

package com.deepwarden.app.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.deepwarden.app.callblock.CallBlockPrefs
import com.deepwarden.app.data.datastore.SettingsRepository
import com.deepwarden.app.intruder.DeepWardenAdminReceiver
import com.deepwarden.app.intruder.IntruderLog
import com.deepwarden.app.ui.theme.DwColors
import com.deepwarden.app.work.ScheduledScanWorker
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import android.app.admin.DevicePolicyManager
import android.app.role.RoleManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Build
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
    val cloudRep = settings.cloudRepEnabled.stateIn(viewModelScope, SharingStarted.Eagerly, false)
    val vtApiKey = settings.vtApiKey.stateIn(viewModelScope, SharingStarted.Eagerly, "")
    val realtime = settings.realtimeProtection.stateIn(viewModelScope, SharingStarted.Eagerly, true)

    fun completeOnboarding() = viewModelScope.launch { settings.setOnboardingDone() }
    fun setSafeMode(v: Boolean) = viewModelScope.launch { settings.setSafeMode(v) }
    fun setContributeIoc(v: Boolean) = viewModelScope.launch { settings.setContributeIoc(v) }
    fun setIntelAutoUpdate(v: Boolean) = viewModelScope.launch { settings.setIntelAutoUpdate(v) }
    fun setContentLayer(v: Boolean) = viewModelScope.launch { settings.setContentLayerEnabled(v) }
    fun setCloudRep(v: Boolean) = viewModelScope.launch { settings.setCloudRepEnabled(v) }
    fun setVtApiKey(v: String) = viewModelScope.launch { settings.setVtApiKey(v) }
    fun setRealtime(v: Boolean) = viewModelScope.launch { settings.setRealtimeProtection(v) }
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
    val cloudRep by vm.cloudRep.collectAsState()
    val vtKey by vm.vtApiKey.collectAsState()
    val realtime by vm.realtime.collectAsState()

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(18.dp),
    ) {
        Text("Settings", style = MaterialTheme.typography.headlineMedium)

        Toggle(
            "Real-time protection", realtime, vm::setRealtime,
            "ON: the moment any new app is installed, DeepWarden checks it instantly and alerts you if it looks risky — like a live antivirus. Trusted Play Store apps are ignored; only suspicious sideloaded apps trigger an alert.",
        )

        // ---- Cloud reputation (Layer 7) -----------------------------------
        Toggle(
            "Cloud reputation — VirusTotal (Layer 7)", cloudRep, vm::setCloudRep,
            "The strongest detection DeepWarden offers: checks your sideloaded apps against 70+ antivirus engines worldwide. Only the app's hash is sent — never the app, never personal data. Needs your own free API key below.",
        )
        if (cloudRep) {
            val visual = if (vtKey.isBlank()) VisualTransformation.None else PasswordVisualTransformation()
            OutlinedTextField(
                value = vtKey,
                onValueChange = vm::setVtApiKey,
                modifier = Modifier.fillMaxWidth(),
                label = { Text("VirusTotal API key") },
                singleLine = true,
                visualTransformation = visual,
            )
            Text(
                "Get a free key: virustotal.com → sign up → your profile → API key. It is stored only on this phone. " +
                    if (vtKey.isBlank()) "Paste it here to activate cloud checks." else "Key saved ✓ — cloud checks active on the next scan.",
                style = MaterialTheme.typography.bodySmall,
                color = if (vtKey.isBlank()) DwColors.WarnOrange else DwColors.CalmGreen,
            )
        }

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

        DefenseControls()

        Text(
            "DeepWarden never sells data, has no accounts, and works fully offline. The network features above are the only ones in the app.",
            style = MaterialTheme.typography.bodySmall, color = DwColors.TextSecondary,
        )
    }
}

/**
 * Call blocking + Intruder Alert controls. Kept honest: call blocking uses the
 * official screening role; intruder alert uses a watch-login device admin that
 * has NO power to lock or wipe the phone.
 */
@Composable
private fun DefenseControls() {
    val context = LocalContext.current

    // ---- Call blocking -----------------------------------------------------
    var blockHidden by remember { mutableStateOf(CallBlockPrefs.blockHidden(context)) }
    var blocked by remember { mutableStateOf(CallBlockPrefs.blockedNumbers(context).toList()) }
    var newNumber by remember { mutableStateOf("") }
    val roleLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { /* result handled by system; nothing to do */ }

    Card(colors = CardDefaults.cardColors(containerColor = DwColors.Surface)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Call blocking", style = MaterialTheme.typography.titleSmall, color = DwColors.ElectricBlue)
            Text(
                "Block spam, hidden and blacklisted numbers automatically using Android's official call-screening. Grant the role once:",
                style = MaterialTheme.typography.bodySmall, color = DwColors.TextSecondary,
            )
            Button(
                onClick = {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        val rm = context.getSystemService(RoleManager::class.java)
                        if (rm != null && rm.isRoleAvailable(RoleManager.ROLE_CALL_SCREENING)) {
                            runCatching { roleLauncher.launch(rm.createRequestRoleIntent(RoleManager.ROLE_CALL_SCREENING)) }
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Set DeepWarden as call screener") }

            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text("Block hidden / unknown (no-number) calls", style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
                Switch(checked = blockHidden, onCheckedChange = {
                    blockHidden = it; CallBlockPrefs.setBlockHidden(context, it)
                })
            }

            OutlinedTextField(
                value = newNumber,
                onValueChange = { newNumber = it },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Add number to block") },
                singleLine = true,
            )
            OutlinedButton(
                onClick = {
                    CallBlockPrefs.addBlocked(context, newNumber)
                    blocked = CallBlockPrefs.blockedNumbers(context).toList()
                    newNumber = ""
                },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Block this number") }

            if (blocked.isNotEmpty()) {
                Text("Blocked numbers:", style = MaterialTheme.typography.labelMedium, color = DwColors.TextSecondary)
                blocked.forEach { num ->
                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
                        Text(num, style = MaterialTheme.typography.bodyMedium)
                        TextButton(onClick = {
                            CallBlockPrefs.removeBlocked(context, num)
                            blocked = CallBlockPrefs.blockedNumbers(context).toList()
                        }) { Text("Remove") }
                    }
                }
            }
        }
    }

    // ---- Intruder Alert ----------------------------------------------------
    var events by remember { mutableStateOf(IntruderLog.recentEvents(context)) }
    val adminLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { events = IntruderLog.recentEvents(context) }

    Card(colors = CardDefaults.cardColors(containerColor = DwColors.Surface)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Intruder Alert", style = MaterialTheme.typography.titleSmall, color = DwColors.ElectricBlue)
            Text(
                "Detects when someone enters the wrong screen lock and alerts you instantly. " +
                    "Note: Android blocks apps from using the camera while locked, so a secret \"selfie\" of the intruder is not possible on modern phones without root — DeepWarden alerts you to the attempt instead. It can never lock or wipe your phone.",
                style = MaterialTheme.typography.bodySmall, color = DwColors.TextSecondary,
            )
            Button(
                onClick = {
                    val comp = ComponentName(context, DeepWardenAdminReceiver::class.java)
                    val intent = Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN)
                        .putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, comp)
                        .putExtra(
                            DevicePolicyManager.EXTRA_ADD_EXPLANATION,
                            "Enable Intruder Alert: DeepWarden will warn you about failed unlock attempts. It only watches logins — it cannot lock or erase your phone.",
                        )
                    runCatching { adminLauncher.launch(intent) }
                },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Enable Intruder Alert") }

            if (events.isNotEmpty()) {
                Text("Recent failed unlocks:", style = MaterialTheme.typography.labelMedium, color = DwColors.WarnOrange)
                events.forEach { e ->
                    Text("• $e", style = MaterialTheme.typography.bodySmall, color = DwColors.TextSecondary)
                }
                TextButton(onClick = { IntruderLog.clear(context); events = emptyList() }) { Text("Clear log") }
            } else {
                Text("No failed unlock attempts recorded.", style = MaterialTheme.typography.bodySmall, color = DwColors.CalmGreen)
            }
        }
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

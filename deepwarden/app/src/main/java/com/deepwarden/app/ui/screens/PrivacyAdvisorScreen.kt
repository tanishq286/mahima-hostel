package com.deepwarden.app.ui.screens

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.deepwarden.app.ui.theme.DwColors
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

/**
 * ============================================================================
 *  PRIVACY ADVISOR — "which apps can watch me?" (Quick Heal-style paid feature)
 * ============================================================================
 *
 * Groups installed apps by the SENSITIVE permission they hold, so the user can
 * see at a glance "these 4 apps can read my SMS", "these 3 can use my camera".
 * Tapping an app opens its system settings to revoke access. 100% local, just
 * PackageManager — no network, no special permissions.
 */
@HiltViewModel
class PrivacyAdvisorViewModel @Inject constructor(
    @ApplicationContext private val context: Context,
) : ViewModel() {

    data class AppRef(val label: String, val pkg: String)
    data class PermissionGroup(
        val title: String,
        val why: String,
        val apps: List<AppRef>,
        val sensitivity: Int, // higher = more sensitive (sort order)
    )

    private val _groups = MutableStateFlow<List<PermissionGroup>>(emptyList())
    val groups = _groups.asStateFlow()

    init { load() }

    private fun load() {
        viewModelScope.launch {
            _groups.value = withContext(Dispatchers.Default) { build() }
        }
    }

    private fun build(): List<PermissionGroup> {
        val pm = context.packageManager
        val packages = runCatching {
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        }.getOrDefault(emptyList())

        // permission-string -> friendly group definition
        val defs = listOf(
            GroupDef("Location", "Apps that can track where you are", 100,
                setOf("android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION")),
            GroupDef("Microphone", "Apps that can record audio", 95,
                setOf("android.permission.RECORD_AUDIO")),
            GroupDef("Camera", "Apps that can take photos/video", 90,
                setOf("android.permission.CAMERA")),
            GroupDef("Read your SMS", "Apps that can read your text messages and OTPs", 98,
                setOf("android.permission.READ_SMS", "android.permission.RECEIVE_SMS")),
            GroupDef("Send SMS", "Apps that can send texts (premium-fraud risk)", 85,
                setOf("android.permission.SEND_SMS")),
            GroupDef("Contacts", "Apps that can read your contacts", 70,
                setOf("android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS")),
            GroupDef("Call log", "Apps that can see who you called", 75,
                setOf("android.permission.READ_CALL_LOG", "android.permission.PROCESS_OUTGOING_CALLS")),
            GroupDef("Phone", "Apps that can read phone state or place calls", 60,
                setOf("android.permission.READ_PHONE_STATE", "android.permission.CALL_PHONE", "android.permission.ANSWER_PHONE_CALLS")),
            GroupDef("Draw over other apps", "Apps that can overlay screens (phishing/clickjacking risk)", 80,
                setOf("android.permission.SYSTEM_ALERT_WINDOW")),
            GroupDef("Files & photos", "Apps that can read your storage", 50,
                setOf("android.permission.READ_EXTERNAL_STORAGE", "android.permission.READ_MEDIA_IMAGES", "android.permission.READ_MEDIA_VIDEO")),
        )

        val result = defs.map { def ->
            val apps = packages.mapNotNull { pkg ->
                val app = pkg.applicationInfo ?: return@mapNotNull null
                if (app.flags and ApplicationInfo.FLAG_SYSTEM != 0) return@mapNotNull null
                if (pkg.packageName == context.packageName) return@mapNotNull null
                if (!hasAnyGranted(pkg, def.perms)) return@mapNotNull null
                AppRef(pm.getApplicationLabel(app).toString(), pkg.packageName)
            }.sortedBy { it.label.lowercase() }
            PermissionGroup(def.title, def.why, apps, def.sensitivity)
        }.filter { it.apps.isNotEmpty() }
            .sortedByDescending { it.sensitivity }

        return result
    }

    private fun hasAnyGranted(pkg: PackageInfo, perms: Set<String>): Boolean {
        val requested = pkg.requestedPermissions ?: return false
        val flags = pkg.requestedPermissionsFlags
        requested.forEachIndexed { i, p ->
            if (p in perms) {
                val granted = flags?.getOrElse(i) { 0 }?.and(PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
                if (granted) return true
            }
        }
        return false
    }

    private data class GroupDef(val title: String, val why: String, val sensitivity: Int, val perms: Set<String>)
}

@Composable
fun PrivacyAdvisorScreen(vm: PrivacyAdvisorViewModel = hiltViewModel()) {
    val groups by vm.groups.collectAsState()
    val context = LocalContext.current

    LazyColumn(
        Modifier.fillMaxSize().padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Text("Privacy advisor", style = MaterialTheme.typography.headlineMedium)
            Text(
                "Exactly which apps can watch you. Tap any app to open its settings and turn off access — DeepWarden never changes anything for you.",
                style = MaterialTheme.typography.bodyMedium, color = DwColors.TextSecondary,
            )
        }
        if (groups.isEmpty()) {
            item { Text("Scanning your apps…", color = DwColors.TextSecondary) }
        }
        items(groups) { group -> PermissionGroupCard(group, context) }
    }
}

@Composable
private fun PermissionGroupCard(group: PrivacyAdvisorViewModel.PermissionGroup, context: Context) {
    var expanded by remember { mutableStateOf(false) }
    Card(
        Modifier.fillMaxWidth().clickable { expanded = !expanded },
        colors = CardDefaults.cardColors(containerColor = DwColors.Surface),
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(group.title, style = MaterialTheme.typography.titleSmall)
                Text("${group.apps.size} app(s)", style = MaterialTheme.typography.titleSmall, color = DwColors.ElectricBlue)
            }
            Text(group.why, style = MaterialTheme.typography.bodySmall, color = DwColors.TextSecondary)
            AnimatedVisibility(expanded) {
                Column {
                    HorizontalDivider()
                    group.apps.forEach { app ->
                        Row(
                            Modifier.fillMaxWidth().padding(vertical = 2.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            Text(app.label, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
                            TextButton(onClick = {
                                runCatching {
                                    context.startActivity(
                                        android.content.Intent(
                                            android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                                            android.net.Uri.parse("package:${app.pkg}"),
                                        ).addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
                                    )
                                }
                            }) { Text("Manage") }
                        }
                    }
                }
            }
        }
    }
}

package com.deepwarden.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CleaningServices
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.deepwarden.app.ui.screens.AdbDeepScanScreen
import com.deepwarden.app.ui.screens.DashboardScreen
import com.deepwarden.app.ui.screens.HistoryScreen
import com.deepwarden.app.ui.screens.OnboardingScreen
import com.deepwarden.app.ui.screens.SafeCleanScreen
import com.deepwarden.app.ui.screens.ScanScreen
import com.deepwarden.app.ui.screens.SettingsScreen
import com.deepwarden.app.ui.screens.SettingsViewModel
import com.deepwarden.app.ui.theme.DwColors

/** Navigation destinations. */
object Routes {
    const val ONBOARDING = "onboarding"
    const val DASHBOARD = "dashboard"
    const val SCAN = "scan"
    const val SCAN_EMERGENCY = "scan?emergency=true"
    const val ADB = "adb"
    const val CLEAN = "clean"
    const val HISTORY = "history"
    const val SETTINGS = "settings"
}

@Composable
fun DeepWardenRoot(integrityProblems: List<String>) {
    val nav = rememberNavController()
    val settingsVm: SettingsViewModel = hiltViewModel()
    val onboardingDone by settingsVm.onboardingDone.collectAsState(initial = null)

    val tabs = listOf(
        Triple(Routes.DASHBOARD, Icons.Filled.Security, "Guard"),
        Triple(Routes.ADB, Icons.Filled.Terminal, "Deep"),
        Triple(Routes.CLEAN, Icons.Filled.CleaningServices, "Clean"),
        Triple(Routes.HISTORY, Icons.Filled.History, "History"),
        Triple(Routes.SETTINGS, Icons.Filled.Settings, "Settings"),
    )

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        bottomBar = {
            val current by nav.currentBackStackEntryAsState()
            val route = current?.destination?.route
            if (onboardingDone == true && route != Routes.ONBOARDING) {
                NavigationBar(containerColor = DwColors.Surface) {
                    tabs.forEach { (dest, icon, label) ->
                        NavigationBarItem(
                            selected = route?.startsWith(dest) == true,
                            onClick = { nav.navigate(dest) { launchSingleTop = true; popUpTo(Routes.DASHBOARD) } },
                            icon = { Icon(icon, contentDescription = label) },
                            label = { Text(label) },
                        )
                    }
                }
            }
        },
    ) { padding ->
        Column(Modifier.padding(padding)) {
            // Tamper warning is global and impossible to miss — but factual, not alarmist.
            if (integrityProblems.isNotEmpty()) {
                Column(
                    Modifier
                        .fillMaxWidth()
                        .background(DwColors.DangerRed)
                        .padding(12.dp)
                ) {
                    Text("Scanner integrity warning", style = MaterialTheme.typography.titleSmall)
                    integrityProblems.forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
                    Text(
                        "Results from a tampered scanner cannot be trusted. Reinstall DeepWarden from an official source.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }

            if (onboardingDone == null) return@Column // settings still loading
            NavHost(
                navController = nav,
                startDestination = if (onboardingDone == true) Routes.DASHBOARD else Routes.ONBOARDING,
            ) {
                composable(Routes.ONBOARDING) {
                    OnboardingScreen(onDone = {
                        settingsVm.completeOnboarding()
                        nav.navigate(Routes.DASHBOARD) { popUpTo(Routes.ONBOARDING) { inclusive = true } }
                    })
                }
                composable(Routes.DASHBOARD) {
                    DashboardScreen(
                        onStartScan = { nav.navigate(Routes.SCAN) },
                        onEmergencyScan = { nav.navigate(Routes.SCAN_EMERGENCY) },
                    )
                }
                composable("scan?emergency={emergency}") { entry ->
                    ScanScreen(emergency = entry.arguments?.getString("emergency") == "true")
                }
                composable(Routes.SCAN) { ScanScreen(emergency = false) }
                composable(Routes.ADB) { AdbDeepScanScreen() }
                composable(Routes.CLEAN) { SafeCleanScreen() }
                composable(Routes.HISTORY) { HistoryScreen() }
                composable(Routes.SETTINGS) { SettingsScreen() }
            }
        }
    }
}

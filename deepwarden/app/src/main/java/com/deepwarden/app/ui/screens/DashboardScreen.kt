package com.deepwarden.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.deepwarden.app.core.ScanTrend
import com.deepwarden.app.core.ThreatBand
import com.deepwarden.app.data.db.ScanEntity
import com.deepwarden.app.data.db.ScanHistoryRepository
import com.deepwarden.app.ui.theme.DwColors
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import javax.inject.Inject

/** Process-level guard so the auto-scan fires once per app launch. */
object AutoScanState {
    @Volatile var alreadyRan: Boolean = false
}

@HiltViewModel
class DashboardViewModel @Inject constructor(
    history: ScanHistoryRepository,
) : ViewModel() {
    /** Latest persisted scan, if any — powers the score gauge + trend arrow. */
    val latestScan: StateFlow<ScanEntity?> = history.scansFlow()
        .map { it.firstOrNull() }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)

    val previousScan: StateFlow<ScanEntity?> = history.scansFlow()
        .map { it.getOrNull(1) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)
}

/**
 * Dashboard: device threat score, dimension breakdown, trend, and the two big
 * entry points — normal Deep Scan and the prominent EMERGENCY scan.
 * Tone: calm instrument panel, never fear-mongering.
 */
@Composable
fun DashboardScreen(
    onStartScan: () -> Unit,
    onEmergencyScan: () -> Unit,
    vm: DashboardViewModel = hiltViewModel(),
) {
    val latest by vm.latestScan.collectAsState()
    val previous by vm.previousScan.collectAsState()

    // Auto-scan the whole system once per app launch (like a real AV opening).
    // Guarded by a process-level flag so it runs once, not on every revisit.
    LaunchedEffect(Unit) {
        if (!AutoScanState.alreadyRan) {
            AutoScanState.alreadyRan = true
            onStartScan()
        }
    }

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("Device guard", style = MaterialTheme.typography.headlineMedium)

        // ---- Threat score gauge ------------------------------------------------
        val scan = latest
        Card(colors = CardDefaults.cardColors(containerColor = DwColors.Surface)) {
            Column(
                Modifier.fillMaxWidth().padding(20.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                if (scan == null) {
                    Text("No scan yet", style = MaterialTheme.typography.titleMedium)
                    Text(
                        "Run your first deep scan to establish a baseline. Future scans diff against it to catch anything new.",
                        style = MaterialTheme.typography.bodyMedium, color = DwColors.TextSecondary,
                    )
                } else {
                    val band = bandFor(scan.overallScore)
                    Box(contentAlignment = Alignment.Center) {
                        CircularProgressIndicator(
                            progress = { scan.overallScore / 100f },
                            modifier = Modifier.size(140.dp),
                            color = bandColor(band),
                            trackColor = DwColors.SurfaceHigh,
                            strokeWidth = 10.dp,
                        )
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Text("${scan.overallScore}", style = MaterialTheme.typography.displaySmall, fontWeight = FontWeight.Bold)
                            Text("/100 threat", style = MaterialTheme.typography.labelSmall, color = DwColors.TextSecondary)
                        }
                    }
                    Text(band.label, style = MaterialTheme.typography.titleMedium, color = bandColor(band))
                    Text(band.calmMessage, style = MaterialTheme.typography.bodyMedium, color = DwColors.TextSecondary)
                    Text("Score confidence: ${scan.confidence}%", style = MaterialTheme.typography.labelSmall, color = DwColors.TextSecondary)

                    previous?.let { prev ->
                        val trend = when {
                            scan.overallScore < prev.overallScore -> ScanTrend.IMPROVED
                            scan.overallScore > prev.overallScore -> ScanTrend.WORSE
                            else -> ScanTrend.UNCHANGED
                        }
                        Text(
                            when (trend) {
                                ScanTrend.IMPROVED -> "▼ Better than last scan (${prev.overallScore} → ${scan.overallScore})"
                                ScanTrend.WORSE -> "▲ Worse than last scan (${prev.overallScore} → ${scan.overallScore}) — check History for what's new"
                                else -> "— Unchanged since last scan"
                            },
                            style = MaterialTheme.typography.labelMedium,
                            color = if (trend == ScanTrend.WORSE) DwColors.WarnOrange else DwColors.CalmGreen,
                        )
                    }

                    // Dimension breakdown
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
                        Dimension("Static", scan.staticScore)
                        Dimension("Behavior", scan.behavioralScore)
                        Dimension("System", scan.systemScore)
                        Dimension("Network", scan.networkScore)
                    }
                }
            }
        }

        Button(onClick = onStartScan, modifier = Modifier.fillMaxWidth()) {
            Text("Run deep scan (Layers 1–4 + 6)")
        }
        Button(
            onClick = onEmergencyScan,
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(containerColor = DwColors.DangerRed),
        ) {
            Text("EMERGENCY scan — I think I'm being watched")
        }
        OutlinedButton(onClick = {}, enabled = false, modifier = Modifier.fillMaxWidth()) {
            Text("Safe Mode is ON — only reversible actions will be suggested")
        }
    }
}

@Composable
private fun Dimension(name: String, value: Int) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text("$value", style = MaterialTheme.typography.titleMedium, color = severityish(value))
        Text(name, style = MaterialTheme.typography.labelSmall, color = DwColors.TextSecondary)
    }
}

private fun severityish(v: Int) = when {
    v >= 70 -> DwColors.DangerRed
    v >= 45 -> DwColors.WarnOrange
    v >= 20 -> DwColors.ElectricBlue
    else -> DwColors.CalmGreen
}

private fun bandFor(score: Int): ThreatBand = when {
    score >= 70 -> ThreatBand.CRITICAL
    score >= 45 -> ThreatBand.ELEVATED
    score >= 20 -> ThreatBand.GUARDED
    else -> ThreatBand.CALM
}

private fun bandColor(band: ThreatBand) = when (band) {
    ThreatBand.CRITICAL -> DwColors.DangerRed
    ThreatBand.ELEVATED -> DwColors.WarnOrange
    ThreatBand.GUARDED -> DwColors.ElectricBlue
    ThreatBand.CALM -> DwColors.CalmGreen
}

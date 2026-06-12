package com.deepwarden.app.ui.screens

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
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.deepwarden.app.core.DetectionLayer
import com.deepwarden.app.core.Finding
import com.deepwarden.app.core.ScanResult
import com.deepwarden.app.detection.engine.ScanOrchestrator
import com.deepwarden.app.data.datastore.SettingsRepository
import com.deepwarden.app.remediation.SafeRemediationEngine
import com.deepwarden.app.report.ForensicReportExporter
import com.deepwarden.app.ui.theme.DwColors
import com.deepwarden.app.ui.theme.severityColor
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class ScanViewModel @Inject constructor(
    private val orchestrator: ScanOrchestrator,
    private val remediation: SafeRemediationEngine,
    private val exporter: ForensicReportExporter,
    settings: SettingsRepository,
) : ViewModel() {

    val progress = orchestrator.progress
    val safeMode = settings.safeMode.stateIn(viewModelScope, SharingStarted.Eagerly, true)

    private val _result = MutableStateFlow<ScanResult?>(null)
    val result: StateFlow<ScanResult?> = _result.asStateFlow()

    private val _plan = MutableStateFlow<SafeRemediationEngine.ActionPlan?>(null)
    val plan: StateFlow<SafeRemediationEngine.ActionPlan?> = _plan.asStateFlow()

    private val _exportPath = MutableStateFlow<String?>(null)
    val exportPath: StateFlow<String?> = _exportPath.asStateFlow()

    private var started = false

    fun startOnce(emergency: Boolean) {
        if (started) return
        started = true
        viewModelScope.launch {
            val res = orchestrator.runFullScan(emergency)
            _result.value = res
            _plan.value = remediation.buildPlan(res.findings, safeMode.first())
        }
    }

    fun exportReports() {
        val res = _result.value ?: return
        viewModelScope.launch {
            val json = exporter.exportJson(res)
            exporter.exportPdf(res)
            _exportPath.value = json.parentFile?.absolutePath
        }
    }
}

/**
 * Scan progress + results. Emergency mode reorders layers so the
 * highest-leverage checks (system/network) stream in first.
 */
@Composable
fun ScanScreen(emergency: Boolean, vm: ScanViewModel = hiltViewModel()) {
    LaunchedEffect(Unit) { vm.startOnce(emergency) }

    val progress by vm.progress.collectAsState()
    val result by vm.result.collectAsState()
    val plan by vm.plan.collectAsState()
    val exportPath by vm.exportPath.collectAsState()

    LazyColumn(
        Modifier.fillMaxSize().padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Text(
                if (emergency) "Emergency deep scan" else "Deep scan",
                style = MaterialTheme.typography.headlineMedium,
                color = if (emergency) DwColors.DangerRed else DwColors.TextPrimary,
            )
            if (emergency) {
                Text(
                    "Running the most critical checks first. Breathe — whatever we find, the action plan starts with steps that cannot lose any data.",
                    style = MaterialTheme.typography.bodyMedium, color = DwColors.TextSecondary,
                )
            }
        }

        // ---- live progress -----------------------------------------------------
        if (result == null) {
            item {
                LinearProgressIndicator(
                    progress = { progress.completedLayers.size / 5f },
                    modifier = Modifier.fillMaxWidth(),
                )
                Text(
                    progress.runningLayer?.let { "Running ${it.displayName}…" } ?: "Preparing…",
                    style = MaterialTheme.typography.labelMedium, color = DwColors.TextSecondary,
                )
            }
            items(progress.findingsSoFar) { FindingCard(it) }
        }

        // ---- final result --------------------------------------------------------
        result?.let { res ->
            item {
                Text(
                    "Scan complete — ${res.findings.size} finding(s), device score ${res.deviceThreatScore.overall}/100 (confidence ${res.deviceThreatScore.confidence}%)",
                    style = MaterialTheme.typography.titleMedium,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = { vm.exportReports() }) { Text("Export report (PDF + JSON)") }
                }
                exportPath?.let {
                    Text("Saved to app storage: $it", style = MaterialTheme.typography.labelSmall, color = DwColors.CalmGreen)
                }
            }

            plan?.let { p ->
                item {
                    Text("Safe action plan", style = MaterialTheme.typography.titleMedium, color = DwColors.CalmGreen)
                    if (p.safeModeActive) {
                        Text(
                            "Safe Mode is ON: every step below is reversible and loses no data.",
                            style = MaterialTheme.typography.labelMedium, color = DwColors.CalmGreen,
                        )
                    }
                }
                items(p.steps) { step ->
                    PlanStepCard(step)
                }
                p.factoryResetAdvice?.let { advice ->
                    item {
                        Card(colors = CardDefaults.cardColors(containerColor = DwColors.SurfaceHigh)) {
                            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                Text("About factory reset", style = MaterialTheme.typography.titleSmall, color = DwColors.WarnOrange)
                                Text(advice, style = MaterialTheme.typography.bodySmall, color = DwColors.TextSecondary)
                            }
                        }
                    }
                }
            }

            item {
                Card(colors = CardDefaults.cardColors(containerColor = DwColors.Surface)) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text("What this scan could NOT see", style = MaterialTheme.typography.titleSmall, color = DwColors.WarnOrange)
                        res.limitations.forEach {
                            Text("• $it", style = MaterialTheme.typography.bodySmall, color = DwColors.TextSecondary)
                        }
                    }
                }
            }
        }
    }
}

/** Expandable finding card: severity, confidence, layer, evidence, education. */
@Composable
fun FindingCard(finding: Finding) {
    var expanded by remember { mutableStateOf(false) }
    Card(
        Modifier.fillMaxWidth().clickable { expanded = !expanded },
        colors = CardDefaults.cardColors(containerColor = DwColors.Surface),
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AssistChip(onClick = {}, label = { Text(finding.severity.displayName) },
                    colors = androidx.compose.material3.AssistChipDefaults.assistChipColors(
                        labelColor = severityColor(finding.severity.name)
                    ))
                AssistChip(onClick = {}, label = { Text("${finding.confidence}% sure") })
            }
            Text(finding.title, style = MaterialTheme.typography.titleSmall)
            Text(finding.layer.displayName, style = MaterialTheme.typography.labelSmall, color = DwColors.ElectricBlue)
            Text(finding.explanation, style = MaterialTheme.typography.bodySmall, color = DwColors.TextSecondary)
            AnimatedVisibility(expanded) {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    HorizontalDivider()
                    Text("How this technique works & how we caught it", style = MaterialTheme.typography.labelMedium, color = DwColors.ElectricBlue)
                    Text(finding.techniqueEducation, style = MaterialTheme.typography.bodySmall, color = DwColors.TextSecondary)
                    Text("Technical evidence", style = MaterialTheme.typography.labelMedium, color = DwColors.ElectricBlue)
                    Text(finding.technicalDetail, style = MaterialTheme.typography.bodySmall, color = DwColors.TextSecondary)
                }
            }
        }
    }
}

@Composable
private fun PlanStepCard(step: SafeRemediationEngine.PlanStep) {
    Card(colors = CardDefaults.cardColors(containerColor = DwColors.SurfaceHigh)) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("Step ${step.order}: ${step.finding.title}", style = MaterialTheme.typography.titleSmall)
            if (step.downgradedForSafeMode) {
                Text("Safe Mode swapped a destructive action for a reversible one.", style = MaterialTheme.typography.labelSmall, color = DwColors.CalmGreen)
            }
            Text(step.action.description, style = MaterialTheme.typography.bodySmall)
            Text("Why this is safe: ${step.action.whySafe}", style = MaterialTheme.typography.bodySmall, color = DwColors.CalmGreen)
            Text("Data impact: ${step.action.dataLossImpact.userLabel}", style = MaterialTheme.typography.labelSmall, color = DwColors.TextSecondary)
            Text("Undo: ${step.action.undoInstructions}", style = MaterialTheme.typography.labelSmall, color = DwColors.TextSecondary)
        }
    }
}

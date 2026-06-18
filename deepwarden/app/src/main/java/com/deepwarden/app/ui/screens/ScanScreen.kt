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
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.deepwarden.app.core.ActionType
import com.deepwarden.app.core.DetectionLayer
import com.deepwarden.app.core.Finding
import com.deepwarden.app.core.ScanResult
import com.deepwarden.app.core.ThreatClassifier
import com.deepwarden.app.detection.engine.ScanOrchestrator
import com.deepwarden.app.data.datastore.SettingsRepository
import com.deepwarden.app.remediation.SafeRemediationEngine
import com.deepwarden.app.report.ForensicReportExporter
import com.deepwarden.app.ui.RemediationLauncher
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
    // Concise report: extra/awareness items stay hidden until the user asks.
    var showDetails by remember { mutableStateOf(false) }

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
            item { AttackVerdictCard(res.findings) }
            item {
                Text(
                    "Device score ${res.deviceThreatScore.overall}/100 (confidence ${res.deviceThreatScore.confidence}%)",
                    style = MaterialTheme.typography.labelMedium, color = DwColors.TextSecondary,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = { vm.exportReports() }) { Text("Export report (PDF + JSON)") }
                }
                exportPath?.let {
                    Text("Saved to app storage: $it", style = MaterialTheme.typography.labelSmall, color = DwColors.CalmGreen)
                }
            }

            plan?.let { p ->
                val attackSteps = p.steps.filter { ThreatClassifier.categoryOf(it.finding).isAttack }
                val otherSteps = p.steps.filter { !ThreatClassifier.categoryOf(it.finding).isAttack }

                // NECESSARY part: the threats to remove. Shown first, always.
                if (attackSteps.isNotEmpty()) {
                    item {
                        Text("Remove these threats", style = MaterialTheme.typography.titleMedium, color = DwColors.DangerRed)
                        if (p.safeModeActive) {
                            Text(
                                "Safe Mode is ON: actions are reversible and never delete your photos, files or important apps.",
                                style = MaterialTheme.typography.labelMedium, color = DwColors.CalmGreen,
                            )
                        }
                    }
                    items(attackSteps) { step -> PlanStepCard(step) }
                } else {
                    item {
                        Text(
                            "Nothing to remove — no active threats need action.",
                            style = MaterialTheme.typography.titleMedium, color = DwColors.CalmGreen,
                        )
                    }
                }

                // EVERYTHING ELSE collapsed by default, so the report stays clean.
                item {
                    OutlinedButton(
                        onClick = { showDetails = !showDetails },
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(
                            if (showDetails) "Hide extra details"
                            else "Show ${otherSteps.size} item(s) to review + what we couldn't see",
                        )
                    }
                }
                if (showDetails) {
                    if (otherSteps.isNotEmpty()) {
                        item {
                            Text("Worth reviewing (not active attacks)", style = MaterialTheme.typography.titleSmall, color = DwColors.WarnOrange)
                        }
                        items(otherSteps) { step -> PlanStepCard(step) }
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

/**
 * Big verdict at the top of the results: tells the user in plain language what
 * was found — "1 malware, 2 spyware, 1 phishing" — instead of a flat app list.
 */
@Composable
private fun AttackVerdictCard(findings: List<Finding>) {
    val groups = ThreatClassifier.summarize(findings)
    val attackGroups = groups.filter { it.first.isAttack && it.second.isNotEmpty() }
    val awarenessGroups = groups.filter { !it.first.isAttack && it.second.isNotEmpty() }
    val underAttack = attackGroups.isNotEmpty()

    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = if (underAttack) DwColors.DangerRed.copy(alpha = 0.18f) else DwColors.Surface,
        ),
    ) {
        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            if (underAttack) {
                Text(
                    "⚠ Threats detected",
                    style = MaterialTheme.typography.headlineSmall, color = DwColors.DangerRed,
                )
                Text(
                    "DeepWarden found signs of the following. Tap any item below for the safe removal steps.",
                    style = MaterialTheme.typography.bodyMedium, color = DwColors.TextPrimary,
                )
                attackGroups.forEach { (cat, list) ->
                    VerdictRow(cat.label, list.size, cat.blurb, DwColors.DangerRed)
                }
            } else {
                Text(
                    "✓ No active attacks detected",
                    style = MaterialTheme.typography.headlineSmall, color = DwColors.CalmGreen,
                )
                Text(
                    "No malware, phishing, spyware or network attacks were found. Stay aware, not afraid.",
                    style = MaterialTheme.typography.bodyMedium, color = DwColors.TextSecondary,
                )
            }
            if (awarenessGroups.isNotEmpty()) {
                HorizontalDivider()
                Text("Worth reviewing (not active attacks):", style = MaterialTheme.typography.labelMedium, color = DwColors.WarnOrange)
                awarenessGroups.forEach { (cat, list) ->
                    VerdictRow(cat.label, list.size, cat.blurb, DwColors.WarnOrange)
                }
            }
            Text(
                "Honest note: this checks what a non-root app can see. It cannot prove the phone is 100% clean — no app can without root.",
                style = MaterialTheme.typography.labelSmall, color = DwColors.TextSecondary,
            )
        }
    }
}

@Composable
private fun VerdictRow(label: String, count: Int, blurb: String, accent: androidx.compose.ui.graphics.Color) {
    Column {
        Text("$label — $count found", style = MaterialTheme.typography.titleSmall, color = accent)
        Text(blurb, style = MaterialTheme.typography.bodySmall, color = DwColors.TextSecondary)
    }
}

@Composable
private fun PlanStepCard(step: SafeRemediationEngine.PlanStep) {
    val context = LocalContext.current
    val category = remember(step.finding.id) { ThreatClassifier.categoryOf(step.finding) }
    Card(colors = CardDefaults.cardColors(containerColor = DwColors.SurfaceHigh)) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(category.label.uppercase(), style = MaterialTheme.typography.labelSmall, color = severityColor(step.finding.severity.name))
            Text("Step ${step.order}: ${step.finding.title}", style = MaterialTheme.typography.titleSmall)
            if (step.downgradedForSafeMode) {
                Text("Safe Mode swapped a destructive action for a reversible one.", style = MaterialTheme.typography.labelSmall, color = DwColors.CalmGreen)
            }
            Text(step.action.description, style = MaterialTheme.typography.bodySmall)
            Text("Why this is safe: ${step.action.whySafe}", style = MaterialTheme.typography.bodySmall, color = DwColors.CalmGreen)
            Text("Data impact: ${step.action.dataLossImpact.userLabel}", style = MaterialTheme.typography.labelSmall, color = DwColors.TextSecondary)
            Text("Undo: ${step.action.undoInstructions}", style = MaterialTheme.typography.labelSmall, color = DwColors.TextSecondary)

            // One-tap "remove it safely": launches Android's own screen/dialog.
            val intent = remember(step.finding.id) { RemediationLauncher.intentFor(context, step.finding) }
            if (intent != null) {
                val isRemoval = step.action.type == ActionType.UNINSTALL_APP ||
                    step.action.type == ActionType.CLEAR_APP_DATA
                Button(
                    onClick = { runCatching { context.startActivity(intent) } },
                    modifier = Modifier.fillMaxWidth(),
                    colors = if (isRemoval) {
                        ButtonDefaults.buttonColors(containerColor = DwColors.DangerRed)
                    } else {
                        ButtonDefaults.buttonColors()
                    },
                ) {
                    Text(RemediationLauncher.buttonLabel(step.finding))
                }
                Text(
                    "Android will ask you to confirm — nothing happens until you tap its button.",
                    style = MaterialTheme.typography.labelSmall, color = DwColors.TextSecondary,
                )
            }
        }
    }
}

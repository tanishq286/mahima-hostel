package com.deepwarden.app.detection.engine

import com.deepwarden.app.core.DetectionLayer
import com.deepwarden.app.core.Finding
import com.deepwarden.app.core.PermanentLimitations
import com.deepwarden.app.core.ScanResult
import com.deepwarden.app.data.db.ScanHistoryRepository
import com.deepwarden.app.detection.layer1.PackageForensicsScanner
import com.deepwarden.app.detection.layer2.BehavioralHeuristicsScanner
import com.deepwarden.app.detection.layer3.SystemIntegrityScanner
import com.deepwarden.app.detection.layer4.NetworkForensicsScanner
import com.deepwarden.app.detection.layer6.ContentAnalysisScanner
import com.deepwarden.app.detection.layer7.CloudReputationScanner
import com.deepwarden.app.data.datastore.SettingsRepository
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Runs detection layers, aggregates findings, scores the device, persists the
 * run for history-diffing, and emits live progress for the UI.
 *
 * EMERGENCY MODE ordering: in a panic, what matters most is what an attacker
 * can do RIGHT NOW — so we run System Integrity (accessibility/admin/USB) and
 * Network (proxy/DNS) FIRST and surface results as they stream in, then the
 * slower package layers.
 */
@Singleton
class ScanOrchestrator @Inject constructor(
    private val layer1: PackageForensicsScanner,
    private val layer2: BehavioralHeuristicsScanner,
    private val layer3: SystemIntegrityScanner,
    private val layer4: NetworkForensicsScanner,
    private val layer6: ContentAnalysisScanner,
    private val layer7: CloudReputationScanner,
    private val scoring: ThreatScoringEngine,
    private val history: ScanHistoryRepository,
    private val settings: SettingsRepository,
) {
    data class Progress(
        val runningLayer: DetectionLayer? = null,
        val completedLayers: Set<DetectionLayer> = emptySet(),
        val findingsSoFar: List<Finding> = emptyList(),
        val done: Boolean = false,
    )

    private val _progress = MutableStateFlow(Progress())
    val progress: StateFlow<Progress> = _progress.asStateFlow()

    /** Full scan (Layers 1–4, 6 if permitted). Layer 5 is interactive via its own screen. */
    suspend fun runFullScan(emergency: Boolean = false): ScanResult {
        _progress.value = Progress()
        val findings = mutableListOf<Finding>()
        val limitations = mutableListOf<String>()
        val started = System.currentTimeMillis()

        // Cloud reputation (Layer 7) only when the user enabled it and set a key.
        val cloudEnabled = settings.cloudRepEnabled.first()
        val vtKey = settings.vtApiKey.first()
        val cloudStep: Pair<DetectionLayer, suspend () -> Pair<List<Finding>, List<String>>>? =
            if (cloudEnabled && vtKey.isNotBlank()) {
                DetectionLayer.CLOUD_REPUTATION to { layer7.scan(vtKey) }
            } else null

        // Emergency: fastest, highest-leverage checks first. The explicit type
        // annotation on baseOrder is what makes the lambdas infer as `suspend`;
        // we append the optional cloud step afterwards to keep that inference.
        val baseOrder: List<Pair<DetectionLayer, suspend () -> Pair<List<Finding>, List<String>>>> =
            if (emergency) listOf(
                DetectionLayer.SYSTEM_INTEGRITY to { layer3.scan() },
                DetectionLayer.NETWORK_FORENSICS to { layer4.scan() },
                DetectionLayer.STATIC_FORENSICS to { layer1.scan() },
                DetectionLayer.BEHAVIORAL_HEURISTICS to { layer2.scan() },
                DetectionLayer.CONTENT_ANALYSIS to { layer6.scan() },
            ) else listOf(
                DetectionLayer.STATIC_FORENSICS to { layer1.scan() },
                DetectionLayer.BEHAVIORAL_HEURISTICS to { layer2.scan() },
                DetectionLayer.SYSTEM_INTEGRITY to { layer3.scan() },
                DetectionLayer.NETWORK_FORENSICS to { layer4.scan() },
                DetectionLayer.CONTENT_ANALYSIS to { layer6.scan() },
            )
        val order = baseOrder + listOfNotNull(cloudStep)

        for ((layer, run) in order) {
            _progress.value = _progress.value.copy(runningLayer = layer)
            val (f, l) = runCatching { run() }
                .getOrElse { e ->
                    // A layer crashing must never kill the scan — report honestly instead.
                    emptyList<Finding>() to listOf("${layer.displayName} failed to run: ${e.message ?: e.javaClass.simpleName}")
                }
            findings += f
            limitations += l
            _progress.value = _progress.value.copy(
                completedLayers = _progress.value.completedLayers + layer,
                findingsSoFar = findings.toList(),
            )
        }

        limitations += PermanentLimitations.WITHOUT_ROOT
        val deduped = dedupe(findings)
        val score = scoring.score(deduped)
        val result = ScanResult(
            scanId = 0,
            startedAtMillis = started,
            finishedAtMillis = System.currentTimeMillis(),
            layersRun = order.map { it.first }.toSet(),
            findings = deduped.sortedByDescending { it.priorityScore },
            limitations = limitations.distinct(),
            deviceThreatScore = score,
            isEmergencyScan = emergency,
        )
        val persisted = history.saveScan(result)
        _progress.value = _progress.value.copy(done = true, runningLayer = null)
        return persisted
    }

    /** Same package + same title from different code paths = one finding (keep the most confident). */
    private fun dedupe(findings: List<Finding>): List<Finding> =
        findings.groupBy { it.subjectPackage to it.title }
            .map { (_, group) -> group.maxBy { it.confidence } }
}

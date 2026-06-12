package com.deepwarden.app.data.db

import com.deepwarden.app.core.DetectionLayer
import com.deepwarden.app.core.DeviceThreatScore
import com.deepwarden.app.core.Finding
import com.deepwarden.app.core.SafeAction
import com.deepwarden.app.core.ScanResult
import com.deepwarden.app.core.ScanTrend
import com.deepwarden.app.core.Severity
import kotlinx.coroutines.flow.Flow
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Maps domain <-> Room and computes the SCAN DIFF: which findings are NEW
 * since the previous scan (a new infection indicator), which were RESOLVED.
 *
 * Storage budget: history is pruned to the newest [MAX_SCANS_KEPT] scans —
 * DeepWarden practices the same storage frugality it preaches.
 */
@Singleton
class ScanHistoryRepository @Inject constructor(
    private val dao: ScanDao,
) {
    private val json = Json { ignoreUnknownKeys = true }

    data class ScanDiff(
        val newFindings: List<Finding>,
        val resolvedTitles: List<String>,
        val trend: ScanTrend,
        val scoreDelta: Int,
    )

    fun scansFlow(): Flow<List<ScanEntity>> = dao.scansFlow()

    suspend fun saveScan(result: ScanResult): ScanResult {
        val scanId = dao.insertScan(
            ScanEntity(
                startedAt = result.startedAtMillis,
                finishedAt = result.finishedAtMillis,
                overallScore = result.deviceThreatScore.overall,
                staticScore = result.deviceThreatScore.staticDimension,
                behavioralScore = result.deviceThreatScore.behavioralDimension,
                systemScore = result.deviceThreatScore.systemDimension,
                networkScore = result.deviceThreatScore.networkDimension,
                confidence = result.deviceThreatScore.confidence,
                isEmergency = result.isEmergencyScan,
                layersRun = result.layersRun.joinToString(",") { it.name },
                limitationsJson = json.encodeToString(ListSerializer(String.serializer()), result.limitations),
            )
        )
        dao.insertFindings(result.findings.map { it.toEntity(scanId) })
        dao.pruneScans(MAX_SCANS_KEPT)
        dao.pruneOrphanFindings()
        return result.copy(scanId = scanId)
    }

    suspend fun loadScan(scanId: Long): ScanResult? {
        val scan = dao.scanById(scanId) ?: return null
        val findings = dao.findingsForScan(scanId).map { it.toDomain() }
        return ScanResult(
            scanId = scan.id,
            startedAtMillis = scan.startedAt,
            finishedAtMillis = scan.finishedAt,
            layersRun = scan.layersRun.split(',').filter { it.isNotBlank() }
                .map { DetectionLayer.valueOf(it) }.toSet(),
            findings = findings,
            limitations = json.decodeFromString(ListSerializer(String.serializer()), scan.limitationsJson),
            deviceThreatScore = DeviceThreatScore(
                scan.overallScore, scan.staticScore, scan.behavioralScore,
                scan.systemScore, scan.networkScore, scan.confidence,
            ),
            isEmergencyScan = scan.isEmergency,
        )
    }

    /** Diff the two most recent scans — the "did anything NEW appear?" answer. */
    suspend fun latestDiff(): ScanDiff? {
        val lastTwo = dao.lastTwoScans()
        if (lastTwo.isEmpty()) return null
        val current = dao.findingsForScan(lastTwo[0].id)
        if (lastTwo.size == 1) {
            return ScanDiff(current.map { it.toDomain() }, emptyList(), ScanTrend.FIRST_SCAN, 0)
        }
        val previous = dao.findingsForScan(lastTwo[1].id)
        val prevKeys = previous.map { it.diffKey }.toSet()
        val currKeys = current.map { it.diffKey }.toSet()
        val newFindings = current.filter { it.diffKey !in prevKeys }.map { it.toDomain() }
        val resolved = previous.filter { it.diffKey !in currKeys }.map { it.title }
        val delta = lastTwo[0].overallScore - lastTwo[1].overallScore
        val trend = when {
            delta < 0 -> ScanTrend.IMPROVED
            delta > 0 -> ScanTrend.WORSE
            else -> ScanTrend.UNCHANGED
        }
        return ScanDiff(newFindings, resolved, trend, delta)
    }

    // ---- mapping -------------------------------------------------------------

    private fun Finding.toEntity(scanId: Long) = FindingEntity(
        id = id, scanId = scanId, layer = layer.name, severity = severity.name,
        confidence = confidence, title = title, explanation = explanation,
        technicalDetail = technicalDetail, techniqueEducation = techniqueEducation,
        subjectPackage = subjectPackage, subjectAppLabel = subjectAppLabel,
        actionJson = json.encodeToString(SafeActionSurrogate.serializer(), SafeActionSurrogate.from(recommendedAction)),
        detectedAt = detectedAtMillis,
        diffKey = "${layer.name}|${subjectPackage ?: "-"}|$title",
    )

    private fun FindingEntity.toDomain() = Finding(
        id = id,
        layer = DetectionLayer.valueOf(layer),
        severity = Severity.valueOf(severity),
        confidence = confidence,
        title = title,
        explanation = explanation,
        technicalDetail = technicalDetail,
        techniqueEducation = techniqueEducation,
        subjectPackage = subjectPackage,
        subjectAppLabel = subjectAppLabel,
        recommendedAction = json.decodeFromString(SafeActionSurrogate.serializer(), actionJson).toDomain(),
        detectedAtMillis = detectedAt,
    )

    private companion object { const val MAX_SCANS_KEPT = 30 }
}

/** Serializable mirror of SafeAction (domain type stays serialization-free). */
@kotlinx.serialization.Serializable
data class SafeActionSurrogate(
    val type: String,
    val description: String,
    val whySafe: String,
    val undoInstructions: String,
    val reversibility: String,
    val dataLossImpact: String,
    val confirmationSteps: Int,
) {
    fun toDomain() = SafeAction(
        type = com.deepwarden.app.core.ActionType.valueOf(type),
        description = description, whySafe = whySafe, undoInstructions = undoInstructions,
        reversibility = com.deepwarden.app.core.Reversibility.valueOf(reversibility),
        dataLossImpact = com.deepwarden.app.core.DataLossImpact.valueOf(dataLossImpact),
        confirmationSteps = confirmationSteps,
    )
    companion object {
        fun from(a: SafeAction) = SafeActionSurrogate(
            a.type.name, a.description, a.whySafe, a.undoInstructions,
            a.reversibility.name, a.dataLossImpact.name, a.confirmationSteps,
        )
    }
}

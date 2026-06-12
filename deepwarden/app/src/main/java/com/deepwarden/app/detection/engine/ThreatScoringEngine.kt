package com.deepwarden.app.detection.engine

import com.deepwarden.app.core.DetectionLayer
import com.deepwarden.app.core.DeviceThreatScore
import com.deepwarden.app.core.Finding
import javax.inject.Inject
import javax.inject.Singleton

/**
 * ============================================================================
 *  GOD-LEVEL RISK SCORING — multi-dimensional, explainable, confidence-aware
 * ============================================================================
 *
 * Pure logic, fully unit-tested (see ThreatScoringEngineTest).
 *
 * Dimensions map to layers:
 *   static     <- Layer 1 (+ Layer 5, which is "deep static")
 *   behavioral <- Layer 2 + Layer 6
 *   system     <- Layer 3
 *   network    <- Layer 4
 *
 * Each dimension = saturating sum of (severity weight × confidence) so that
 * one CRITICAL@95 outweighs five LOW@40s, but many mediums still add up.
 * Saturation (asymptotic curve) keeps scores meaningful: 100 means
 * "overwhelming evidence", not "two criticals happened to sum past a line".
 *
 * Overall = weighted blend, with system+static dominating because those are
 * the dimensions attackers MUST touch to persist.
 */
@Singleton
class ThreatScoringEngine @Inject constructor() {

    fun score(findings: List<Finding>): DeviceThreatScore {
        val static = dimension(
            findings,
            DetectionLayer.STATIC_FORENSICS,
            DetectionLayer.ADB_DEEP_FORENSICS,
            DetectionLayer.CLOUD_REPUTATION,
        )
        val behavioral = dimension(findings, DetectionLayer.BEHAVIORAL_HEURISTICS, DetectionLayer.CONTENT_ANALYSIS)
        val system = dimension(findings, DetectionLayer.SYSTEM_INTEGRITY)
        val network = dimension(findings, DetectionLayer.NETWORK_FORENSICS)

        val overall = (static * 0.30 + behavioral * 0.25 + system * 0.25 + network * 0.20)
            .toInt().coerceIn(0, 100)

        val confidence = if (findings.isEmpty()) 100 // confident the device LOOKS clean (within our limits)
        else findings.sumOf { it.confidence } / findings.size

        return DeviceThreatScore(
            overall = overall,
            staticDimension = static,
            behavioralDimension = behavioral,
            systemDimension = system,
            networkDimension = network,
            confidence = confidence,
        )
    }

    /**
     * Saturating dimension score. Each finding contributes
     * severityWeight × (confidence/100); the running total is squashed with
     * x/(x+K) scaled to 0–100. K=120 tuned so one CRITICAL@95 ≈ 44 and
     * three CRITICALs ≈ 70 (clearly "act now" territory).
     */
    private fun dimension(findings: List<Finding>, vararg layers: DetectionLayer): Int {
        val relevant = findings.filter { it.layer in layers }
        if (relevant.isEmpty()) return 0
        val raw = relevant.sumOf { it.severity.weight * it.confidence / 100.0 }
        val squashed = raw / (raw + SATURATION_K) * 100.0
        return squashed.toInt().coerceIn(0, 100)
    }

    private companion object { const val SATURATION_K = 120.0 }
}

package com.deepwarden.app.core

/**
 * Aggregate result of one scan run (any subset of the 6 layers).
 *
 * [limitations] is mandatory: every scan honestly lists what it could NOT see
 * (e.g. "No usage-access permission → behavioral layer limited", or the
 * permanent non-root caveats). The UI shows these in a dedicated card.
 */
data class ScanResult(
    val scanId: Long,
    val startedAtMillis: Long,
    val finishedAtMillis: Long,
    val layersRun: Set<DetectionLayer>,
    val findings: List<Finding>,
    /** Honest list of blind spots for THIS run. */
    val limitations: List<String>,
    val deviceThreatScore: DeviceThreatScore,
    val isEmergencyScan: Boolean = false,
)

/**
 * Multi-dimensional device threat score (0 = clean, 100 = severely compromised).
 * Each dimension is computed by [com.deepwarden.app.detection.engine.ThreatScoringEngine].
 */
data class DeviceThreatScore(
    val overall: Int,
    val staticDimension: Int,
    val behavioralDimension: Int,
    val systemDimension: Int,
    val networkDimension: Int,
    /** Mean confidence across contributing findings — shown next to the score. */
    val confidence: Int,
) {
    val band: ThreatBand
        get() = when {
            overall >= 70 -> ThreatBand.CRITICAL
            overall >= 45 -> ThreatBand.ELEVATED
            overall >= 20 -> ThreatBand.GUARDED
            else -> ThreatBand.CALM
        }
}

enum class ThreatBand(val label: String, val calmMessage: String) {
    CALM("Looking good", "No significant threats found. Stay aware, not afraid."),
    GUARDED("Worth a look", "A few items deserve review. None require drastic action."),
    ELEVATED("Needs attention", "Suspicious signals found. Follow the safe action plan — no data loss needed."),
    CRITICAL("Act now — calmly", "Strong indicators of compromise. The plan below starts with fully reversible steps."),
}

/** Trend vs the previous scan, powering the dashboard arrow + history diff. */
enum class ScanTrend { IMPROVED, UNCHANGED, WORSE, FIRST_SCAN }

/**
 * The permanent, non-negotiable honesty list. Shown during onboarding and
 * appended to every report. We never claim to see what we cannot.
 */
object PermanentLimitations {
    val WITHOUT_ROOT = listOf(
        "True kernel-level rootkits cannot be detected from a non-root app. Layer 5 (ADB) can spot common traces, not all.",
        "Fully encrypted exfiltration to reputable-looking domains may evade network heuristics.",
        "Deep /data partition changes are invisible without root on modern Android.",
        "Apps using zero-day platform exploits may hide from PackageManager itself.",
        "If the OS itself is compromised (malicious ROM), no on-device scanner can be fully trusted — including this one.",
    )
}

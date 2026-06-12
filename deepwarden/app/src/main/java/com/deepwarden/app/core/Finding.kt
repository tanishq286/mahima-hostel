package com.deepwarden.app.core

import java.util.UUID

/**
 * ============================================================================
 *  CORE DOMAIN MODEL — every detection in DeepWarden produces a [Finding].
 * ============================================================================
 *
 * DESIGN CONTRACT ("Maximum Honesty"):
 * A Finding is only valid if it can answer ALL of these for the user:
 *   1. WHAT was found            -> [title], [explanation]
 *   2. HOW SURE we are           -> [confidence] (0–100, never implied 100%)
 *   3. WHICH layer caught it     -> [layer]
 *   4. WHY it matters            -> [severity] + [techniqueEducation]
 *   5. WHAT to do, SAFELY        -> [recommendedAction]
 *   6. WHAT data is at risk      -> [recommendedAction.dataLossImpact]
 *
 * The UI refuses to render findings with empty explanations — honesty is
 * enforced structurally, not by convention.
 */
data class Finding(
    val id: String = UUID.randomUUID().toString(),
    /** Which of the 6 detection layers produced this finding. */
    val layer: DetectionLayer,
    val severity: Severity,
    /**
     * Confidence 0–100. Heuristics are probabilistic; we NEVER show a heuristic
     * match as a certainty. Rule of thumb used across scanners:
     *   95+  direct observation of a hostile config (e.g. rogue proxy set)
     *   80+  multiple independent signals agree
     *   60+  strong single heuristic (e.g. extreme permission combo)
     *   <60  informational / "worth reviewing"
     */
    val confidence: Int,
    /** Short human title, e.g. "Hidden app with SMS + Accessibility access". */
    val title: String,
    /** Plain-language explanation of what was detected and why it is suspicious. */
    val explanation: String,
    /** Raw technical evidence (permission lists, component names, parsed ADB lines). */
    val technicalDetail: String,
    /** "How this technique works and how we caught it" — education, not fear. */
    val techniqueEducation: String,
    /** Package this finding refers to, if app-specific (null for system findings). */
    val subjectPackage: String? = null,
    val subjectAppLabel: String? = null,
    /** The single safest next step. Remediation engine may add alternatives. */
    val recommendedAction: SafeAction,
    val detectedAtMillis: Long = System.currentTimeMillis(),
) {
    init {
        require(confidence in 0..100) { "confidence must be 0..100" }
        require(explanation.isNotBlank()) { "Honesty contract: explanation required" }
    }

    /** Composite used for prioritisation: severity weight scaled by confidence. */
    val priorityScore: Int
        get() = severity.weight * confidence / 100
}

/** The six detection layers. Order == depth (1 shallowest, 5 deepest visibility). */
enum class DetectionLayer(val displayName: String, val depthRank: Int) {
    STATIC_FORENSICS("Layer 1 · Package Forensics", 1),
    BEHAVIORAL_HEURISTICS("Layer 2 · Behavioral Heuristics", 2),
    SYSTEM_INTEGRITY("Layer 3 · System Integrity", 3),
    NETWORK_FORENSICS("Layer 4 · Network & Exfiltration", 4),
    ADB_DEEP_FORENSICS("Layer 5 · ADB Deep Forensics", 5),
    CONTENT_ANALYSIS("Layer 6 · Content Analysis", 2),
}

enum class Severity(val weight: Int, val displayName: String) {
    INFO(5, "Info"),
    LOW(20, "Low"),
    MEDIUM(45, "Medium"),
    HIGH(75, "High"),
    CRITICAL(100, "Critical"),
}

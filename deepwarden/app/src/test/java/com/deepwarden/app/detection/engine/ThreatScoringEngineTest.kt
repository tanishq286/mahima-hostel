package com.deepwarden.app.detection.engine

import com.deepwarden.app.core.DetectionLayer
import com.deepwarden.app.core.Finding
import com.deepwarden.app.core.SafeActions
import com.deepwarden.app.core.Severity
import com.deepwarden.app.core.ThreatBand
import com.google.common.truth.Truth.assertThat
import org.junit.Test

class ThreatScoringEngineTest {

    private val engine = ThreatScoringEngine()

    private fun finding(layer: DetectionLayer, severity: Severity, confidence: Int) = Finding(
        layer = layer, severity = severity, confidence = confidence,
        title = "t", explanation = "e", technicalDetail = "d", techniqueEducation = "edu",
        recommendedAction = SafeActions.reviewOnly("x"),
    )

    @Test
    fun `no findings means zero score with full confidence`() {
        val score = engine.score(emptyList())
        assertThat(score.overall).isEqualTo(0)
        assertThat(score.confidence).isEqualTo(100)
        assertThat(score.band).isEqualTo(ThreatBand.CALM)
    }

    @Test
    fun `one low confidence info finding stays calm`() {
        val score = engine.score(listOf(finding(DetectionLayer.STATIC_FORENSICS, Severity.INFO, 40)))
        assertThat(score.band).isEqualTo(ThreatBand.CALM)
    }

    @Test
    fun `one critical does not alone max the score`() {
        // Saturation: a single signal must not scream 100/100.
        val score = engine.score(listOf(finding(DetectionLayer.SYSTEM_INTEGRITY, Severity.CRITICAL, 95)))
        assertThat(score.overall).isGreaterThan(5)
        assertThat(score.overall).isLessThan(45)
    }

    @Test
    fun `multiple high confidence criticals escalate to elevated or critical band`() {
        val findings = listOf(
            finding(DetectionLayer.SYSTEM_INTEGRITY, Severity.CRITICAL, 95),
            finding(DetectionLayer.STATIC_FORENSICS, Severity.CRITICAL, 90),
            finding(DetectionLayer.NETWORK_FORENSICS, Severity.CRITICAL, 95),
            finding(DetectionLayer.BEHAVIORAL_HEURISTICS, Severity.HIGH, 75),
            finding(DetectionLayer.STATIC_FORENSICS, Severity.CRITICAL, 90),
            finding(DetectionLayer.SYSTEM_INTEGRITY, Severity.HIGH, 90),
        )
        val score = engine.score(findings)
        assertThat(score.overall).isAtLeast(45)
    }

    @Test
    fun `confidence is mean of finding confidences`() {
        val score = engine.score(
            listOf(
                finding(DetectionLayer.STATIC_FORENSICS, Severity.HIGH, 80),
                finding(DetectionLayer.STATIC_FORENSICS, Severity.LOW, 40),
            ),
        )
        assertThat(score.confidence).isEqualTo(60)
    }

    @Test
    fun `adb layer feeds the static dimension`() {
        val score = engine.score(listOf(finding(DetectionLayer.ADB_DEEP_FORENSICS, Severity.CRITICAL, 90)))
        assertThat(score.staticDimension).isGreaterThan(0)
        assertThat(score.networkDimension).isEqualTo(0)
    }

    @Test
    fun `dimensions stay within bounds under load`() {
        val many = (1..50).map { finding(DetectionLayer.NETWORK_FORENSICS, Severity.CRITICAL, 95) }
        val score = engine.score(many)
        assertThat(score.networkDimension).isAtMost(100)
        assertThat(score.overall).isAtMost(100)
    }
}

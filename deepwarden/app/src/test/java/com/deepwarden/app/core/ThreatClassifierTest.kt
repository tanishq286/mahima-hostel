package com.deepwarden.app.core

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class ThreatClassifierTest {

    private fun finding(layer: DetectionLayer, title: String) = Finding(
        layer = layer, severity = Severity.HIGH, confidence = 80,
        title = title, explanation = "e", technicalDetail = "d", techniqueEducation = "edu",
        recommendedAction = SafeActions.reviewOnly("x"),
    )

    @Test
    fun `cloud malicious finding is malware`() {
        val c = ThreatClassifier.categoryOf(
            finding(DetectionLayer.CLOUD_REPUTATION, "\"X\" flagged by 9 antivirus engines"),
        )
        assertThat(c).isEqualTo(AttackCategory.MALWARE)
    }

    @Test
    fun `content layer is phishing`() {
        val c = ThreatClassifier.categoryOf(finding(DetectionLayer.CONTENT_ANALYSIS, "Suspicious message"))
        assertThat(c).isEqualTo(AttackCategory.PHISHING)
    }

    @Test
    fun `network layer is network attack`() {
        val c = ThreatClassifier.categoryOf(finding(DetectionLayer.NETWORK_FORENSICS, "Global HTTP proxy is set"))
        assertThat(c).isEqualTo(AttackCategory.NETWORK_ATTACK)
    }

    @Test
    fun `hidden sms app is spyware`() {
        val c = ThreatClassifier.categoryOf(
            finding(DetectionLayer.STATIC_FORENSICS, "Invisible app with surveillance permissions"),
        )
        assertThat(c).isEqualTo(AttackCategory.SPYWARE)
    }

    @Test
    fun `active attack detection works`() {
        val attack = listOf(finding(DetectionLayer.NETWORK_FORENSICS, "Global HTTP proxy is set"))
        val benign = listOf(finding(DetectionLayer.BEHAVIORAL_HEURISTICS, "High-risk permission profile"))
        assertThat(ThreatClassifier.hasActiveAttack(attack)).isTrue()
        assertThat(ThreatClassifier.hasActiveAttack(benign)).isFalse()
    }

    @Test
    fun `summary puts attacks before awareness items`() {
        val findings = listOf(
            finding(DetectionLayer.BEHAVIORAL_HEURISTICS, "High-risk permission profile"),
            finding(DetectionLayer.NETWORK_FORENSICS, "Global HTTP proxy is set"),
        )
        val summary = ThreatClassifier.summarize(findings)
        assertThat(summary.first().first.isAttack).isTrue()
    }
}

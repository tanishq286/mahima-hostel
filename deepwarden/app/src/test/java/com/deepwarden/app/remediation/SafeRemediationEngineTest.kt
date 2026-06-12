package com.deepwarden.app.remediation

import com.deepwarden.app.core.ActionType
import com.deepwarden.app.core.DetectionLayer
import com.deepwarden.app.core.Finding
import com.deepwarden.app.core.SafeActions
import com.deepwarden.app.core.Severity
import com.google.common.truth.Truth.assertThat
import org.junit.Test

/**
 * The Zero Data Loss guarantee, verified:
 * Safe Mode must never let a destructive action reach the user.
 */
class SafeRemediationEngineTest {

    private val engine = SafeRemediationEngine()

    private fun critical(label: String) = Finding(
        layer = DetectionLayer.STATIC_FORENSICS, severity = Severity.CRITICAL, confidence = 90,
        title = "Spyware: $label", explanation = "e", technicalDetail = "d", techniqueEducation = "edu",
        subjectAppLabel = label, subjectPackage = "com.bad.$label",
        recommendedAction = SafeActions.uninstallLastResort(label),
    )

    private fun settingFinding() = Finding(
        layer = DetectionLayer.SYSTEM_INTEGRITY, severity = Severity.MEDIUM, confidence = 95,
        title = "USB debugging on", explanation = "e", technicalDetail = "d", techniqueEducation = "edu",
        recommendedAction = SafeActions.reviewOnly("usb"),
    )

    @Test
    fun `safe mode downgrades uninstall to disable`() {
        val plan = engine.buildPlan(listOf(critical("evil")), safeMode = true)
        val step = plan.steps.single()
        assertThat(step.action.type).isEqualTo(ActionType.DISABLE_APP)
        assertThat(step.downgradedForSafeMode).isTrue()
        assertThat(step.action.allowedInSafeMode()).isTrue()
    }

    @Test
    fun `safe mode off keeps last resort action with three confirmations`() {
        val plan = engine.buildPlan(listOf(critical("evil")), safeMode = false)
        val step = plan.steps.single()
        assertThat(step.action.type).isEqualTo(ActionType.UNINSTALL_APP)
        assertThat(step.action.confirmationSteps).isAtLeast(3)
    }

    @Test
    fun `plan orders reversible setting changes before app-level actions`() {
        val plan = engine.buildPlan(listOf(critical("evil"), settingFinding()), safeMode = false)
        // REVIEW_ONLY (tier 0) before UNINSTALL (tier 4)
        assertThat(plan.steps.first().action.type).isEqualTo(ActionType.REVIEW_ONLY)
        assertThat(plan.steps.last().action.type).isEqualTo(ActionType.UNINSTALL_APP)
    }

    @Test
    fun `factory reset advice requires two strong criticals`() {
        assertThat(engine.factoryResetAdvice(listOf(critical("a")))).isNull()
        assertThat(engine.factoryResetAdvice(listOf(critical("a"), critical("b")))).isNotNull()
    }

    @Test
    fun `factory reset advice leads with backup`() {
        val advice = engine.factoryResetAdvice(listOf(critical("a"), critical("b")))!!
        assertThat(advice).contains("BACK UP FIRST")
    }

    @Test
    fun `every safe mode step is reversible and data-safe`() {
        val findings = listOf(critical("a"), critical("b"), settingFinding())
        val plan = engine.buildPlan(findings, safeMode = true)
        plan.steps.forEach { step ->
            assertThat(step.action.allowedInSafeMode()).isTrue()
        }
    }
}

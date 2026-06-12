package com.deepwarden.app.remediation

import com.deepwarden.app.core.ActionType
import com.deepwarden.app.core.DataLossImpact
import com.deepwarden.app.core.Finding
import com.deepwarden.app.core.Reversibility
import com.deepwarden.app.core.SafeAction
import com.deepwarden.app.core.Severity
import javax.inject.Inject
import javax.inject.Singleton

/**
 * ============================================================================
 *  GOD-LEVEL SAFE REMEDIATION ENGINE
 * ============================================================================
 *
 * Turns raw findings into an ORDERED, context-aware action plan.
 *
 * Ordering principle — "Smart Safe Clean":
 *   lowest risk-to-user-data FIRST, highest threat-impact within each tier:
 *     Tier 0  REVIEW_ONLY (look, confirm, learn)
 *     Tier 1  Setting toggles (revoke permission, disable accessibility/admin,
 *             fix proxy/DNS/USB-debug)  — fully reversible
 *     Tier 2  Disable app (frozen, data intact) — fully reversible
 *     Tier 3  Cache-level cleaning — zero personal data
 *     Tier 4  LAST RESORT (uninstall / clear data) — gated behind Safe Mode OFF
 *             + 3 confirmations
 *
 * SAFE MODE filter: when ON (default), Tier 4 steps are replaced by their
 * reversible Tier-2 equivalent (disable instead of uninstall).
 *
 * FACTORY RESET: never a button. [factoryResetAdvice] only ever returns
 * guidance when ≥2 CRITICAL findings at ≥85 confidence exist, and the guidance
 * is a backup-first checklist, not an action.
 */
@Singleton
class SafeRemediationEngine @Inject constructor() {

    data class PlanStep(
        val order: Int,
        val finding: Finding,
        val action: SafeAction,
        /** True when Safe Mode swapped a destructive action for a reversible one. */
        val downgradedForSafeMode: Boolean,
    )

    data class ActionPlan(
        val steps: List<PlanStep>,
        val factoryResetAdvice: String?,
        val safeModeActive: Boolean,
    )

    fun buildPlan(findings: List<Finding>, safeMode: Boolean): ActionPlan {
        val steps = findings
            .map { finding -> toStep(finding, safeMode) }
            .sortedWith(
                compareBy<Pair<Finding, Pair<SafeAction, Boolean>>> { tier(it.second.first) }
                    .thenByDescending { it.first.priorityScore }
            )
            .mapIndexed { i, (finding, actionPair) ->
                PlanStep(order = i + 1, finding = finding, action = actionPair.first, downgradedForSafeMode = actionPair.second)
            }

        return ActionPlan(
            steps = steps,
            factoryResetAdvice = factoryResetAdvice(findings),
            safeModeActive = safeMode,
        )
    }

    private fun toStep(finding: Finding, safeMode: Boolean): Pair<Finding, Pair<SafeAction, Boolean>> {
        val action = finding.recommendedAction
        // Safe Mode: destructive → reversible equivalent.
        if (safeMode && !action.allowedInSafeMode()) {
            val label = finding.subjectAppLabel ?: finding.subjectPackage ?: "the app"
            val downgraded = SafeAction(
                type = ActionType.DISABLE_APP,
                description = "SAFE MODE: instead of \"${action.type}\", DISABLE \"$label\" (Settings → Apps → $label → Disable). Equally effective at stopping it; zero data loss.",
                whySafe = "Disabling freezes the app completely while keeping every byte of data. You can turn Safe Mode off later if you decide to remove it permanently.",
                undoInstructions = "Settings → Apps → show disabled → $label → Enable.",
                reversibility = Reversibility.FULLY_REVERSIBLE,
                dataLossImpact = DataLossImpact.SETTINGS_ONLY,
            )
            return finding to (downgraded to true)
        }
        return finding to (action to false)
    }

    /** Lower tier = safer = earlier in the wizard. */
    internal fun tier(action: SafeAction): Int = when (action.type) {
        ActionType.REVIEW_ONLY -> 0
        ActionType.REVOKE_PERMISSION, ActionType.DISABLE_ACCESSIBILITY,
        ActionType.REMOVE_DEVICE_ADMIN, ActionType.CHANGE_SETTING,
        ActionType.NETWORK_RESET_GUIDED, ActionType.REMOVE_CERTIFICATE -> 1
        ActionType.DISABLE_APP -> 2
        ActionType.CLEAR_CACHE -> 3
        ActionType.UNINSTALL_APP, ActionType.CLEAR_APP_DATA -> 4
        ActionType.FACTORY_RESET_GUIDANCE -> 5
    }

    /**
     * Factory reset guidance threshold: multiple independent high-confidence
     * criticals. Anything less and we explicitly tell the user a reset is NOT
     * warranted — calming an anxious user is part of the job.
     */
    internal fun factoryResetAdvice(findings: List<Finding>): String? {
        val strongCriticals = findings.count { it.severity == Severity.CRITICAL && it.confidence >= 85 }
        if (strongCriticals < 2) return null
        return """
            |Multiple high-confidence critical threats were found. A factory reset is the only
            |way to be CERTAIN a deeply embedded threat is gone — but do it on YOUR terms:
            |
            |  1. BACK UP FIRST (photos, contacts, WhatsApp chat backup, documents). The app's
            |     backup checklist walks through every category. Do NOT skip this.
            |  2. Write down / export this report (PDF) — evidence may matter later.
            |  3. If this involves a person who had access to your phone and you feel unsafe,
            |     consider contacting local support organisations before changing anything —
            |     removing spyware can alert the person who installed it.
            |  4. After reset: restore from the backup made in step 1, set a NEW screen lock
            |     PIN, and change important passwords from a different, trusted device.
            |
            |Until you're ready, the reversible steps above (disable apps, revoke access)
            |neutralise the threats without losing anything.
        """.trimMargin()
    }
}

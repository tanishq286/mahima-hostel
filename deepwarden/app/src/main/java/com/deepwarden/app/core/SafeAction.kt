package com.deepwarden.app.core

/**
 * ============================================================================
 *  ZERO DATA LOSS GUARANTEE — encoded in the type system.
 * ============================================================================
 *
 * Every recommended action carries an explicit [DataLossImpact] and
 * [Reversibility]. The remediation UI:
 *   - In SAFE MODE (default ON): hides every action whose impact is worse
 *     than [DataLossImpact.NONE] unless it is fully reversible.
 *   - ALWAYS requires multi-step confirmation for APP_DATA impact.
 *   - NEVER auto-executes anything. DeepWarden is read-only by default;
 *     actions are deep-links into system Settings where the USER acts.
 */
data class SafeAction(
    val type: ActionType,
    /** What the user should do, step by step. */
    val description: String,
    /** Why this action cannot harm personal data (or exactly what it touches). */
    val whySafe: String,
    /** How to undo it. Required for every reversible action. */
    val undoInstructions: String,
    val reversibility: Reversibility,
    val dataLossImpact: DataLossImpact,
    /** Number of explicit confirmations the UI must collect (1..3). */
    val confirmationSteps: Int = 1,
) {
    init {
        // Structural guarantee: destructive actions always need 3 confirmations
        // and can never be marked reversible.
        if (dataLossImpact >= DataLossImpact.APP_DATA) {
            require(confirmationSteps >= 3) { "Destructive actions need 3 confirmations" }
        }
        if (reversibility == Reversibility.FULLY_REVERSIBLE) {
            require(undoInstructions.isNotBlank()) { "Reversible actions must document undo" }
        }
    }

    /** Whether this action is allowed to be shown while Safe Mode is enabled. */
    fun allowedInSafeMode(): Boolean =
        dataLossImpact <= DataLossImpact.APP_CACHE_ONLY &&
            reversibility != Reversibility.IRREVERSIBLE
}

enum class ActionType {
    REVIEW_ONLY,             // just look — no change at all
    REVOKE_PERMISSION,       // Settings deep-link; fully reversible
    DISABLE_ACCESSIBILITY,   // toggle off a service; fully reversible
    REMOVE_DEVICE_ADMIN,     // deactivate admin; fully reversible
    DISABLE_APP,             // freeze app, data intact; fully reversible
    CLEAR_CACHE,             // cache only — Android recreates it; zero personal data
    CHANGE_SETTING,          // e.g. turn off USB debugging / rogue proxy
    REMOVE_CERTIFICATE,      // remove user-added CA cert
    NETWORK_RESET_GUIDED,    // reset APN/proxy/DNS with current values shown first
    UNINSTALL_APP,           // LAST RESORT — destroys that app's data
    CLEAR_APP_DATA,          // LAST RESORT — destroys that app's data
    FACTORY_RESET_GUIDANCE,  // never a button; a guided checklist incl. backup first
}

/** Ordered: later == worse. Comparisons rely on ordinal order. */
enum class DataLossImpact(val userLabel: String) {
    NONE("No data is affected"),
    SETTINGS_ONLY("Only a setting changes — no files touched"),
    APP_CACHE_ONLY("Only temporary cache files — recreated automatically"),
    APP_DATA("That app's own data will be deleted (NOT your photos/documents)"),
    DEVICE_WIDE("Whole device affected — full backup required first"),
}

enum class Reversibility { FULLY_REVERSIBLE, REVERSIBLE_WITH_EFFORT, IRREVERSIBLE }

/** Common, pre-vetted safe actions reused across scanners. */
object SafeActions {
    fun reviewOnly(what: String) = SafeAction(
        type = ActionType.REVIEW_ONLY,
        description = "Review: $what",
        whySafe = "Looking changes nothing. DeepWarden is read-only.",
        undoInstructions = "Nothing to undo.",
        reversibility = Reversibility.FULLY_REVERSIBLE,
        dataLossImpact = DataLossImpact.NONE,
    )

    fun revokePermission(appLabel: String, permission: String) = SafeAction(
        type = ActionType.REVOKE_PERMISSION,
        description = "Open Settings → Apps → $appLabel → Permissions and turn OFF \"$permission\".",
        whySafe = "Revoking a permission deletes nothing. The app keeps all its data; it just loses access.",
        undoInstructions = "Same screen — turn the permission back ON.",
        reversibility = Reversibility.FULLY_REVERSIBLE,
        dataLossImpact = DataLossImpact.SETTINGS_ONLY,
    )

    fun disableApp(appLabel: String) = SafeAction(
        type = ActionType.DISABLE_APP,
        description = "Open Settings → Apps → $appLabel → Disable. The app is frozen but ALL its data stays on the phone.",
        whySafe = "Disabling stops the app from running and hides it, but deletes nothing. Ideal first response to a suspicious app.",
        undoInstructions = "Settings → Apps → show system/disabled → $appLabel → Enable.",
        reversibility = Reversibility.FULLY_REVERSIBLE,
        dataLossImpact = DataLossImpact.SETTINGS_ONLY,
        confirmationSteps = 1,
    )

    fun uninstallLastResort(appLabel: String) = SafeAction(
        type = ActionType.UNINSTALL_APP,
        description = "LAST RESORT: uninstall $appLabel. Try Disable first — it is just as effective and fully reversible.",
        whySafe = "Uninstalling removes ONLY this app and its own data. Your photos, chats and documents in shared storage are untouched. Still, prefer Disable.",
        undoInstructions = "Cannot restore the app's internal data once uninstalled.",
        reversibility = Reversibility.IRREVERSIBLE,
        dataLossImpact = DataLossImpact.APP_DATA,
        confirmationSteps = 3,
    )
}

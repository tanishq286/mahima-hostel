package com.deepwarden.app.ui

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import com.deepwarden.app.core.ActionType
import com.deepwarden.app.core.Finding

/**
 * Turns a [Finding]'s recommended action into a one-tap system intent — the
 * "remove it safely" capability.
 *
 * HONEST SAFETY MODEL: a non-root app cannot delete or change another app
 * silently. Every intent below hands off to Android, which shows its OWN
 * confirmation (uninstall dialog, the app's settings page, the accessibility
 * list, etc.). The user is always the one who taps the final button. That is
 * exactly why a hacker's app cannot use this same path to wipe your apps.
 */
object RemediationLauncher {

    /** Human label for the action button. */
    fun buttonLabel(finding: Finding): String = when (finding.recommendedAction.type) {
        ActionType.UNINSTALL_APP, ActionType.CLEAR_APP_DATA -> "Remove app"
        ActionType.DISABLE_APP -> "Open to disable"
        ActionType.REVOKE_PERMISSION -> "Open permissions"
        ActionType.DISABLE_ACCESSIBILITY -> "Open accessibility"
        ActionType.REMOVE_DEVICE_ADMIN -> "Open device admins"
        ActionType.CLEAR_CACHE -> "Open app info"
        ActionType.CHANGE_SETTING, ActionType.NETWORK_RESET_GUIDED -> "Open settings"
        ActionType.REMOVE_CERTIFICATE -> "Open credentials"
        ActionType.FACTORY_RESET_GUIDANCE -> "Backup & reset guide"
        ActionType.REVIEW_ONLY -> "Open app info"
    }

    /**
     * Build the best system intent for this finding. Returns null if there is
     * nothing to launch (pure review with no subject app).
     */
    fun intentFor(context: Context, finding: Finding): Intent? {
        val pkg = finding.subjectPackage
        return when (finding.recommendedAction.type) {
            ActionType.UNINSTALL_APP, ActionType.CLEAR_APP_DATA -> pkg?.let {
                // Android's own uninstall confirmation dialog.
                Intent(Intent.ACTION_DELETE, Uri.parse("package:$it"))
            }
            ActionType.DISABLE_APP,
            ActionType.REVOKE_PERMISSION,
            ActionType.CLEAR_CACHE,
            ActionType.REVIEW_ONLY,
            -> pkg?.let { appDetails(it) }

            ActionType.DISABLE_ACCESSIBILITY ->
                Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)

            ActionType.REMOVE_DEVICE_ADMIN ->
                tryIntent(Settings.ACTION_SECURITY_SETTINGS)

            ActionType.REMOVE_CERTIFICATE ->
                tryIntent(Settings.ACTION_SECURITY_SETTINGS)

            ActionType.CHANGE_SETTING, ActionType.NETWORK_RESET_GUIDED ->
                tryIntent(Settings.ACTION_SETTINGS)

            ActionType.FACTORY_RESET_GUIDANCE -> null // never auto-launch a reset
        }?.apply { addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) }
    }

    private fun appDetails(pkg: String) =
        Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$pkg"))

    private fun tryIntent(action: String) = Intent(action)
}

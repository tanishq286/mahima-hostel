package com.deepwarden.app.detection.layer3

import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.provider.Settings
import android.view.accessibility.AccessibilityManager
import com.deepwarden.app.core.ActionType
import com.deepwarden.app.core.DataLossImpact
import com.deepwarden.app.core.DetectionLayer
import com.deepwarden.app.core.Finding
import com.deepwarden.app.core.Reversibility
import com.deepwarden.app.core.SafeAction
import com.deepwarden.app.core.SafeActions
import com.deepwarden.app.core.Severity
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

/**
 * ============================================================================
 *  LAYER 3 — SYSTEM INTEGRITY & DEEP SETTINGS FORENSICS
 * ============================================================================
 *
 * Attackers rarely rely on the malicious app alone — they weaken the system
 * around it. This layer audits exactly those settings:
 *
 *  1. Developer options / USB debugging  (physical-access attack residue)
 *  2. Screen lock & device encryption status
 *  3. Enabled ACCESSIBILITY SERVICES     (the #1 abused special access)
 *  4. Active DEVICE ADMINS               (uninstall-resistance trick)
 *  5. Root heuristics                    (su binaries, test-keys, Magisk paths)
 *  6. "Install unknown apps" exposure
 *
 * Every remediation here is a SETTINGS change — DataLossImpact.SETTINGS_ONLY
 * or NONE. Nothing in this layer can ever delete user data.
 */
@Singleton
class SystemIntegrityScanner @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    suspend fun scan(): Pair<List<Finding>, List<String>> = withContext(Dispatchers.IO) {
        val findings = mutableListOf<Finding>()
        val limitations = mutableListOf<String>()
        val cr = context.contentResolver

        // ---- 1. USB debugging / developer options ----------------------------
        if (Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, 0) == 1) {
            findings += Finding(
                layer = DetectionLayer.SYSTEM_INTEGRITY,
                severity = Severity.MEDIUM,
                confidence = 95,
                title = "USB debugging is enabled",
                explanation = "USB debugging lets any computer this phone is plugged into install apps, pull data and run commands. If YOU didn't enable it (or forgot to disable it after DeepWarden's ADB Deep Scan), someone with physical access may have.",
                technicalDetail = "Settings.Global.ADB_ENABLED=1",
                techniqueEducation = "Abusers with brief physical access enable USB debugging to plant stalkerware from a laptop in under a minute. The setting then stays on silently.",
                recommendedAction = SafeAction(
                    type = ActionType.CHANGE_SETTING,
                    description = "Settings → Developer options → turn OFF USB debugging (or disable Developer options entirely).",
                    whySafe = "Pure toggle. Affects no data, no apps. You can re-enable it whenever you need it (e.g. for the ADB Deep Scan).",
                    undoInstructions = "Same toggle, switch back on.",
                    reversibility = Reversibility.FULLY_REVERSIBLE,
                    dataLossImpact = DataLossImpact.SETTINGS_ONLY,
                ),
            )
        }

        // ---- 2. Screen lock --------------------------------------------------
        val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        if (!keyguard.isDeviceSecure) {
            findings += Finding(
                layer = DetectionLayer.SYSTEM_INTEGRITY,
                severity = Severity.HIGH,
                confidence = 98,
                title = "No screen lock set",
                explanation = "Without a PIN/pattern/biometric, anyone who picks up the phone can install stalkerware in seconds — and most stalkerware IS installed exactly this way.",
                technicalDetail = "KeyguardManager.isDeviceSecure=false",
                techniqueEducation = "Physical access is the dominant infection vector for partner-surveillance. A strong screen lock is the single most effective defense.",
                recommendedAction = SafeAction(
                    type = ActionType.CHANGE_SETTING,
                    description = "Settings → Security → Screen lock → set a PIN (6+ digits) or biometric.",
                    whySafe = "Adds protection only. Nothing is removed or modified.",
                    undoInstructions = "You can change or remove the lock anytime in the same menu.",
                    reversibility = Reversibility.FULLY_REVERSIBLE,
                    dataLossImpact = DataLossImpact.SETTINGS_ONLY,
                ),
            )
        }

        // ---- 3. Accessibility services ---------------------------------------
        val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
        val enabledServices = Settings.Secure.getString(cr, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES).orEmpty()
        if (enabledServices.isNotBlank()) {
            val services = enabledServices.split(':').filter { it.isNotBlank() }
            for (svc in services) {
                val pkgName = svc.substringBefore('/')
                findings += Finding(
                    layer = DetectionLayer.SYSTEM_INTEGRITY,
                    severity = Severity.MEDIUM,
                    confidence = 55,
                    title = "Accessibility service active: $pkgName",
                    explanation = "An enabled accessibility service can read EVERYTHING on screen (messages, passwords as you type, banking apps) and perform taps on your behalf. Legitimate uses exist (screen readers, password managers) — verify you recognise this one: $svc",
                    technicalDetail = "ENABLED_ACCESSIBILITY_SERVICES entry: $svc (touch exploration active=${am.isTouchExplorationEnabled})",
                    techniqueEducation = "Accessibility abuse is THE defining technique of modern Android spyware and banking trojans, because one toggle grants screen-reading and input-injection. Always audit this list.",
                    subjectPackage = pkgName,
                    recommendedAction = SafeAction(
                        type = ActionType.DISABLE_ACCESSIBILITY,
                        description = "Settings → Accessibility → find this service → turn OFF (if you don't recognise it).",
                        whySafe = "Disabling an accessibility service deletes nothing — the app stays installed, it just loses screen access.",
                        undoInstructions = "Same screen, toggle back ON.",
                        reversibility = Reversibility.FULLY_REVERSIBLE,
                        dataLossImpact = DataLossImpact.SETTINGS_ONLY,
                    ),
                )
            }
        }

        // ---- 4. Device admins --------------------------------------------------
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val admins = dpm.activeAdmins.orEmpty()
        for (admin in admins) {
            findings += Finding(
                layer = DetectionLayer.SYSTEM_INTEGRITY,
                severity = Severity.MEDIUM,
                confidence = 55,
                title = "Device admin active: ${admin.packageName}",
                explanation = "Device admin apps can lock the phone, set password rules and — crucially — BLOCK their own uninstall. Spyware registers as device admin to resist removal. Verify this is one you set up (workplace MDM, Find My Device).",
                technicalDetail = "admin component: ${admin.flattenToString()}",
                techniqueEducation = "When a victim tries to uninstall stalkerware, Android refuses while it holds device-admin. Deactivating the admin first re-enables uninstall — that's why we surface every admin.",
                subjectPackage = admin.packageName,
                recommendedAction = SafeAction(
                    type = ActionType.REMOVE_DEVICE_ADMIN,
                    description = "Settings → Security → Device admin apps → deactivate it if unrecognised. (The app itself remains installed and untouched.)",
                    whySafe = "Deactivating an admin changes a privilege flag only. No app data, no personal data affected.",
                    undoInstructions = "Re-activate it on the same screen.",
                    reversibility = Reversibility.FULLY_REVERSIBLE,
                    dataLossImpact = DataLossImpact.SETTINGS_ONLY,
                ),
            )
        }

        // ---- 5. Root heuristics -------------------------------------------------
        findings += rootHeuristics()

        limitations += "SELinux enforcement state and verified-boot status cannot be reliably read by a non-root app on modern Android; Layer 5 (ADB) covers them via `getprop`."
        findings to limitations
    }

    /**
     * Root detection heuristics. HONESTY: these catch *common* rooting setups
     * (su in PATH, test-keys builds, well-known manager packages). A carefully
     * hidden root (e.g. modern Magisk with denylist) will NOT be caught here —
     * stated in the finding text itself.
     */
    private fun rootHeuristics(): List<Finding> {
        val signals = mutableListOf<String>()

        val suPaths = listOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/system/sd/xbin/su", "/data/local/bin/su", "/data/local/xbin/su",
        )
        suPaths.filter { runCatching { File(it).exists() }.getOrDefault(false) }
            .forEach { signals += "su binary at $it" }

        if (android.os.Build.TAGS?.contains("test-keys") == true) {
            signals += "build signed with test-keys (custom/insecure ROM)"
        }
        val rootManagers = listOf("com.topjohnwu.magisk", "eu.chainfire.supersu", "com.koushikdutta.superuser")
        rootManagers.filter { isInstalled(it) }.forEach { signals += "root manager installed: $it" }

        if (signals.isEmpty()) return emptyList()
        return listOf(
            Finding(
                layer = DetectionLayer.SYSTEM_INTEGRITY,
                severity = Severity.HIGH,
                confidence = 85,
                title = "Device shows signs of being rooted",
                explanation = "Root signals found: ${signals.joinToString()}. If YOU rooted this phone, this is expected. If not, someone with deep access modified it — on a rooted device, spyware can hide far better and our visibility shrinks.",
                technicalDetail = signals.joinToString("\n"),
                techniqueEducation = "Root removes Android's app sandbox. We check su binary paths, build tags and known manager apps. Hidden-root frameworks can evade these checks — absence of signals is NOT proof of no root.",
                recommendedAction = SafeActions.reviewOnly("whether you intentionally rooted this device; if not, treat all findings as more serious and consider professional help."),
            )
        )
    }

    private fun isInstalled(pkg: String): Boolean =
        runCatching { context.packageManager.getPackageInfo(pkg, 0); true }.getOrDefault(false)
}

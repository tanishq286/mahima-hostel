package com.deepwarden.app.detection.layer2

import android.app.AppOpsManager
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.PowerManager
import android.os.Process
import com.deepwarden.app.core.DetectionLayer
import com.deepwarden.app.core.Finding
import com.deepwarden.app.core.SafeActions
import com.deepwarden.app.core.Severity
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton

/**
 * ============================================================================
 *  LAYER 2 — ADVANCED HEURISTIC & BEHAVIORAL DETECTION
 * ============================================================================
 *
 * Combines the [PermissionScoring] table with live behavioral telemetry:
 *
 *  A. Permission-combination scoring (see PermissionScoring for the table).
 *  B. Background-runtime anomaly: apps with near-zero foreground time but high
 *     total runtime (via UsageStatsManager) — spyware runs while you don't look.
 *  C. Battery-optimization exemption abuse: non-messaging apps that demanded
 *     "ignore battery optimizations" to stay resident forever.
 *  D. Stealth signals folded in from Layer 1 (icon hiding) raise confidence.
 *
 * GRACEFUL DEGRADATION: if Usage Access isn't granted, B is skipped and the
 * scan's limitation list says so explicitly — never silently.
 */
@Singleton
class BehavioralHeuristicsScanner @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    suspend fun scan(): Pair<List<Finding>, List<String>> = withContext(Dispatchers.Default) {
        val findings = mutableListOf<Finding>()
        val limitations = mutableListOf<String>()
        val pm = context.packageManager

        val packages = runCatching {
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        }.getOrDefault(emptyList())

        // ---- A. Permission combination scoring ------------------------------
        for (pkg in packages) {
            val app = pkg.applicationInfo ?: continue
            if (pkg.packageName == context.packageName) continue
            if (app.flags and ApplicationInfo.FLAG_SYSTEM != 0) continue

            val granted = grantedPermissions(pkg)
            val score = PermissionScoring.score(granted)
            // Apps from a vetted store are held to a higher bar: a permission
            // profile alone is weak evidence for a Play-Store app the user chose
            // to install. Only surface store apps when the score is EXTREME; for
            // sideloaded apps, the normal MEDIUM threshold applies.
            val trusted = com.deepwarden.app.detection.common.InstallerTrust
                .of(context, pkg.packageName).trusted
            val threshold = if (trusted) PermissionScoring.BAND_EXTREME else PermissionScoring.BAND_MEDIUM
            if (score.normalised >= threshold) {
                findings += permissionFinding(
                    pkg, pm.getApplicationLabel(app).toString(), score, trusted,
                )
            }
        }

        // ---- B. Background runtime anomaly ----------------------------------
        if (hasUsageAccess()) {
            findings += backgroundAnomalies(packages)
        } else {
            limitations += "Usage Access not granted → background-runtime anomaly detection skipped. Grant it in Settings → Special access → Usage access (read-only, revocable anytime)."
        }

        // ---- C. Battery exemption abuse --------------------------------------
        findings += batteryExemptionAbuse(packages)

        findings to limitations
    }

    private fun permissionFinding(
        pkg: PackageInfo,
        label: String,
        score: PermissionScoring.PermissionScore,
        trustedInstaller: Boolean,
    ): Finding {
        val severity = when {
            // A store-installed app, even at an extreme score, is downgraded one
            // level — we report it for awareness, not as a likely threat.
            trustedInstaller -> Severity.MEDIUM
            score.normalised >= PermissionScoring.BAND_EXTREME -> Severity.CRITICAL
            score.normalised >= PermissionScoring.BAND_HIGH -> Severity.HIGH
            else -> Severity.MEDIUM
        }
        // Honesty cap: permission profile alone is never >75% certain — and far
        // less for a store app the user deliberately installed.
        val confidence = if (trustedInstaller) {
            (25 + score.normalised / 4).coerceAtMost(45)
        } else {
            (40 + score.normalised / 2).coerceAtMost(75)
        }
        val comboText = if (score.triggeredCombos.isEmpty()) "" else
            "\n\nMatched patterns: " + score.triggeredCombos.joinToString("; ") { "${it.name} — ${it.education}" }
        return Finding(
            layer = DetectionLayer.BEHAVIORAL_HEURISTICS,
            severity = severity,
            confidence = confidence,
            title = "High-risk permission profile: \"$label\" (${score.normalised}/100)",
            explanation = "\"$label\" combines: ${score.contributing.keys.joinToString { it.substringAfterLast('.') }}. " +
                "This combination matches surveillance-software profiles.$comboText" +
                "\n\nIMPORTANT: a legitimate app you knowingly installed (e.g. an SMS backup tool) can score high. Ask yourself: did I install this, and does it need all of these?",
            technicalDetail = score.contributing.entries.joinToString("\n") { "${it.key} = +${it.value}" } +
                "\nraw=${score.raw} normalised=${score.normalised}",
            techniqueEducation = "Spyware needs a recognisable bundle of permissions to spy. We weight each permission and multiply known-bad combinations — the same approach professional analysts use for APK triage.",
            subjectPackage = pkg.packageName,
            subjectAppLabel = label,
            recommendedAction = SafeActions.revokePermission(label, "the permissions listed above that it doesn't obviously need"),
        )
    }

    /**
     * B: apps whose total runtime dwarfs their visible (foreground) time.
     * Spyware's defining behavior: always running, never used.
     */
    private fun backgroundAnomalies(packages: List<PackageInfo>): List<Finding> {
        val usm = context.getSystemService(Context.USAGE_STATS_SERVICE) as UsageStatsManager
        val now = System.currentTimeMillis()
        val stats = usm.queryUsageStats(UsageStatsManager.INTERVAL_WEEKLY, now - TimeUnit.DAYS.toMillis(7), now)
            ?: return emptyList()
        val byPackage = stats.associateBy { it.packageName }
        val out = mutableListOf<Finding>()
        val pm = context.packageManager

        for (pkg in packages) {
            val app = pkg.applicationInfo ?: continue
            if (app.flags and ApplicationInfo.FLAG_SYSTEM != 0) continue
            val s = byPackage[pkg.packageName] ?: continue
            val foregroundMin = TimeUnit.MILLISECONDS.toMinutes(s.totalTimeInForeground)
            val granted = grantedPermissions(pkg)
            val risky = granted.count { it in PermissionScoring.WEIGHTS && PermissionScoring.WEIGHTS.getValue(it) >= 10 }
            // Heuristic: powerful permissions + virtually never opened by the user.
            if (risky >= 2 && foregroundMin < 2) {
                val label = pm.getApplicationLabel(app).toString()
                out += Finding(
                    layer = DetectionLayer.BEHAVIORAL_HEURISTICS,
                    severity = Severity.MEDIUM,
                    confidence = 60,
                    title = "\"$label\" holds spy-grade permissions but you never open it",
                    explanation = "In the last 7 days \"$label\" was on screen for under 2 minutes, yet it holds $risky high-risk permissions. Software you don't use shouldn't be watching anything.",
                    technicalDetail = "foreground=${foregroundMin}min/7d, risky permissions=$risky",
                    techniqueEducation = "Stalkerware is designed to be forgotten: zero interaction, constant background presence. Usage statistics expose exactly that gap.",
                    subjectPackage = pkg.packageName,
                    subjectAppLabel = label,
                    recommendedAction = SafeActions.revokePermission(label, "its unused sensitive permissions"),
                )
            }
        }
        return out
    }

    /** C: battery-exemption + sensitive permissions on non-system apps. */
    private fun batteryExemptionAbuse(packages: List<PackageInfo>): List<Finding> {
        val power = context.getSystemService(Context.POWER_SERVICE) as PowerManager
        val pm = context.packageManager
        val out = mutableListOf<Finding>()
        for (pkg in packages) {
            val app = pkg.applicationInfo ?: continue
            if (app.flags and ApplicationInfo.FLAG_SYSTEM != 0) continue
            if (!power.isIgnoringBatteryOptimizations(pkg.packageName)) continue
            val granted = grantedPermissions(pkg)
            val score = PermissionScoring.score(granted)
            if (score.normalised >= PermissionScoring.BAND_HIGH) {
                val label = pm.getApplicationLabel(app).toString()
                out += Finding(
                    layer = DetectionLayer.BEHAVIORAL_HEURISTICS,
                    severity = Severity.HIGH,
                    confidence = 70,
                    title = "\"$label\" is exempt from battery limits AND heavily permissioned",
                    explanation = "\"$label\" persuaded Android to never put it to sleep, while also holding a high-risk permission set (${score.normalised}/100). This pairing is how spyware guarantees 24/7 operation.",
                    technicalDetail = "isIgnoringBatteryOptimizations=true, permScore=${score.normalised}",
                    techniqueEducation = "Doze mode would normally suspend background spying. Malware asks for the exemption during setup so surveillance never pauses — we cross-check the exemption list against permission risk.",
                    subjectPackage = pkg.packageName,
                    subjectAppLabel = label,
                    recommendedAction = SafeActions.revokePermission(label, "battery optimization exemption (Settings → Battery)"),
                )
            }
        }
        return out
    }

    private fun grantedPermissions(pkg: PackageInfo): List<String> {
        val requested = pkg.requestedPermissions ?: return emptyList()
        val flags = pkg.requestedPermissionsFlags ?: return requested.toList()
        return requested.filterIndexed { i, _ ->
            flags.getOrElse(i) { 0 } and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0
        }
    }

    private fun hasUsageAccess(): Boolean {
        val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
        val mode = appOps.unsafeCheckOpNoThrow(
            AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), context.packageName
        )
        return mode == AppOpsManager.MODE_ALLOWED
    }
}

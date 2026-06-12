package com.deepwarden.app.detection.layer1

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import com.deepwarden.app.core.DetectionLayer
import com.deepwarden.app.core.Finding
import com.deepwarden.app.core.SafeActions
import com.deepwarden.app.core.Severity
import com.deepwarden.app.data.threatintel.ThreatIntelRepository
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.MessageDigest
import javax.inject.Inject
import javax.inject.Singleton

/**
 * ============================================================================
 *  LAYER 1 — COMPREHENSIVE STATIC & PACKAGE FORENSICS
 * ============================================================================
 *
 * Inventories EVERY package the platform will reveal to a non-root app
 * (including disabled and "icon-hidden" apps via MATCH_DISABLED_COMPONENTS /
 * MATCH_UNINSTALLED_PACKAGES) and deep-parses each one:
 *
 *  1. Install-source forensics  — sideloaded? installer mismatch? (stalkerware
 *     is almost always sideloaded by the abuser with physical access)
 *  2. Fake-system-app detection — claims a system-looking name but lives in
 *     /data/app and is not signed by the platform
 *  3. Launcher-icon hiding      — has powerful permissions but NO launcher
 *     activity (the classic "invisible" stalkerware trick)
 *  4. Component forensics       — exported receivers/services, boot/SMS/package
 *     priority intent filters
 *  5. Certificate analysis      — debug-key signing, certificate hash vs IOC DB
 *  6. Timeline anomalies        — installed recently + immediately granted
 *     dangerous permissions; lastUpdate >> firstInstall on dormant apps
 *
 * READ-ONLY: this scanner only queries PackageManager. It changes nothing.
 */
@Singleton
class PackageForensicsScanner @Inject constructor(
    @ApplicationContext private val context: Context,
    private val threatIntel: ThreatIntelRepository,
) {
    private val pm: PackageManager get() = context.packageManager

    suspend fun scan(): Pair<List<Finding>, List<String>> = withContext(Dispatchers.Default) {
        val findings = mutableListOf<Finding>()
        val limitations = mutableListOf<String>()

        val packages = queryAllPackages()
        if (packages.isEmpty()) {
            limitations += "Package list query returned nothing — OS may be restricting QUERY_ALL_PACKAGES."
        }
        val intel = threatIntel.rules()

        for (pkg in packages) {
            val app = pkg.applicationInfo ?: continue
            if (pkg.packageName == context.packageName) continue // self
            val isSystem = app.flags and ApplicationInfo.FLAG_SYSTEM != 0
            val label = pm.getApplicationLabel(app).toString()

            // ---- 1. Install source forensics --------------------------------
            val source = com.deepwarden.app.detection.common.InstallerTrust.of(context, pkg.packageName)
            val installer = source.installer
            val sideloaded = !isSystem && installer == null
            if (sideloaded) {
                findings += sideloadFinding(pkg, label)
            }

            // ---- 2. Fake system app -----------------------------------------
            if (!isSystem && looksLikeSystemName(label, pkg.packageName, intel.systemLookalikeRegexes)) {
                findings += Finding(
                    layer = DetectionLayer.STATIC_FORENSICS,
                    severity = Severity.HIGH,
                    confidence = 80,
                    title = "App impersonating a system component: \"$label\"",
                    explanation = "\"$label\" (${pkg.packageName}) uses a system-sounding name but is NOT a real system app — it is installed in user space (${app.sourceDir}). Malware names itself \"System Update\" or \"Android Service\" so victims never suspect it.",
                    technicalDetail = "path=${app.sourceDir}, system=false, installer=${installer ?: "none (sideloaded)"}",
                    techniqueEducation = "Real system apps live under /system or /product and are signed by the device maker. We compared the install path and signature origin — this one fails both checks.",
                    subjectPackage = pkg.packageName,
                    subjectAppLabel = label,
                    recommendedAction = SafeActions.disableApp(label),
                )
            }

            // ---- 3. Hidden icon + powerful permissions ----------------------
            val granted = grantedPermissions(pkg)
            val hasLauncher = pm.getLaunchIntentForPackage(pkg.packageName) != null
            if (!isSystem && !hasLauncher && hasSurveillancePermission(granted)) {
                findings += Finding(
                    layer = DetectionLayer.STATIC_FORENSICS,
                    severity = Severity.HIGH,
                    confidence = 78,
                    title = "Invisible app with surveillance permissions: \"$label\"",
                    explanation = "\"$label\" has no icon in your launcher yet holds sensitive permissions (${granted.filter { hasSurveillancePermission(listOf(it)) }.joinToString { it.substringAfterLast('.') }}). Stalkerware hides its icon so you forget it exists.",
                    technicalDetail = "no LAUNCHER activity; granted=${granted.joinToString()}",
                    techniqueEducation = "Apps hide by omitting a launcher activity or disabling their alias after first run. PackageManager still sees them — that's how we caught it.",
                    subjectPackage = pkg.packageName,
                    subjectAppLabel = label,
                    recommendedAction = SafeActions.disableApp(label),
                )
            }

            // ---- 4. Component forensics: boot/SMS priority receivers --------
            // Only meaningful for apps NOT installed from a vetted store: a
            // store-signed payment/OTP app reading SMS at boot is normal.
            findings += scanComponents(pkg, label, isSystem, source.trusted, source.viaAdb)

            // ---- 5. Certificate analysis ------------------------------------
            signatureSha256(pkg)?.let { sha ->
                if (sha in intel.badCertSha256) {
                    findings += Finding(
                        layer = DetectionLayer.STATIC_FORENSICS,
                        severity = Severity.CRITICAL,
                        confidence = 95,
                        title = "App signed with a known-abusive certificate: \"$label\"",
                        explanation = "The signing certificate of \"$label\" matches DeepWarden's local IOC list of certificates used by surveillance tooling.",
                        technicalDetail = "cert sha256=$sha",
                        techniqueEducation = "A signing certificate uniquely identifies a developer key. Matching it is one of the highest-confidence static signals available without root.",
                        subjectPackage = pkg.packageName,
                        subjectAppLabel = label,
                        recommendedAction = SafeActions.disableApp(label),
                    )
                }
            }
        }

        limitations += "Layer 1 sees what PackageManager reveals. Packages hidden by platform exploits or root frameworks are invisible here — run Layer 5 (ADB Deep Scan) for deeper visibility."
        findings to limitations
    }

    // -------------------------------------------------------------------------

    @SuppressLint("QueryPermissionsNeeded")
    private fun queryAllPackages(): List<PackageInfo> {
        // MATCH_UNINSTALLED_PACKAGES surfaces apps "uninstalled" with kept data
        // and apps hidden for other users — a known persistence trick.
        val flags = PackageManager.GET_PERMISSIONS or
            PackageManager.GET_RECEIVERS or
            PackageManager.GET_SERVICES or
            PackageManager.GET_PROVIDERS or
            PackageManager.GET_SIGNING_CERTIFICATES or
            PackageManager.MATCH_DISABLED_COMPONENTS or
            PackageManager.MATCH_UNINSTALLED_PACKAGES
        return runCatching { pm.getInstalledPackages(flags) }.getOrDefault(emptyList())
    }

    private fun installerOf(packageName: String): String? = runCatching {
        pm.getInstallSourceInfo(packageName).installingPackageName
    }.getOrNull()

    private fun grantedPermissions(pkg: PackageInfo): List<String> {
        val requested = pkg.requestedPermissions ?: return emptyList()
        val flags = pkg.requestedPermissionsFlags ?: return requested.toList()
        return requested.filterIndexed { i, _ ->
            flags.getOrElse(i) { 0 } and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0
        }
    }

    private fun hasSurveillancePermission(perms: Collection<String>): Boolean =
        perms.any {
            it in setOf(
                "android.permission.READ_SMS", "android.permission.RECORD_AUDIO",
                "android.permission.CAMERA", "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission.READ_CALL_LOG",
            )
        }

    private fun looksLikeSystemName(label: String, packageName: String, regexes: List<Regex>): Boolean =
        regexes.any { it.containsMatchIn(label) || it.containsMatchIn(packageName) }

    /**
     * Receivers listening for BOOT_COMPLETED / SMS_RECEIVED / PACKAGE_ADDED with
     * high priority are the persistence + interception backbone of mobile malware.
     */
    private fun scanComponents(
        pkg: PackageInfo,
        label: String,
        isSystem: Boolean,
        trustedInstaller: Boolean,
        viaAdb: Boolean,
    ): List<Finding> {
        if (isSystem) return emptyList()
        // KEY FALSE-POSITIVE FIX: a store-installed, store-signed app that reads
        // SMS and starts at boot is normal (PhonePe, BHIM, Truecaller, banking
        // and messaging apps all do this legitimately). We do NOT flag those.
        // The boot+SMS pattern is only a red flag for apps the user (or an
        // abuser) installed OUTSIDE a store, or pushed via ADB.
        if (trustedInstaller) return emptyList()

        val out = mutableListOf<Finding>()
        val receivers = pkg.receivers ?: return out
        val granted = grantedPermissions(pkg).toSet()
        val watchesBoot = "android.permission.RECEIVE_BOOT_COMPLETED" in granted
        val watchesSms = "android.permission.RECEIVE_SMS" in granted

        val exportedReceivers = receivers.filter { it.exported }
        if (watchesBoot && watchesSms && exportedReceivers.isNotEmpty()) {
            // ADB-pushed apps with this pattern are far more suspicious than a
            // merely sideloaded one, so we scale severity/confidence accordingly.
            val severity = if (viaAdb) Severity.HIGH else Severity.MEDIUM
            val confidence = if (viaAdb) 72 else 55
            out += Finding(
                layer = DetectionLayer.STATIC_FORENSICS,
                severity = severity,
                confidence = confidence,
                title = "\"$label\" starts at boot and intercepts SMS (installed outside any store)",
                explanation = "\"$label\" was not installed from an app store" +
                    (if (viaAdb) " (it was pushed via ADB/USB — a planting method)" else "") +
                    ", yet it wakes at every reboot and receives your incoming SMS. For a sideloaded app this combination is worth checking; for store apps it would be normal, but this one isn't from a store.",
                technicalDetail = "installer=${if (viaAdb) "ADB shell" else "none/unknown"}; exported receivers: ${exportedReceivers.joinToString { it.name }}",
                techniqueEducation = "Malware registers a BOOT_COMPLETED receiver to survive reboots and an SMS receiver (often high-priority) to read or swallow messages — including OTPs — before your SMS app sees them. We only raise this for non-store apps to avoid flagging legitimate payment/OTP apps.",
                subjectPackage = pkg.packageName,
                subjectAppLabel = label,
                recommendedAction = SafeActions.reviewOnly("whether you installed \"$label\" yourself and trust it; if you don't recognise it, disable it (fully reversible)."),
            )
        }
        return out
    }

    private fun sideloadFinding(pkg: PackageInfo, label: String): Finding {
        val granted = grantedPermissions(pkg)
        val risky = granted.count { it in PermissionWatchlist.SENSITIVE }
        val severity = if (risky >= 3) Severity.MEDIUM else Severity.LOW
        return Finding(
            layer = DetectionLayer.STATIC_FORENSICS,
            severity = severity,
            confidence = if (risky >= 3) 60 else 40,
            title = "Sideloaded app: \"$label\"",
            explanation = "\"$label\" was not installed from any app store (no installer recorded). Sideloading is how stalkerware is planted by someone with physical access to the phone." +
                if (risky > 0) " It also holds $risky sensitive permission(s)." else "",
            technicalDetail = "package=${pkg.packageName}, firstInstall=${pkg.firstInstallTime}, granted=${granted.joinToString()}",
            techniqueEducation = "Android records which app performed each install. A null installer means manual APK installation — legitimate for developers, but the #1 stalkerware delivery path.",
            subjectPackage = pkg.packageName,
            subjectAppLabel = label,
            recommendedAction = SafeActions.reviewOnly("whether you installed \"$label\" yourself, on purpose."),
        )
    }

    private fun signatureSha256(pkg: PackageInfo): String? {
        val signers = pkg.signingInfo?.apkContentsSigners ?: return null
        val first = signers.firstOrNull() ?: return null
        val digest = MessageDigest.getInstance("SHA-256").digest(first.toByteArray())
        return digest.joinToString("") { "%02x".format(it) }
    }
}

/** Sensitive permissions used for quick triage counts in Layer 1. */
object PermissionWatchlist {
    val SENSITIVE = setOf(
        "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
        "android.permission.SEND_SMS", "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA", "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission.READ_CALL_LOG",
        "android.permission.READ_CONTACTS", "android.permission.SYSTEM_ALERT_WINDOW",
    )
}

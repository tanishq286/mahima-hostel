package com.deepwarden.app.detection.layer7

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import com.deepwarden.app.core.DetectionLayer
import com.deepwarden.app.core.Finding
import com.deepwarden.app.core.SafeActions
import com.deepwarden.app.core.Severity
import com.deepwarden.app.data.cloud.VirusTotalClient
import com.deepwarden.app.detection.common.InstallerTrust
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

/**
 * LAYER 7 — cloud reputation via [VirusTotalClient].
 *
 * Strategy that respects free-tier rate limits AND privacy:
 *   - Only runs when enabled + an API key is present.
 *   - Only checks the SUSPICIOUS subset: apps NOT from a vetted store (these
 *     are the realistic threat candidates), capped at [MAX_LOOKUPS] per scan.
 *   - Sends only the APK SHA-256 hash. Throttles to stay under ~4 req/min.
 *   - A clean VirusTotal result is reported as reassurance; a hit is a
 *     high-confidence threat because it reflects dozens of commercial engines.
 */
@Singleton
class CloudReputationScanner @Inject constructor(
    @ApplicationContext private val context: Context,
    private val vt: VirusTotalClient,
) {
    suspend fun scan(apiKey: String): Pair<List<Finding>, List<String>> =
        withContext(Dispatchers.Default) {
            val findings = mutableListOf<Finding>()
            val limitations = mutableListOf<String>()
            if (apiKey.isBlank()) {
                limitations += "Cloud reputation (Layer 7) skipped: no VirusTotal API key set. Add one in Settings to enable global malware-database checks."
                return@withContext findings to limitations
            }
            val pm = context.packageManager
            val packages = runCatching { pm.getInstalledPackages(0) }.getOrDefault(emptyList())

            // Candidate set: non-system apps installed OUTSIDE a vetted store.
            val candidates = packages.filter { pkg ->
                val app = pkg.applicationInfo ?: return@filter false
                if (app.flags and ApplicationInfo.FLAG_SYSTEM != 0) return@filter false
                if (pkg.packageName == context.packageName) return@filter false
                !InstallerTrust.of(context, pkg.packageName).trusted
            }.take(MAX_LOOKUPS)

            if (candidates.isEmpty()) {
                limitations += "Cloud reputation: no sideloaded apps to check (all your apps came from trusted stores)."
                return@withContext findings to limitations
            }

            var checked = 0
            var errors = 0
            for (pkg in candidates) {
                val app = pkg.applicationInfo ?: continue
                val label = pm.getApplicationLabel(app).toString()
                val apk = app.sourceDir?.let { File(it) } ?: continue
                val hash = vt.sha256(apk) ?: continue

                val verdict = vt.lookup(hash, apiKey)
                if (verdict.error != null) {
                    errors++
                    if (verdict.error.contains("Rate limit")) {
                        limitations += "Cloud reputation stopped early at rate limit — checked $checked app(s). Free keys allow ~4/min; re-scan later for more."
                        break
                    }
                    continue
                }
                checked++

                when {
                    verdict.found && verdict.malicious >= 1 -> {
                        val severity = if (verdict.malicious >= 5) Severity.CRITICAL else Severity.HIGH
                        // Cloud-backed: many independent engines agreeing is the
                        // strongest signal this app produces.
                        val confidence = (60 + verdict.malicious * 3).coerceAtMost(98)
                        findings += Finding(
                            layer = DetectionLayer.CLOUD_REPUTATION,
                            severity = severity,
                            confidence = confidence,
                            title = "\"$label\" flagged by ${verdict.malicious} antivirus engines",
                            explanation = "VirusTotal reports that ${verdict.malicious} of ${verdict.totalEngines} security engines classify this app as malicious" +
                                (verdict.popularLabel?.let { " (\"$it\")" } ?: "") +
                                ". This is a strong, cloud-backed verdict from the global security community — treat it seriously.",
                            technicalDetail = "sha256=$hash\nmalicious=${verdict.malicious} suspicious=${verdict.suspicious} harmless=${verdict.harmless} of ${verdict.totalEngines}",
                            techniqueEducation = "VirusTotal aggregates 70+ commercial antivirus engines. A hash match across many engines is far stronger than any single on-device heuristic — this is how professionals confirm malware.",
                            subjectPackage = pkg.packageName,
                            subjectAppLabel = label,
                            recommendedAction = SafeActions.disableApp(label),
                        )
                    }
                    verdict.found && verdict.suspicious >= 2 -> {
                        findings += Finding(
                            layer = DetectionLayer.CLOUD_REPUTATION,
                            severity = Severity.MEDIUM,
                            confidence = 55,
                            title = "\"$label\" marked suspicious by ${verdict.suspicious} engines",
                            explanation = "VirusTotal shows ${verdict.suspicious} engines find this app suspicious (not outright malicious). Worth reviewing whether you trust its source.",
                            technicalDetail = "sha256=$hash\nsuspicious=${verdict.suspicious} of ${verdict.totalEngines}",
                            techniqueEducation = "\"Suspicious\" means heuristic engines saw risky traits without a confirmed signature. Combined with sideloaded install, it raises the priority.",
                            subjectPackage = pkg.packageName,
                            subjectAppLabel = label,
                            recommendedAction = SafeActions.reviewOnly("whether you trust the source of \"$label\"; disable it if unsure (reversible)."),
                        )
                    }
                    // found && clean → no finding (silent good news); not-found → see limitation below
                }

                // Throttle: stay under the free tier's ~4 requests/minute.
                delay(THROTTLE_MS)
            }

            limitations += "Cloud reputation checked $checked sideloaded app(s) against VirusTotal." +
                (if (errors > 0) " $errors lookup(s) failed (network/limits)." else "") +
                " Apps unknown to VirusTotal are not proven safe — a brand-new threat may not be in the database yet."
            findings to limitations
        }

    private companion object {
        const val MAX_LOOKUPS = 12      // free-tier friendly per scan
        const val THROTTLE_MS = 16_000L // ~4/min
    }
}

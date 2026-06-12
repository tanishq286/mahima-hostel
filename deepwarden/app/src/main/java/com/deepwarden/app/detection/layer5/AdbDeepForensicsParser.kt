package com.deepwarden.app.detection.layer5

import com.deepwarden.app.core.DetectionLayer
import com.deepwarden.app.core.Finding
import com.deepwarden.app.core.SafeActions
import com.deepwarden.app.core.Severity
import javax.inject.Inject
import javax.inject.Singleton

/**
 * ============================================================================
 *  LAYER 5 — EXPERT ADB-ASSISTED DEEP FORENSIC MODE
 *  ("very deep in the system" without root)
 * ============================================================================
 *
 * The ADB shell runs as the `shell` UID, which sees FAR more than any
 * installed app: full package paths, dumpsys internals, kernel version,
 * system properties, process lists. DeepWarden never executes commands itself;
 * the USER runs a curated set of READ-ONLY commands on a computer and pastes
 * the output here. This file is a pure parser — no Android dependencies —
 * so the whole layer is unit-testable.
 *
 * SAFETY: every command in [SAFE_COMMANDS] is read-only (list/dump/cat/getprop).
 * None can modify the device. The guide screen also reminds the user to turn
 * USB debugging OFF afterwards (and Layer 3 will nag if they forget).
 *
 * The parser auto-detects which command produced a pasted block, so users can
 * paste everything in one go.
 */
@Singleton
class AdbDeepForensicsParser @Inject constructor() {

    data class SafeCommand(val command: String, val purpose: String)

    companion object {
        /** The curated, read-only command set shown in the guided UI. */
        val SAFE_COMMANDS = listOf(
            SafeCommand("adb shell pm list packages -f -u", "Every package incl. 'uninstalled-with-kept-data' ones, with on-disk APK paths"),
            SafeCommand("adb shell pm list packages -d", "Disabled packages (malware sometimes disables itself between tasks)"),
            SafeCommand("adb shell getprop", "System properties: debug flags, verified boot state, OEM unlock"),
            SafeCommand("adb shell cat /proc/version", "Kernel build string — custom/test kernels stand out"),
            SafeCommand("adb shell dumpsys package queries", "Which apps can see which others (broad visibility = recon)"),
            SafeCommand("adb shell dumpsys accessibility", "Authoritative list of bound accessibility services"),
            SafeCommand("adb shell dumpsys deviceidle whitelist", "Apps exempt from Doze (persistence list)"),
            SafeCommand("adb shell dumpsys activity services", "Long-running services right now"),
            SafeCommand("adb shell settings list global", "Global settings incl. proxy/ADB flags, raw"),
            SafeCommand("adb shell which su", "Quick root probe from the shell UID"),
        )

        // ---- detection patterns (kept generic & responsible: behaviors/paths,
        // ---- never malware code) ------------------------------------------------
        private val SUSPICIOUS_PATH = Regex("""^package:(/data/(?:local/tmp|data/[^/]+/files)/[^=]+\.apk)=(\S+)""")
        private val PKG_LINE = Regex("""^package:(\S+\.apk)=(\S+)$""")
        private val TEST_KEYS = Regex("""\btest-keys\b""")
        private val KERNEL_NONSTOCK = Regex("""(lineage|cyanogen|kali|nethunter|custom)""", RegexOption.IGNORE_CASE)
        private val DANGEROUS_PROPS = mapOf(
            "[ro.debuggable]: [1]" to "Build is debuggable — apps can be debugged/injected at runtime",
            "[ro.secure]: [0]" to "ADB root shell allowed — a major integrity red flag on a consumer device",
            "[ro.boot.verifiedbootstate]: [orange]" to "Verified Boot reports ORANGE: the bootloader is UNLOCKED",
            "[ro.boot.flash.locked]: [0]" to "Bootloader flash-unlocked — system partitions can be rewritten",
            "[sys.oem_unlock_allowed]: [1]" to "OEM unlocking permitted in developer options",
        )
        private val SU_FOUND = Regex("""^(/\S*/su)\s*$""", RegexOption.MULTILINE)
    }

    /**
     * Parse an arbitrary paste (one or many command outputs concatenated).
     * Returns findings + the honest list of what was NOT in the paste.
     */
    fun parse(pastedOutput: String): Pair<List<Finding>, List<String>> {
        val findings = mutableListOf<Finding>()
        val limitations = mutableListOf<String>()
        val text = pastedOutput.trim()
        if (text.isEmpty()) return emptyList<Finding>() to listOf("No ADB output pasted yet.")

        var sawPackages = false
        var sawProps = false

        // ---- pm list packages -f: path anomalies -----------------------------
        text.lineSequence().forEach { line ->
            SUSPICIOUS_PATH.find(line.trim())?.let { m ->
                sawPackages = true
                findings += Finding(
                    layer = DetectionLayer.ADB_DEEP_FORENSICS,
                    severity = Severity.CRITICAL,
                    confidence = 90,
                    title = "APK running from a staging path: ${m.groupValues[2]}",
                    explanation = "Package ${m.groupValues[2]} is installed from ${m.groupValues[1]}. /data/local/tmp is the ADB upload directory — normal apps NEVER live there. This strongly suggests a manually planted tool.",
                    technicalDetail = line.trim(),
                    techniqueEducation = "Attackers with ADB access push an APK to /data/local/tmp and install it in place. Only the shell user sees this path — which is exactly why Layer 5 exists.",
                    subjectPackage = m.groupValues[2],
                    recommendedAction = SafeActions.disableApp(m.groupValues[2]),
                )
            }
            if (PKG_LINE.matches(line.trim())) sawPackages = true
        }

        // ---- getprop: dangerous system properties ----------------------------
        DANGEROUS_PROPS.forEach { (needle, meaning) ->
            if (text.contains(needle)) {
                sawProps = true
                findings += Finding(
                    layer = DetectionLayer.ADB_DEEP_FORENSICS,
                    severity = Severity.HIGH,
                    confidence = 92,
                    title = "System property red flag: ${needle.substringBefore(']')}]",
                    explanation = meaning + ". If you did not modify this device, these properties should not look like this.",
                    technicalDetail = needle,
                    techniqueEducation = "System properties are set by the boot chain and are readable—but not fakeable—via `getprop` from the shell. They reveal integrity states no normal app can query.",
                    recommendedAction = SafeActions.reviewOnly("device integrity — consider re-locking the bootloader / reflashing stock firmware if this is unexpected (guided, backup-first checklist in app)."),
                )
            }
        }
        if (text.contains("[ro.build.tags]")) sawProps = true

        // ---- kernel string ------------------------------------------------------
        if (text.contains("Linux version")) {
            if (TEST_KEYS.containsMatchIn(text) || KERNEL_NONSTOCK.containsMatchIn(text.lineSequence().first { it.contains("Linux version") })) {
                findings += Finding(
                    layer = DetectionLayer.ADB_DEEP_FORENSICS,
                    severity = Severity.HIGH,
                    confidence = 80,
                    title = "Non-stock kernel detected",
                    explanation = "The kernel build string indicates a custom or test-signed kernel. A replaced kernel can hide anything from every scanner — including this one.",
                    technicalDetail = text.lineSequence().first { it.contains("Linux version") },
                    techniqueEducation = "/proc/version exposes who compiled the kernel and with which keys. Stock kernels carry vendor build hosts and release-keys; custom ones rarely bother to fake this.",
                    recommendedAction = SafeActions.reviewOnly("whether this device ever had a custom ROM/kernel installed; if not, treat as serious."),
                )
            }
        }

        // ---- which su ------------------------------------------------------------
        SU_FOUND.find(text)?.let { m ->
            findings += Finding(
                layer = DetectionLayer.ADB_DEEP_FORENSICS,
                severity = Severity.CRITICAL,
                confidence = 95,
                title = "su binary present at ${m.groupValues[1]}",
                explanation = "A root 'su' binary exists on this device. Root access lets software bypass every sandbox protection.",
                technicalDetail = m.value.trim(),
                techniqueEducation = "`which su` from the shell UID searches the real PATH — far more reliable than in-app file checks that root-hiders intercept.",
                recommendedAction = SafeActions.reviewOnly("whether you rooted this phone yourself. If not: backup (DeepWarden checklist), then reflash stock firmware."),
            )
        }

        // ---- dumpsys accessibility: bound services ---------------------------------
        if (text.contains("ACCESSIBILITY MANAGER", ignoreCase = true)) {
            Regex("""(?:Service\[label=|ComponentName\{)([^,}\]]+)""").findAll(text).forEach { m ->
                findings += Finding(
                    layer = DetectionLayer.ADB_DEEP_FORENSICS,
                    severity = Severity.MEDIUM,
                    confidence = 60,
                    title = "Bound accessibility service (authoritative): ${m.groupValues[1].trim()}",
                    explanation = "dumpsys confirms this accessibility service is ACTUALLY bound right now (not just enabled in settings). Verify you recognise it — bound services read your screen live.",
                    technicalDetail = m.value,
                    techniqueEducation = "Settings can claim a service is enabled while dumpsys shows the live binding state — the ground truth the system itself uses.",
                    recommendedAction = SafeActions.reviewOnly("this service in Settings → Accessibility; disable if unrecognised (fully reversible)."),
                )
            }
        }

        // ---- honesty: what this paste did NOT cover ---------------------------------
        if (!sawPackages) limitations += "Paste didn't include `pm list packages -f -u` — hidden-package path analysis skipped."
        if (!sawProps) limitations += "Paste didn't include `getprop` — verified-boot / debug-flag analysis skipped."
        limitations += "ADB inspection runs as the 'shell' user: deep /data contents and true kernel rootkits remain out of reach without root. We report what shell can prove, nothing more."

        return findings to limitations
    }
}

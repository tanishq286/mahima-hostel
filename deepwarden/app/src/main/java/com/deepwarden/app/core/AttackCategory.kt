package com.deepwarden.app.core

/**
 * Human attack categories. The detection layers produce technical [Finding]s;
 * this turns them into the language a worried user actually wants to hear —
 * "phishing", "malware", "spyware" — instead of a flat list of app names.
 *
 * [isAttack] marks the categories that mean "someone may be acting against
 * you", which drive the big red/green verdict on the results screen. The rest
 * are awareness items, not active attacks.
 */
enum class AttackCategory(
    val label: String,
    val blurb: String,
    val isAttack: Boolean,
) {
    MALWARE(
        "Malware",
        "Confirmed malicious app — flagged by professional antivirus engines.",
        true,
    ),
    PHISHING(
        "Phishing / scam messages",
        "Messages trying to trick you into giving away passwords, OTPs or money.",
        true,
    ),
    SPYWARE(
        "Spyware / stalkerware",
        "An app secretly watching your screen, location, calls or messages.",
        true,
    ),
    NETWORK_ATTACK(
        "Network interception",
        "Your internet traffic may be redirected or monitored (rogue proxy, DNS or VPN).",
        true,
    ),
    SYSTEM_TAMPERING(
        "System tampering",
        "Signs the phone was modified to weaken its built-in protections.",
        true,
    ),
    SURVEILLANCE_RISK(
        "Surveillance-capable app",
        "An app that HAS the power to spy — verify you installed and trust it.",
        false,
    ),
    DEVICE_EXPOSURE(
        "Device left exposed",
        "A setting makes it easy for someone with physical access to attack the phone.",
        false,
    ),
    SUSPICIOUS_APP(
        "Suspicious app",
        "Installed outside any app store, or behaving oddly — worth reviewing.",
        false,
    ),
    INFO(
        "For your awareness",
        "Informational — not an attack.",
        false,
    ),
}

/**
 * Pure classifier (no Android deps, unit-testable): maps a [Finding] to the
 * attack category a human cares about, using its layer and wording.
 */
object ThreatClassifier {

    fun categoryOf(finding: Finding): AttackCategory {
        val t = finding.title.lowercase()
        return when (finding.layer) {
            DetectionLayer.CLOUD_REPUTATION ->
                if (t.contains("suspicious")) AttackCategory.SUSPICIOUS_APP else AttackCategory.MALWARE

            DetectionLayer.CONTENT_ANALYSIS -> AttackCategory.PHISHING

            DetectionLayer.NETWORK_FORENSICS -> AttackCategory.NETWORK_ATTACK

            DetectionLayer.ADB_DEEP_FORENSICS ->
                when {
                    t.contains("apk") || t.contains("kernel") || t.contains("su ") ||
                        t.contains("root") || t.contains("boot") || t.contains("property") ->
                        AttackCategory.SYSTEM_TAMPERING
                    t.contains("accessibility") -> AttackCategory.SPYWARE
                    else -> AttackCategory.SUSPICIOUS_APP
                }

            DetectionLayer.SYSTEM_INTEGRITY ->
                when {
                    t.contains("accessibility") || t.contains("device admin") -> AttackCategory.SPYWARE
                    t.contains("rooted") || t.contains("root") -> AttackCategory.SYSTEM_TAMPERING
                    else -> AttackCategory.DEVICE_EXPOSURE
                }

            DetectionLayer.STATIC_FORENSICS ->
                when {
                    t.contains("impersonating") || t.contains("abusive certificate") ->
                        AttackCategory.MALWARE
                    t.contains("invisible") || t.contains("intercepts sms") || t.contains("hidden") ->
                        AttackCategory.SPYWARE
                    t.contains("sideloaded") -> AttackCategory.SUSPICIOUS_APP
                    else -> AttackCategory.SUSPICIOUS_APP
                }

            DetectionLayer.BEHAVIORAL_HEURISTICS ->
                when {
                    t.contains("stalkerware") || t.contains("battery") || t.contains("never open") ->
                        AttackCategory.SPYWARE
                    t.contains("permission profile") -> AttackCategory.SURVEILLANCE_RISK
                    else -> AttackCategory.SURVEILLANCE_RISK
                }
        }
    }

    /** Group + count findings by category, attack-categories first. */
    fun summarize(findings: List<Finding>): List<Pair<AttackCategory, List<Finding>>> =
        findings.groupBy { categoryOf(it) }
            .toList()
            .sortedWith(
                compareByDescending<Pair<AttackCategory, List<Finding>>> { it.first.isAttack }
                    .thenByDescending { group -> group.second.maxOf { it.priorityScore } }
            )

    /** True if any genuine attack (not just awareness items) was found. */
    fun hasActiveAttack(findings: List<Finding>): Boolean =
        findings.any { categoryOf(it).isAttack }
}

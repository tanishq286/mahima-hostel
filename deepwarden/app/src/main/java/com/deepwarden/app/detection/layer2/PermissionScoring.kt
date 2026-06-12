package com.deepwarden.app.detection.layer2

/**
 * ============================================================================
 *  LAYER 2 — WEIGHTED PERMISSION SCORING TABLE
 * ============================================================================
 *
 * Pure logic (no Android deps) so it is fully unit-testable.
 *
 * HOW THE SCORE WORKS
 * -------------------
 * 1. Each risky permission contributes a base weight (table below).
 * 2. Known SPYWARE COMBINATIONS apply multipliers, because the danger of
 *    surveillance permissions is multiplicative, not additive:
 *    an app that can read SMS *and* track location *and* draw over other
 *    apps *and* run an accessibility service is qualitatively different
 *    from four apps with one permission each.
 * 3. The raw score is normalised to 0–100 and mapped to severity bands.
 *
 * EXAMPLE (the canonical stalkerware profile):
 *    READ_SMS(18) + SEND_SMS(12) + ACCESS_FINE_LOCATION(10)
 *  + SYSTEM_ALERT_WINDOW(12) + REQUEST_IGNORE_BATTERY_OPTIMIZATIONS(8)
 *  + BIND_ACCESSIBILITY_SERVICE(25) = 85 base
 *  → triggers SMS_SPY(×1.4) and STALKERWARE_CORE(×1.5) combos
 *  → capped at 100 → EXTREME band.
 *
 * HONESTY NOTE: a high score is a *signal*, not proof. Legitimate apps
 * (SMS backup tools, parental-control the user installed knowingly) can score
 * high. That is why confidence for pure permission findings never exceeds 75
 * and the explanation always names every contributing permission.
 */
object PermissionScoring {

    /** Base risk weights. Keep sorted by weight for readability. */
    val WEIGHTS: Map<String, Int> = mapOf(
        // --- Tier 1: surveillance superpowers -------------------------------
        "android.permission.BIND_ACCESSIBILITY_SERVICE" to 25, // can read screen, inject input — #1 stalkerware tool
        "android.permission.BIND_DEVICE_ADMIN" to 20,          // resist uninstall, lock device
        "android.permission.READ_SMS" to 18,                   // read OTPs, private messages
        "android.permission.RECEIVE_SMS" to 15,                // intercept incoming SMS silently
        "android.permission.ACCESS_BACKGROUND_LOCATION" to 15, // 24/7 tracking
        "android.permission.READ_CALL_LOG" to 14,
        // --- Tier 2: strong spying capability -------------------------------
        "android.permission.RECORD_AUDIO" to 12,
        "android.permission.SEND_SMS" to 12,                   // exfil/premium fraud channel
        "android.permission.SYSTEM_ALERT_WINDOW" to 12,        // overlay phishing, click-jacking
        "android.permission.PROCESS_OUTGOING_CALLS" to 12,
        "android.permission.ANSWER_PHONE_CALLS" to 11,
        "android.permission.CAMERA" to 10,
        "android.permission.ACCESS_FINE_LOCATION" to 10,
        "android.permission.READ_PHONE_STATE" to 8,
        "android.permission.READ_CONTACTS" to 8,
        "android.permission.PACKAGE_USAGE_STATS" to 8,         // watch what the victim uses
        "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS" to 8, // stay alive 24/7
        "android.permission.READ_CALENDAR" to 6,
        "android.permission.RECEIVE_BOOT_COMPLETED" to 6,      // auto-restart after reboot
        "android.permission.QUERY_ALL_PACKAGES" to 6,
        "android.permission.GET_ACCOUNTS" to 5,
        "android.permission.READ_EXTERNAL_STORAGE" to 5,
        "android.permission.WRITE_SETTINGS" to 5,
        "android.permission.REQUEST_INSTALL_PACKAGES" to 5,    // dropper behaviour
        "android.permission.ACCESS_COARSE_LOCATION" to 4,
        "android.permission.READ_MEDIA_IMAGES" to 4,
        "android.permission.BLUETOOTH_CONNECT" to 3,
        "android.permission.NFC" to 2,
        "android.permission.INTERNET" to 2,                    // small alone; amplifier in combos
    )

    /**
     * Combination multipliers. [required] must ALL be present (and, where noted,
     * INTERNET acts as the exfiltration channel that arms the combo).
     */
    data class Combo(val name: String, val required: Set<String>, val multiplier: Double, val education: String)

    val COMBOS: List<Combo> = listOf(
        Combo(
            name = "STALKERWARE_CORE",
            required = setOf(
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
            ),
            multiplier = 1.5,
            education = "Accessibility + location + battery exemption is the classic stalkerware skeleton: read everything on screen, track the victim, never get killed by the OS.",
        ),
        Combo(
            name = "SMS_SPY",
            required = setOf(
                "android.permission.READ_SMS",
                "android.permission.SEND_SMS",
                "android.permission.INTERNET",
            ),
            multiplier = 1.4,
            education = "Read + send SMS with network access enables OTP theft and silent command-and-control over SMS.",
        ),
        Combo(
            name = "FULL_SURVEILLANCE",
            required = setOf(
                "android.permission.RECORD_AUDIO",
                "android.permission.CAMERA",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.INTERNET",
            ),
            multiplier = 1.45,
            education = "Microphone + camera + location + network is a complete remote-surveillance kit.",
        ),
        Combo(
            name = "OVERLAY_PHISHER",
            required = setOf(
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
            ),
            multiplier = 1.35,
            education = "Overlays + accessibility lets malware draw fake login screens over real apps AND auto-grant itself permissions (banking-trojan signature).",
        ),
        Combo(
            name = "CALL_INTERCEPTOR",
            required = setOf(
                "android.permission.READ_CALL_LOG",
                "android.permission.RECORD_AUDIO",
                "android.permission.READ_PHONE_STATE",
            ),
            multiplier = 1.3,
            education = "Call log + mic + phone state is the call-recording-spy pattern.",
        ),
        Combo(
            name = "PERSISTENT_DROPPER",
            required = setOf(
                "android.permission.REQUEST_INSTALL_PACKAGES",
                "android.permission.RECEIVE_BOOT_COMPLETED",
                "android.permission.INTERNET",
            ),
            multiplier = 1.25,
            education = "Boot persistence + ability to install other APKs + network = dropper/loader behaviour.",
        ),
    )

    /** Severity bands on the normalised 0–100 score. */
    const val BAND_EXTREME = 80
    const val BAND_HIGH = 60
    const val BAND_MEDIUM = 40
    const val BAND_LOW = 20

    data class PermissionScore(
        val raw: Int,
        val normalised: Int,
        val triggeredCombos: List<Combo>,
        val contributing: Map<String, Int>,
    )

    /**
     * Score a set of GRANTED (or requested, for not-yet-granted analysis)
     * permission strings.
     */
    fun score(permissions: Collection<String>): PermissionScore {
        val present = permissions.toSet()
        val contributing = WEIGHTS.filterKeys { it in present }
        val base = contributing.values.sum()

        val triggered = COMBOS.filter { combo -> combo.required.all { it in present } }
        // Multipliers compound, but we dampen stacking with sqrt-style decay
        // so 3 combos don't absurdly explode the score.
        var multiplied = base.toDouble()
        triggered.forEachIndexed { index, combo ->
            val damp = 1.0 / (1.0 + index * 0.5) // 1st full, 2nd 2/3, 3rd 1/2 …
            multiplied *= 1.0 + (combo.multiplier - 1.0) * damp
        }
        val normalised = multiplied.toInt().coerceIn(0, 100)
        return PermissionScore(base, normalised, triggered, contributing)
    }
}

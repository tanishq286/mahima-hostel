package com.deepwarden.app.detection.layer6

/**
 * Pure, unit-testable smishing/C2 rule engine for Layer 6.
 *
 * Each rule contributes points; >= [REPORT_THRESHOLD] is reported.
 * Rules are deliberately generic patterns of ATTACK SHAPE (urgency + link +
 * credential bait) — no real campaign content is embedded.
 */
object PhishingRules {

    const val REPORT_THRESHOLD = 45
    const val HIGH_THRESHOLD = 70

    data class Verdict(val score: Int, val matchedRules: List<String>)

    private data class Rule(val name: String, val points: Int, val regex: Regex)

    private val RULES = listOf(
        Rule(
            "URGENCY_LANGUAGE", 20,
            Regex("""\b(urgent|immediately|within 24 ?hours?|account (will be )?(blocked|suspended|closed)|final (warning|notice)|act now|verify now)\b""", RegexOption.IGNORE_CASE),
        ),
        Rule(
            "CREDENTIAL_BAIT", 25,
            Regex("""\b(verify your (identity|account)|confirm your (password|pin|otp)|enter your (card|cvv|password)|update (kyc|your details)|re-?activate your account)\b""", RegexOption.IGNORE_CASE),
        ),
        Rule(
            "SHORTENED_LINK", 15,
            Regex("""https?://(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|cutt\.ly|rb\.gy|tiny\.cc)/\S+""", RegexOption.IGNORE_CASE),
        ),
        Rule(
            "RAW_IP_LINK", 30,
            Regex("""https?://\d{1,3}(\.\d{1,3}){3}(:\d+)?(/\S*)?"""),
        ),
        Rule(
            "APK_DOWNLOAD_LINK", 35,
            Regex("""https?://\S+\.apk\b""", RegexOption.IGNORE_CASE),
        ),
        Rule(
            "PRIZE_BAIT", 15,
            Regex("""\b(congratulations? you (have )?won|claim your (prize|reward|cashback)|lottery|lucky (draw|winner))\b""", RegexOption.IGNORE_CASE),
        ),
        Rule(
            "BANK_IMPERSONATION", 20,
            Regex("""\b(your (bank|upi|wallet) (account|id))\b.*\bhttps?://""", RegexOption.IGNORE_CASE),
        ),
        Rule(
            "PUNYCODE_OR_LOOKALIKE", 25,
            Regex("""https?://xn--\S+|https?://\S*(paypa1|g00gle|amaz0n|faceb00k|netfl1x)\S*""", RegexOption.IGNORE_CASE),
        ),
        Rule(
            // SMS-C2 shape: terse command-like keywords sent as a bare message.
            "C2_COMMAND_SHAPE", 30,
            Regex("""^\s*(#|cmd:|exec:|run:)\s*\w+|^\s*(gps|loc|rec|wipe|sms|hide)\s+(on|off|start|stop|now)\s*$""", RegexOption.IGNORE_CASE),
        ),
    )

    fun evaluate(messageBody: String): Verdict {
        if (messageBody.isBlank()) return Verdict(0, emptyList())
        val matched = RULES.filter { it.regex.containsMatchIn(messageBody) }
        // Synergy bonus: urgency + any link-type rule is the classic smishing pair.
        val names = matched.map { it.name }
        var score = matched.sumOf { it.points }
        if ("URGENCY_LANGUAGE" in names && names.any { it.endsWith("_LINK") || it == "PUNYCODE_OR_LOOKALIKE" }) {
            score += 15
        }
        return Verdict(score.coerceAtMost(100), names)
    }
}

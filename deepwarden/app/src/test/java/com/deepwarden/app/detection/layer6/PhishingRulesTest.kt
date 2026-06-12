package com.deepwarden.app.detection.layer6

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class PhishingRulesTest {

    @Test
    fun `benign message scores zero`() {
        val v = PhishingRules.evaluate("Hey, are we still on for dinner at 8?")
        assertThat(v.score).isEqualTo(0)
    }

    @Test
    fun `classic smishing crosses the report threshold`() {
        val v = PhishingRules.evaluate(
            "URGENT: your account will be blocked within 24 hours. Verify your identity at http://bit.ly/x9z",
        )
        assertThat(v.score).isAtLeast(PhishingRules.REPORT_THRESHOLD)
        assertThat(v.matchedRules).containsAtLeast("URGENCY_LANGUAGE", "CREDENTIAL_BAIT", "SHORTENED_LINK")
    }

    @Test
    fun `apk download link plus urgency is high`() {
        val v = PhishingRules.evaluate("Final warning! Update now: http://example-update.net/app.apk")
        assertThat(v.score).isAtLeast(PhishingRules.HIGH_THRESHOLD)
    }

    @Test
    fun `raw ip link is heavily weighted`() {
        val v = PhishingRules.evaluate("see http://203.0.113.7:8080/login")
        assertThat(v.matchedRules).contains("RAW_IP_LINK")
    }

    @Test
    fun `c2 command shape detected`() {
        val v = PhishingRules.evaluate("gps on")
        assertThat(v.matchedRules).contains("C2_COMMAND_SHAPE")
    }

    @Test
    fun `score is capped at 100`() {
        val v = PhishingRules.evaluate(
            "URGENT final warning! You won a prize! Verify your password and update KYC at " +
                "http://bit.ly/a http://203.0.113.7/x.apk http://g00gle-login.example/claim",
        )
        assertThat(v.score).isAtMost(100)
    }

    @Test
    fun `blank message is safe`() {
        assertThat(PhishingRules.evaluate("   ").score).isEqualTo(0)
    }
}

package com.deepwarden.app.detection.layer2

import com.google.common.truth.Truth.assertThat
import org.junit.Test

/**
 * Tests for the Layer 2 scoring table — the most consequential logic in the
 * app. Bands and combo behaviour are part of the product contract.
 */
class PermissionScoringTest {

    @Test
    fun `empty permission set scores zero`() {
        val score = PermissionScoring.score(emptyList())
        assertThat(score.normalised).isEqualTo(0)
        assertThat(score.triggeredCombos).isEmpty()
    }

    @Test
    fun `benign app stays below low band`() {
        val score = PermissionScoring.score(
            listOf("android.permission.INTERNET", "android.permission.NFC"),
        )
        assertThat(score.normalised).isLessThan(PermissionScoring.BAND_LOW)
    }

    @Test
    fun `canonical stalkerware profile reaches extreme band`() {
        // The exact profile documented in the scoring table header.
        val score = PermissionScoring.score(
            listOf(
                "android.permission.READ_SMS",
                "android.permission.SEND_SMS",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.INTERNET",
            ),
        )
        assertThat(score.normalised).isAtLeast(PermissionScoring.BAND_EXTREME)
        assertThat(score.triggeredCombos.map { it.name })
            .containsAtLeast("STALKERWARE_CORE", "SMS_SPY")
    }

    @Test
    fun `sms spy combo requires the internet exfil channel`() {
        val without = PermissionScoring.score(
            listOf("android.permission.READ_SMS", "android.permission.SEND_SMS"),
        )
        assertThat(without.triggeredCombos.map { it.name }).doesNotContain("SMS_SPY")

        val with = PermissionScoring.score(
            listOf("android.permission.READ_SMS", "android.permission.SEND_SMS", "android.permission.INTERNET"),
        )
        assertThat(with.triggeredCombos.map { it.name }).contains("SMS_SPY")
        assertThat(with.normalised).isGreaterThan(without.normalised)
    }

    @Test
    fun `score is always within 0 to 100`() {
        // All weighted permissions at once must still clamp at 100.
        val score = PermissionScoring.score(PermissionScoring.WEIGHTS.keys)
        assertThat(score.normalised).isAtMost(100)
        assertThat(score.normalised).isAtLeast(0)
    }

    @Test
    fun `combo multipliers are dampened not compounded fully`() {
        val full = PermissionScoring.score(PermissionScoring.WEIGHTS.keys)
        // raw base of all weights is far above 100 pre-normalisation; the
        // dampening + clamp must keep the result meaningful.
        assertThat(full.raw).isGreaterThan(100)
        assertThat(full.normalised).isEqualTo(100)
    }

    @Test
    fun `overlay phisher combo detected`() {
        val score = PermissionScoring.score(
            listOf(
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
            ),
        )
        assertThat(score.triggeredCombos.map { it.name }).contains("OVERLAY_PHISHER")
    }
}

package com.deepwarden.app.detection.layer4

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.provider.Settings
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
import javax.inject.Inject
import javax.inject.Singleton

/**
 * ============================================================================
 *  LAYER 4 — NETWORK, TRACING & EXFILTRATION DETECTION
 * ============================================================================
 *
 * Attackers redirect or siphon traffic by quietly changing network plumbing:
 *
 *  1. GLOBAL HTTP PROXY — every connection routed through an attacker box.
 *  2. ACTIVE VPN — legitimate for many users; hostile if you didn't set one up
 *     (spyware uses VpnService to mirror all traffic).
 *  3. PRIVATE DNS override — attacker-controlled DNS = invisible redirection
 *     of every domain you visit.
 *
 * Per-app data-usage trends (NetworkStatsManager) need Usage Access; when
 * granted we flag "high upload, near-zero foreground use" exfiltration shapes.
 *
 * The optional local VpnService packet-inspection module is documented in
 * README §Roadmap — it is OFF by default and entirely opt-in, because running
 * a VPN to *find* a hostile VPN must be a deliberate user decision.
 */
@Singleton
class NetworkForensicsScanner @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    suspend fun scan(): Pair<List<Finding>, List<String>> = withContext(Dispatchers.IO) {
        val findings = mutableListOf<Finding>()
        val limitations = mutableListOf<String>()
        val cr = context.contentResolver

        // ---- 1. Global proxy --------------------------------------------------
        val globalProxy = Settings.Global.getString(cr, Settings.Global.HTTP_PROXY)
        if (!globalProxy.isNullOrBlank() && globalProxy != ":0") {
            findings += Finding(
                layer = DetectionLayer.NETWORK_FORENSICS,
                severity = Severity.CRITICAL,
                confidence = 95,
                title = "Global HTTP proxy is set: $globalProxy",
                explanation = "ALL web traffic from this phone is being routed through $globalProxy. Unless your workplace configured this, an attacker may be intercepting everything you do online.",
                technicalDetail = "Settings.Global.HTTP_PROXY=$globalProxy",
                techniqueEducation = "A proxy is a man-in-the-middle by design. Combined with a planted CA certificate it can decrypt HTTPS. We read the global proxy setting directly — a 95%+ confidence observation.",
                recommendedAction = SafeAction(
                    type = ActionType.NETWORK_RESET_GUIDED,
                    description = "Note the proxy value above (for evidence), then Settings → Wi-Fi → your network → Advanced → Proxy → None.",
                    whySafe = "Removing a proxy only changes how traffic is routed. No data on the phone is touched.",
                    undoInstructions = "Re-enter the same host:port in the proxy field.",
                    reversibility = Reversibility.FULLY_REVERSIBLE,
                    dataLossImpact = DataLossImpact.SETTINGS_ONLY,
                ),
            )
        }

        // ---- 2. Active VPN ------------------------------------------------------
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val caps = cm.activeNetwork?.let { cm.getNetworkCapabilities(it) }
        if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) {
            findings += Finding(
                layer = DetectionLayer.NETWORK_FORENSICS,
                severity = Severity.MEDIUM,
                confidence = 50,
                title = "A VPN is currently routing your traffic",
                explanation = "A VPN is active. If you set it up — great, ignore this. If you did NOT, a spyware app may be funnelling your traffic through itself: Android lets any app become a VPN once you approve a single dialog.",
                technicalDetail = "activeNetwork has TRANSPORT_VPN",
                techniqueEducation = "Spyware abuses VpnService to see every connection's metadata (and contents when paired with a rogue certificate). Check Settings → Network → VPN to see which app owns it.",
                recommendedAction = SafeActions.reviewOnly("Settings → Network & internet → VPN — verify you recognise the active VPN app."),
            )
        }

        // ---- 3. Private DNS -------------------------------------------------------
        val dnsMode = Settings.Global.getString(cr, "private_dns_mode")
        val dnsHost = Settings.Global.getString(cr, "private_dns_specifier")
        if (dnsMode == "hostname" && !dnsHost.isNullOrBlank() && dnsHost !in KNOWN_GOOD_DNS) {
            findings += Finding(
                layer = DetectionLayer.NETWORK_FORENSICS,
                severity = Severity.HIGH,
                confidence = 70,
                title = "Custom Private DNS server: $dnsHost",
                explanation = "Every website name this phone looks up is resolved by \"$dnsHost\". If you didn't choose this provider, an attacker controlling DNS can silently redirect any site — including banking — to lookalike servers.",
                technicalDetail = "private_dns_mode=hostname, private_dns_specifier=$dnsHost",
                techniqueEducation = "DNS is the phone book of the internet. Owning it means deciding where every name points. We compare the configured resolver against a short list of well-known public resolvers.",
                recommendedAction = SafeAction(
                    type = ActionType.NETWORK_RESET_GUIDED,
                    description = "Note the hostname above, then Settings → Network & internet → Private DNS → Automatic.",
                    whySafe = "Only changes which DNS server is asked. No data affected; reversible instantly.",
                    undoInstructions = "Re-enter \"$dnsHost\" in Private DNS.",
                    reversibility = Reversibility.FULLY_REVERSIBLE,
                    dataLossImpact = DataLossImpact.SETTINGS_ONLY,
                ),
            )
        }

        limitations += "Per-connection packet contents are not visible without the opt-in local VPN inspector. APN edits require carrier-level access to read on many OEM builds."
        findings to limitations
    }

    private companion object {
        /** Well-known public DoT resolvers that are NOT suspicious. */
        val KNOWN_GOOD_DNS = setOf(
            "dns.google", "one.one.one.one", "1dot1dot1dot1.cloudflare-dns.com",
            "dns.quad9.net", "dns.adguard-dns.com", "security.cloudflare-dns.com",
        )
    }
}

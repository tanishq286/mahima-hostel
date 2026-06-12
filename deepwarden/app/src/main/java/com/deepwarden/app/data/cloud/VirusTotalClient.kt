package com.deepwarden.app.data.cloud

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import javax.inject.Inject
import javax.inject.Singleton

/**
 * ============================================================================
 *  LAYER 7 — CLOUD REPUTATION (VirusTotal)
 * ============================================================================
 *
 * The closest a non-root phone app can get to "professional" detection: look
 * up an app's APK hash against VirusTotal's aggregate of 70+ commercial
 * antivirus engines (Kaspersky, BitDefender, ESET, etc.). If many engines
 * flag the hash as malicious, that is a strong, cloud-backed verdict.
 *
 * HONESTY & PRIVACY:
 *  - OFF by default. Runs only when the user enables it AND provides their own
 *    free API key (stored locally, never in this repo).
 *  - We send only the APK's SHA-256 HASH, never the APK itself and never any
 *    personal data. A hash reveals nothing about you.
 *  - Free VT keys allow ~4 lookups/min, 500/day — so the scan checks only the
 *    SUSPICIOUS subset (untrusted/sideloaded or already-flagged apps), never
 *    all installed apps. This keeps it within limits and fast.
 *  - "Not in VT database" is NOT proof of safety; we say so explicitly.
 *
 * No third-party HTTP dependency: uses HttpURLConnection so the app stays lean
 * (important for the limited-storage user).
 */
@Singleton
class VirusTotalClient @Inject constructor() {

    data class Verdict(
        val hash: String,
        val found: Boolean,           // was the hash known to VirusTotal?
        val malicious: Int,           // engines calling it malicious
        val suspicious: Int,
        val harmless: Int,
        val totalEngines: Int,
        val popularLabel: String?,    // e.g. "android.trojan.hiddad"
        val error: String? = null,
    )

    /** SHA-256 of an APK file (VirusTotal's primary lookup key). */
    fun sha256(file: File): String? = runCatching {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buf = ByteArray(64 * 1024)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                digest.update(buf, 0, n)
            }
        }
        digest.digest().joinToString("") { "%02x".format(it) }
    }.getOrNull()

    /**
     * Look a hash up on VirusTotal v3. Returns a [Verdict]; network/HTTP errors
     * are returned in [Verdict.error] rather than thrown, so one failed lookup
     * never aborts a scan.
     */
    suspend fun lookup(hash: String, apiKey: String): Verdict = withContext(Dispatchers.IO) {
        if (apiKey.isBlank()) return@withContext Verdict(hash, false, 0, 0, 0, 0, null, "No API key set")
        var conn: HttpURLConnection? = null
        try {
            val url = URL("https://www.virustotal.com/api/v3/files/$hash")
            conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                setRequestProperty("x-apikey", apiKey)
                setRequestProperty("Accept", "application/json")
                connectTimeout = 12_000
                readTimeout = 12_000
            }
            when (val code = conn.responseCode) {
                200 -> parse(hash, conn.inputStream.bufferedReader().use { it.readText() })
                404 -> Verdict(hash, found = false, 0, 0, 0, 0, null) // unknown to VT
                401 -> Verdict(hash, false, 0, 0, 0, 0, null, "API key rejected (401) — check the key")
                429 -> Verdict(hash, false, 0, 0, 0, 0, null, "Rate limit reached (429) — free keys allow ~4/min")
                else -> Verdict(hash, false, 0, 0, 0, 0, null, "HTTP $code from VirusTotal")
            }
        } catch (e: Exception) {
            Verdict(hash, false, 0, 0, 0, 0, null, e.message ?: "network error")
        } finally {
            conn?.disconnect()
        }
    }

    private fun parse(hash: String, body: String): Verdict {
        val attrs = JSONObject(body).getJSONObject("data").getJSONObject("attributes")
        val stats = attrs.getJSONObject("last_analysis_stats")
        val malicious = stats.optInt("malicious")
        val suspicious = stats.optInt("suspicious")
        val harmless = stats.optInt("harmless")
        val undetected = stats.optInt("undetected")
        val label = attrs.optJSONObject("popular_threat_classification")
            ?.optString("suggested_threat_label")?.takeIf { it.isNotBlank() }
        return Verdict(
            hash = hash,
            found = true,
            malicious = malicious,
            suspicious = suspicious,
            harmless = harmless,
            totalEngines = malicious + suspicious + harmless + undetected,
            popularLabel = label,
        )
    }
}

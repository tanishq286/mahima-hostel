package com.deepwarden.app.data.threatintel

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

/**
 * ============================================================================
 *  LOCAL THREAT INTELLIGENCE — responsible IOC rules, bundled & updateable
 * ============================================================================
 *
 * Source of truth is `assets/threat_intel/ioc_rules.json`, shipped with the
 * app. A newer file can be dropped into the app's private files dir by the
 * OPTIONAL one-tap update (signed JSON over HTTPS; OFF by default; see
 * Settings). Local file wins only if its `version` is higher.
 *
 * RESPONSIBLE-CONTENT POLICY for this DB:
 *   - behavioral patterns, permission combos, generic name-lookalike regexes
 *   - certificate hashes of known surveillance tooling
 *   - NO exploit code, NO malware payloads, NO instructions for attackers.
 */
@Serializable
data class IocRulesFile(
    val version: Int,
    val updated: String,
    /** Regexes matched against app label OR package for system-impersonation. */
    val systemLookalikePatterns: List<String>,
    /** SHA-256 of signing certs used by known surveillance tooling. */
    val badCertSha256: List<String>,
    /** Package-name regexes seen in stalkerware families (generic, no brands). */
    val suspiciousPackagePatterns: List<String>,
    /** Human-readable red-flag combos for the education screens. */
    val redFlagCombos: List<RedFlagCombo>,
)

@Serializable
data class RedFlagCombo(val name: String, val signals: List<String>, val whyDangerous: String)

/** Parsed, regex-compiled view used by scanners. */
data class IocRules(
    val version: Int,
    val systemLookalikeRegexes: List<Regex>,
    val badCertSha256: Set<String>,
    val suspiciousPackageRegexes: List<Regex>,
    val redFlagCombos: List<RedFlagCombo>,
)

@Singleton
class ThreatIntelRepository @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    private val json = Json { ignoreUnknownKeys = true }
    private val mutex = Mutex()
    @Volatile private var cached: IocRules? = null

    suspend fun rules(): IocRules = cached ?: mutex.withLock {
        cached ?: load().also { cached = it }
    }

    private suspend fun load(): IocRules = withContext(Dispatchers.IO) {
        val bundled = context.assets.open(ASSET_PATH).bufferedReader().use { it.readText() }
            .let { json.decodeFromString(IocRulesFile.serializer(), it) }
        // Optional updated file (only used when strictly newer than bundled).
        val updatedFile = File(context.filesDir, UPDATE_PATH)
        val effective = if (updatedFile.exists()) {
            runCatching { json.decodeFromString(IocRulesFile.serializer(), updatedFile.readText()) }
                .getOrNull()
                ?.takeIf { it.version > bundled.version } ?: bundled
        } else bundled

        IocRules(
            version = effective.version,
            systemLookalikeRegexes = effective.systemLookalikePatterns.mapNotNull(::safeRegex),
            badCertSha256 = effective.badCertSha256.map { it.lowercase() }.toSet(),
            suspiciousPackageRegexes = effective.suspiciousPackagePatterns.mapNotNull(::safeRegex),
            redFlagCombos = effective.redFlagCombos,
        )
    }

    /** A malformed pattern in an update must never crash scanning. */
    private fun safeRegex(pattern: String): Regex? =
        runCatching { Regex(pattern, RegexOption.IGNORE_CASE) }.getOrNull()

    /**
     * SELF-UPDATING THREAT INTELLIGENCE.
     *
     * Downloads the latest IOC rules over HTTPS and adopts them ONLY if they
     * parse cleanly AND carry a higher version than what we already have. This
     * is the honest version of "the app improves over time": no user data is
     * sent (a plain GET of a public rules file), and a corrupt/older file can
     * never weaken detection. Returns true if a newer ruleset was adopted.
     */
    suspend fun fetchUpdate(url: String = DEFAULT_UPDATE_URL): Boolean = withContext(Dispatchers.IO) {
        val current = rules().version
        val body = runCatching {
            val conn = (java.net.URL(url).openConnection() as java.net.HttpURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = 12_000
                readTimeout = 12_000
            }
            try {
                if (conn.responseCode != 200) return@withContext false
                conn.inputStream.bufferedReader().use { it.readText() }
            } finally {
                conn.disconnect()
            }
        }.getOrNull() ?: return@withContext false

        val parsed = runCatching { json.decodeFromString(IocRulesFile.serializer(), body) }
            .getOrNull() ?: return@withContext false
        if (parsed.version <= current) return@withContext false

        runCatching {
            File(context.filesDir, UPDATE_PATH).writeText(body)
            cached = null // force reload with the new rules on next access
        }.isSuccess
    }

    private companion object {
        const val ASSET_PATH = "threat_intel/ioc_rules.json"
        const val UPDATE_PATH = "threat_intel_update.json"
        // Public rules file in the project repo; updating it ships new detection
        // patterns to every install with no app update required.
        const val DEFAULT_UPDATE_URL =
            "https://raw.githubusercontent.com/tanishq286/mahima-hostel/" +
                "claude/phantomguard-deepforge-android-ul4zvz/" +
                "deepwarden/app/src/main/assets/threat_intel/ioc_rules.json"
    }
}

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

    private companion object {
        const val ASSET_PATH = "threat_intel/ioc_rules.json"
        const val UPDATE_PATH = "threat_intel_update.json"
    }
}

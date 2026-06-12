package com.deepwarden.app.selfprotect

import android.content.Context
import android.content.pm.PackageManager
import dagger.hilt.android.qualifiers.ApplicationContext
import java.security.MessageDigest
import javax.inject.Inject
import javax.inject.Singleton

/**
 * ============================================================================
 *  SELF-PROTECTION / ANTI-TAMPERING
 * ============================================================================
 *
 * A scanner that can be silently replaced is worse than no scanner: a
 * sophisticated attacker would swap it for a version that always says "clean".
 *
 * Checks (with the same honesty rules as everything else — these RAISE
 * suspicion, they cannot PROVE integrity):
 *   1. Our signing cert fingerprint vs the value compiled into this build.
 *   2. Debuggable flag on our own ApplicationInfo (release must be false).
 *   3. Instrumentation/hooking heuristics: known instrumentation frameworks
 *      loaded into our process (stack-walk class probe).
 *
 * On failure the UI shows a persistent warning banner — we never silently
 * keep scanning while compromised, and we never crash (that would just teach
 * attackers to patch the crash).
 */
@Singleton
class SelfIntegrityChecker @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    data class IntegrityStatus(val ok: Boolean, val problems: List<String>)

    fun check(): IntegrityStatus {
        val problems = mutableListOf<String>()

        // 1. Signature pin. EXPECTED_CERT_SHA256 is replaced with the real
        //    release-key hash in CI before the signed build (see README).
        ownCertSha256()?.let { actual ->
            if (EXPECTED_CERT_SHA256 != DEV_PLACEHOLDER && actual != EXPECTED_CERT_SHA256) {
                problems += "APK signature does not match the official DeepWarden release key. This copy may be tampered."
            }
        }

        // 2. Debuggable release build = repacked or run under a debugger.
        val debuggable = context.applicationInfo.flags and
            android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0
        if (debuggable && !BUILD_IS_DEBUG) {
            problems += "Release build is running as debuggable — possible repackaging."
        }

        // 3. Hooking-framework probe (heuristic, can be evaded — stated honestly).
        val hookClasses = listOf(
            "de.robv.android.xposed.XposedBridge",
            "org.lsposed.lspd.core.Main",
            "com.saurik.substrate.MS",
        )
        hookClasses.forEach {
            if (runCatching { Class.forName(it); true }.getOrDefault(false)) {
                problems += "Instrumentation framework detected in process: $it"
            }
        }

        return IntegrityStatus(problems.isEmpty(), problems)
    }

    private fun ownCertSha256(): String? = runCatching {
        val info = context.packageManager.getPackageInfo(
            context.packageName, PackageManager.GET_SIGNING_CERTIFICATES
        )
        val signer = info.signingInfo?.apkContentsSigners?.firstOrNull() ?: return null
        MessageDigest.getInstance("SHA-256").digest(signer.toByteArray())
            .joinToString("") { "%02x".format(it) }
    }.getOrNull()

    private companion object {
        const val DEV_PLACEHOLDER = "REPLACED_IN_CI_WITH_RELEASE_CERT_SHA256"
        const val EXPECTED_CERT_SHA256 = DEV_PLACEHOLDER
        val BUILD_IS_DEBUG = com.deepwarden.app.BuildConfig.DEBUG
    }
}

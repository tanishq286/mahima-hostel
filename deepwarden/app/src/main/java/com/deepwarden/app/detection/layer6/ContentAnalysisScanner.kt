package com.deepwarden.app.detection.layer6

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Telephony
import androidx.core.content.ContextCompat
import com.deepwarden.app.core.DetectionLayer
import com.deepwarden.app.core.Finding
import com.deepwarden.app.core.SafeActions
import com.deepwarden.app.core.Severity
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * ============================================================================
 *  LAYER 6 — CONTENT & ACTIVITY ANALYSIS (PERMISSION-GATED, 100% LOCAL)
 * ============================================================================
 *
 * OPTIONAL layer. Only runs when the user explicitly grants READ_SMS in-app
 * with a full explanation. Analysis is pure on-device regex/rules — message
 * text NEVER leaves the phone and is NEVER stored; only the verdict
 * (sender-hash + matched rule names) is persisted for the report.
 *
 * Detects smishing / C2-over-SMS shapes via [PhishingRules]:
 *   urgency language, credential-bait, shortened/raw-IP links, APK links,
 *   premium-rate reply bait, and known C2 keyword shapes.
 */
@Singleton
class ContentAnalysisScanner @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    suspend fun scan(maxMessages: Int = 200): Pair<List<Finding>, List<String>> =
        withContext(Dispatchers.IO) {
            val limitations = mutableListOf<String>()
            if (ContextCompat.checkSelfPermission(context, Manifest.permission.READ_SMS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                limitations += "SMS permission not granted → phishing/C2 message scan skipped. Optional; grant in-app if wanted. Content never leaves the device."
                return@withContext emptyList<Finding>() to limitations
            }

            val findings = mutableListOf<Finding>()
            val uri: Uri = Telephony.Sms.Inbox.CONTENT_URI
            context.contentResolver.query(
                uri,
                arrayOf(Telephony.Sms.ADDRESS, Telephony.Sms.BODY, Telephony.Sms.DATE),
                null, null,
                "${Telephony.Sms.DATE} DESC LIMIT $maxMessages",
            )?.use { cursor ->
                val addrIdx = cursor.getColumnIndex(Telephony.Sms.ADDRESS)
                val bodyIdx = cursor.getColumnIndex(Telephony.Sms.BODY)
                while (cursor.moveToNext()) {
                    val body = cursor.getString(bodyIdx).orEmpty()
                    val sender = cursor.getString(addrIdx).orEmpty()
                    val verdict = PhishingRules.evaluate(body)
                    if (verdict.score >= PhishingRules.REPORT_THRESHOLD) {
                        findings += Finding(
                            layer = DetectionLayer.CONTENT_ANALYSIS,
                            severity = if (verdict.score >= PhishingRules.HIGH_THRESHOLD) Severity.HIGH else Severity.MEDIUM,
                            confidence = verdict.score.coerceAtMost(85),
                            title = "Suspicious message from ${sender.take(14)}…",
                            // Privacy: only matched RULE NAMES are surfaced/stored — never the message text.
                            explanation = "A recent SMS matches phishing patterns: ${verdict.matchedRules.joinToString()}. Do not tap its links or reply.",
                            technicalDetail = "matched=${verdict.matchedRules.joinToString()} score=${verdict.score} (message text not stored, by design)",
                            techniqueEducation = "Smishing combines urgency (\"account blocked!\"), a disguised link and a request for credentials or an app install. Local rules score each signal — nothing is uploaded.",
                            recommendedAction = SafeActions.reviewOnly("the flagged message in your SMS app — delete it; block the sender. Never enter credentials from an SMS link."),
                        )
                    }
                }
            }
            findings to limitations
        }
}

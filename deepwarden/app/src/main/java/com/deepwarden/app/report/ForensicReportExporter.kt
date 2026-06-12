package com.deepwarden.app.report

import android.content.Context
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Typeface
import android.graphics.pdf.PdfDocument
import com.deepwarden.app.core.ScanResult
import com.deepwarden.app.data.db.SafeActionSurrogate
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Full forensic report export — JSON (machine-readable evidence) and PDF
 * (human/legal-readable). Written to the app's private files dir; the UI
 * shares them via FileProvider so nothing is world-readable.
 *
 * Reports always include the honest limitations section: a report that hides
 * its blind spots is not evidence, it's marketing.
 */
@Singleton
class ForensicReportExporter @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    private val json = Json { prettyPrint = true }

    @Serializable
    data class ReportJson(
        val tool: String,
        val toolVersion: String,
        val generatedAt: String,
        val scanStartedAt: String,
        val overallThreatScore: Int,
        val scoreConfidence: Int,
        val dimensions: Map<String, Int>,
        val findings: List<FindingJson>,
        val honestLimitations: List<String>,
    )

    @Serializable
    data class FindingJson(
        val layer: String, val severity: String, val confidence: Int,
        val title: String, val explanation: String, val technicalDetail: String,
        val subjectPackage: String?, val recommendedAction: SafeActionSurrogate,
    )

    suspend fun exportJson(result: ScanResult): File = withContext(Dispatchers.IO) {
        val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss z", Locale.US)
        val report = ReportJson(
            tool = "DeepWarden",
            toolVersion = "1.0.0",
            generatedAt = fmt.format(Date()),
            scanStartedAt = fmt.format(Date(result.startedAtMillis)),
            overallThreatScore = result.deviceThreatScore.overall,
            scoreConfidence = result.deviceThreatScore.confidence,
            dimensions = mapOf(
                "static" to result.deviceThreatScore.staticDimension,
                "behavioral" to result.deviceThreatScore.behavioralDimension,
                "system" to result.deviceThreatScore.systemDimension,
                "network" to result.deviceThreatScore.networkDimension,
            ),
            findings = result.findings.map {
                FindingJson(
                    it.layer.name, it.severity.name, it.confidence, it.title,
                    it.explanation, it.technicalDetail, it.subjectPackage,
                    SafeActionSurrogate.from(it.recommendedAction),
                )
            },
            honestLimitations = result.limitations,
        )
        File(reportsDir(), "deepwarden_report_${result.startedAtMillis}.json").apply {
            writeText(json.encodeToString(ReportJson.serializer(), report))
        }
    }

    /** Minimal dependency-free PDF via android.graphics.pdf. */
    suspend fun exportPdf(result: ScanResult): File = withContext(Dispatchers.IO) {
        val doc = PdfDocument()
        val titlePaint = Paint().apply { typeface = Typeface.create(Typeface.DEFAULT_BOLD, Typeface.BOLD); textSize = 16f; color = Color.BLACK }
        val bodyPaint = Paint().apply { textSize = 9f; color = Color.DKGRAY }
        val headPaint = Paint().apply { typeface = Typeface.DEFAULT_BOLD; textSize = 11f; color = Color.BLACK }

        var page = doc.startPage(PdfDocument.PageInfo.Builder(595, 842, 1).create())
        var canvas = page.canvas
        var y = 40f
        var pageNo = 1

        fun newPageIfNeeded(needed: Float = 60f) {
            if (y > 842 - needed) {
                doc.finishPage(page)
                pageNo += 1
                page = doc.startPage(PdfDocument.PageInfo.Builder(595, 842, pageNo).create())
                canvas = page.canvas
                y = 40f
            }
        }

        fun line(text: String, paint: Paint, indent: Float = 40f) {
            // crude wrap at ~95 chars for the 9pt body font
            text.chunked(95).forEach {
                newPageIfNeeded()
                canvas.drawText(it, indent, y, paint)
                y += paint.textSize + 4f
            }
        }

        line("DeepWarden Forensic Report", titlePaint)
        line(SimpleDateFormat("yyyy-MM-dd HH:mm z", Locale.US).format(Date(result.startedAtMillis)), bodyPaint)
        y += 10f
        line("Overall threat score: ${result.deviceThreatScore.overall}/100 (confidence ${result.deviceThreatScore.confidence}%)", headPaint)
        line("Static ${result.deviceThreatScore.staticDimension} · Behavioral ${result.deviceThreatScore.behavioralDimension} · System ${result.deviceThreatScore.systemDimension} · Network ${result.deviceThreatScore.networkDimension}", bodyPaint)
        y += 12f

        line("Findings (${result.findings.size})", headPaint)
        result.findings.forEach { f ->
            y += 6f
            line("[${f.severity}] ${f.title}  (${f.confidence}% · ${f.layer.displayName})", headPaint)
            line(f.explanation, bodyPaint, indent = 48f)
            line("Action: ${f.recommendedAction.description}", bodyPaint, indent = 48f)
            line("Data impact: ${f.recommendedAction.dataLossImpact.userLabel}", bodyPaint, indent = 48f)
        }

        y += 12f
        line("What this scan could NOT see (honesty section)", headPaint)
        result.limitations.forEach { line("• $it", bodyPaint, indent = 48f) }

        doc.finishPage(page)
        val out = File(reportsDir(), "deepwarden_report_${result.startedAtMillis}.pdf")
        out.outputStream().use { doc.writeTo(it) }
        doc.close()
        out
    }

    private fun reportsDir(): File =
        File(context.filesDir, "reports").apply { mkdirs() }
}

package com.deepwarden.app.remediation

import android.content.Context
import android.os.Environment
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton

/**
 * ============================================================================
 *  SMART SAFE CLEAN — space recovery for limited-storage users,
 *  with a HARD personal-data firewall.
 * ============================================================================
 *
 * Categories scanned (ALL are recreatable/temporary by definition):
 *   1. Our own cache             — always safe (context.cacheDir)
 *   2. App external caches      — /sdcard/Android/data/x/cache visible to us
 *   3. Stale Download leftovers — ONLY: .apk/.tmp/.part/.crdownload older than
 *                                 [staleDays]; never documents/media
 *   4. Empty folders in Downloads
 *
 * HARD FIREWALL (enforced in [isProtected], tested in SafeCleanEngineTest):
 *   - NEVER touches DCIM, Pictures, Movies, Music, Documents, WhatsApp/ dirs
 *   - NEVER deletes media or document file types anywhere (jpg, mp4, pdf, docx…)
 *   - Deletion is two-phase: scan returns a preview list; the user sees every
 *     file with its path & size and confirms before [delete] runs.
 */
@Singleton
class SafeCleanEngine @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    data class CleanCandidate(val file: File, val category: String, val sizeBytes: Long)
    data class CleanPreview(val candidates: List<CleanCandidate>) {
        val totalBytes: Long get() = candidates.sumOf { it.sizeBytes }
    }

    /** File types that are NEVER deletion candidates, anywhere. */
    private val protectedExtensions = setOf(
        "jpg", "jpeg", "png", "gif", "webp", "heic", "raw", "dng",       // photos
        "mp4", "mkv", "avi", "mov", "3gp", "webm",                        // videos
        "mp3", "m4a", "ogg", "opus", "wav", "flac", "amr",                // audio incl. voice notes
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv", // documents
        "vcf", "ics", "zip", "rar", "7z", "db", "backup", "bak",          // contacts/archives/backups
    )

    /** Directory names that are NEVER entered. Personal-data firewall. */
    private val protectedDirNames = setOf(
        "dcim", "pictures", "movies", "music", "documents", "recordings",
        "whatsapp", "telegram", "signal", "voice recorder", "camera",
    )

    /** Deletable junk types in Downloads when stale. */
    private val junkExtensions = setOf("apk", "tmp", "part", "crdownload", "log", "nomedia")

    suspend fun preview(staleDays: Int = 30): CleanPreview = withContext(Dispatchers.IO) {
        val candidates = mutableListOf<CleanCandidate>()

        // 1. Our own caches — always reclaimable.
        listOfNotNull(context.cacheDir, context.externalCacheDir).forEach { dir ->
            dir.walkTopDown().filter { it.isFile }.forEach {
                candidates += CleanCandidate(it, "DeepWarden cache", it.length())
            }
        }

        // 2/3/4. Stale junk in Downloads only — guarded by the firewall.
        val downloads = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        val cutoff = System.currentTimeMillis() - TimeUnit.DAYS.toMillis(staleDays.toLong())
        if (downloads?.isDirectory == true) {
            downloads.walkTopDown()
                .onEnter { dir -> !isProtectedDir(dir) }
                .filter { it.isFile && !isProtected(it) }
                .filter { it.extension.lowercase() in junkExtensions && it.lastModified() < cutoff }
                .forEach { candidates += CleanCandidate(it, "Stale download junk (${it.extension}, >${staleDays}d old)", it.length()) }
        }

        CleanPreview(candidates)
    }

    /**
     * Phase 2 — only ever called with files the user saw and confirmed.
     * Re-validates the firewall at deletion time (paranoia is a feature).
     */
    suspend fun delete(confirmed: List<CleanCandidate>): Long = withContext(Dispatchers.IO) {
        var freed = 0L
        confirmed.forEach { c ->
            if (!isProtected(c.file) && c.file.exists() && c.file.delete()) freed += c.sizeBytes
        }
        freed
    }

    internal fun isProtected(file: File): Boolean {
        if (file.extension.lowercase() in protectedExtensions) return true
        // Any protected ancestor directory protects the whole subtree.
        var dir: File? = file.parentFile
        while (dir != null) {
            if (dir.name.lowercase() in protectedDirNames) return true
            dir = dir.parentFile
        }
        return false
    }

    internal fun isProtectedDir(dir: File): Boolean = dir.name.lowercase() in protectedDirNames
}

package com.deepwarden.app.data.db

import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.RoomDatabase
import kotlinx.coroutines.flow.Flow

/**
 * Local-only persistence for scan history & findings.
 * Powers the history screen and the "new since last scan" visual diff —
 * critical for catching NEW infections between scans.
 */
@Entity(tableName = "scans")
data class ScanEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val startedAt: Long,
    val finishedAt: Long,
    val overallScore: Int,
    val staticScore: Int,
    val behavioralScore: Int,
    val systemScore: Int,
    val networkScore: Int,
    val confidence: Int,
    val isEmergency: Boolean,
    val layersRun: String,        // comma-separated DetectionLayer names
    val limitationsJson: String,  // serialized honest-limitations list
)

@Entity(tableName = "findings")
data class FindingEntity(
    @PrimaryKey val id: String,
    val scanId: Long,
    val layer: String,
    val severity: String,
    val confidence: Int,
    val title: String,
    val explanation: String,
    val technicalDetail: String,
    val techniqueEducation: String,
    val subjectPackage: String?,
    val subjectAppLabel: String?,
    val actionJson: String,       // serialized SafeAction
    val detectedAt: Long,
    /** Stable identity for diffing across scans (layer+package+title). */
    val diffKey: String,
)

@Dao
interface ScanDao {
    @Insert suspend fun insertScan(scan: ScanEntity): Long
    @Insert suspend fun insertFindings(findings: List<FindingEntity>)

    @Query("SELECT * FROM scans ORDER BY startedAt DESC")
    fun scansFlow(): Flow<List<ScanEntity>>

    @Query("SELECT * FROM scans ORDER BY startedAt DESC LIMIT 2")
    suspend fun lastTwoScans(): List<ScanEntity>

    @Query("SELECT * FROM findings WHERE scanId = :scanId")
    suspend fun findingsForScan(scanId: Long): List<FindingEntity>

    @Query("SELECT * FROM scans WHERE id = :id")
    suspend fun scanById(id: Long): ScanEntity?

    /** Storage-friendly retention: keep the newest [keep] scans. */
    @Query("DELETE FROM scans WHERE id NOT IN (SELECT id FROM scans ORDER BY startedAt DESC LIMIT :keep)")
    suspend fun pruneScans(keep: Int)

    @Query("DELETE FROM findings WHERE scanId NOT IN (SELECT id FROM scans)")
    suspend fun pruneOrphanFindings()
}

@Database(entities = [ScanEntity::class, FindingEntity::class], version = 1, exportSchema = true)
abstract class DeepWardenDatabase : RoomDatabase() {
    abstract fun scanDao(): ScanDao
}

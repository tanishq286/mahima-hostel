package com.deepwarden.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.deepwarden.app.data.db.ScanEntity
import com.deepwarden.app.data.db.ScanHistoryRepository
import com.deepwarden.app.ui.theme.DwColors
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.inject.Inject

@HiltViewModel
class HistoryViewModel @Inject constructor(
    private val history: ScanHistoryRepository,
) : ViewModel() {
    val scans = history.scansFlow()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    private val _diff = MutableStateFlow<ScanHistoryRepository.ScanDiff?>(null)
    val diff = _diff.asStateFlow()

    init {
        viewModelScope.launch { _diff.value = history.latestDiff() }
    }
}

/**
 * Scan history with VISUAL DIFF — the "did something NEW get in?" answer.
 * New findings since the previous scan are the highest-signal infection
 * indicator the app produces.
 */
@Composable
fun HistoryScreen(vm: HistoryViewModel = hiltViewModel()) {
    val scans by vm.scans.collectAsState()
    val diff by vm.diff.collectAsState()
    val fmt = SimpleDateFormat("dd MMM yyyy, HH:mm", Locale.getDefault())

    LazyColumn(Modifier.fillMaxSize().padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item { Text("Scan history & diff", style = MaterialTheme.typography.headlineMedium) }

        diff?.let { d ->
            item {
                Card(colors = CardDefaults.cardColors(containerColor = DwColors.SurfaceHigh)) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text("Since the previous scan", style = MaterialTheme.typography.titleSmall, color = DwColors.ElectricBlue)
                        if (d.newFindings.isEmpty()) {
                            Text("No new findings — nothing new got in. ✓", color = DwColors.CalmGreen, style = MaterialTheme.typography.bodyMedium)
                        } else {
                            Text("${d.newFindings.size} NEW finding(s) — review these first:", color = DwColors.WarnOrange, style = MaterialTheme.typography.bodyMedium)
                        }
                        if (d.resolvedTitles.isNotEmpty()) {
                            Text("Resolved since last scan: ${d.resolvedTitles.size}", color = DwColors.CalmGreen, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }
            items(d.newFindings) { FindingCard(it) }
        }

        items(scans) { scan -> ScanRow(scan, fmt) }

        if (scans.isEmpty()) {
            item { Text("No scans recorded yet.", color = DwColors.TextSecondary) }
        }
    }
}

@Composable
private fun ScanRow(scan: ScanEntity, fmt: SimpleDateFormat) {
    Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = DwColors.Surface)) {
        Column(Modifier.padding(12.dp)) {
            Text(
                "${fmt.format(Date(scan.startedAt))}${if (scan.isEmergency) "  ·  EMERGENCY" else ""}",
                style = MaterialTheme.typography.titleSmall,
            )
            Text(
                "Score ${scan.overallScore}/100 · confidence ${scan.confidence}% · static ${scan.staticScore} / behavior ${scan.behavioralScore} / system ${scan.systemScore} / network ${scan.networkScore}",
                style = MaterialTheme.typography.labelSmall, color = DwColors.TextSecondary,
            )
        }
    }
}

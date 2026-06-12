package com.deepwarden.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.deepwarden.app.remediation.SafeCleanEngine
import com.deepwarden.app.ui.theme.DwColors
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class CleanViewModel @Inject constructor(
    private val engine: SafeCleanEngine,
) : ViewModel() {
    data class State(
        val preview: SafeCleanEngine.CleanPreview? = null,
        val freedBytes: Long? = null,
        val scanning: Boolean = false,
    )

    private val _state = MutableStateFlow(State())
    val state = _state.asStateFlow()

    fun scan() {
        _state.value = State(scanning = true)
        viewModelScope.launch {
            _state.value = State(preview = engine.preview())
        }
    }

    /** Two-phase: only deletes what the preview displayed and the user confirmed. */
    fun confirmDelete() {
        val preview = _state.value.preview ?: return
        viewModelScope.launch {
            val freed = engine.delete(preview.candidates)
            _state.value = State(freedBytes = freed)
        }
    }
}

/**
 * Smart Safe Clean — space recovery with a hard personal-data firewall.
 * Photos, WhatsApp media, documents are structurally untouchable (see
 * SafeCleanEngine.isProtected + its unit tests).
 */
@Composable
fun SafeCleanScreen(vm: CleanViewModel = hiltViewModel()) {
    val state by vm.state.collectAsState()

    LazyColumn(Modifier.fillMaxSize().padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            Text("Smart Safe Clean", style = MaterialTheme.typography.headlineMedium)
            Text(
                "Frees space from caches and stale junk ONLY. Photos, videos, voice notes, WhatsApp media and documents are protected by a hard firewall in the code — they are never even listed.",
                style = MaterialTheme.typography.bodyMedium, color = DwColors.TextSecondary,
            )
        }
        item {
            Button(onClick = { vm.scan() }, modifier = Modifier.fillMaxWidth(), enabled = !state.scanning) {
                Text(if (state.scanning) "Scanning…" else "Find safe-to-free space")
            }
        }

        state.preview?.let { preview ->
            item {
                Text(
                    "Reclaimable: ${"%.1f".format(preview.totalBytes / 1024.0 / 1024.0)} MB in ${preview.candidates.size} file(s) — review every file below before confirming.",
                    style = MaterialTheme.typography.titleMedium, color = DwColors.CalmGreen,
                )
            }
            items(preview.candidates.take(200)) { c ->
                Card(colors = CardDefaults.cardColors(containerColor = DwColors.Surface)) {
                    Column(Modifier.padding(10.dp)) {
                        Text(c.file.absolutePath, style = MaterialTheme.typography.bodySmall)
                        Text("${c.category} · ${"%.1f".format(c.sizeBytes / 1024.0)} KB", style = MaterialTheme.typography.labelSmall, color = DwColors.TextSecondary)
                    }
                }
            }
            item {
                if (preview.candidates.isEmpty()) {
                    Text("Nothing junk-like found. Your storage is already tidy.", color = DwColors.CalmGreen)
                } else {
                    Button(onClick = { vm.confirmDelete() }, modifier = Modifier.fillMaxWidth()) {
                        Text("Delete the ${preview.candidates.size} files listed above")
                    }
                    OutlinedButton(onClick = { vm.scan() }, modifier = Modifier.fillMaxWidth()) {
                        Text("Re-scan instead")
                    }
                }
            }
        }

        state.freedBytes?.let { freed ->
            item {
                Text(
                    "Freed ${"%.1f".format(freed / 1024.0 / 1024.0)} MB. No personal files were touched.",
                    style = MaterialTheme.typography.titleMedium, color = DwColors.CalmGreen,
                )
            }
        }
    }
}

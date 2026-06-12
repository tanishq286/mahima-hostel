package com.deepwarden.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import com.deepwarden.app.core.Finding
import com.deepwarden.app.detection.layer5.AdbDeepForensicsParser
import com.deepwarden.app.ui.theme.DwColors
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject

@HiltViewModel
class AdbViewModel @Inject constructor(
    private val parser: AdbDeepForensicsParser,
) : ViewModel() {
    data class State(val findings: List<Finding> = emptyList(), val limitations: List<String> = emptyList(), val analysed: Boolean = false)

    private val _state = MutableStateFlow(State())
    val state = _state.asStateFlow()

    fun analyse(paste: String) {
        val (findings, limitations) = parser.parse(paste)
        _state.value = State(findings, limitations, analysed = true)
    }
}

/**
 * Layer 5 — guided ADB deep forensic mode.
 * The user runs READ-ONLY commands on a computer and pastes the output here.
 */
@Composable
fun AdbDeepScanScreen(vm: AdbViewModel = hiltViewModel()) {
    val state by vm.state.collectAsState()
    var paste by remember { mutableStateOf("") }

    LazyColumn(
        Modifier.fillMaxSize().padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Text("ADB deep forensics", style = MaterialTheme.typography.headlineMedium)
            Text(
                "This expert mode reads system internals no installed app can see — without root. " +
                    "You run safe, read-only commands from a computer; DeepWarden analyses the output entirely on this phone.",
                style = MaterialTheme.typography.bodyMedium, color = DwColors.TextSecondary,
            )
        }

        item {
            Card(colors = CardDefaults.cardColors(containerColor = DwColors.SurfaceHigh)) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("Before you start", style = MaterialTheme.typography.titleSmall, color = DwColors.WarnOrange)
                    Text(
                        "1. On the phone: Settings → About → tap Build number 7× → Developer options → enable USB debugging.\n" +
                            "2. Connect to a computer YOU trust with adb installed, accept the fingerprint prompt.\n" +
                            "3. Run the commands below, paste ALL output into the box.\n" +
                            "4. IMPORTANT: turn USB debugging OFF when done — DeepWarden will remind you if you forget.",
                        style = MaterialTheme.typography.bodySmall, color = DwColors.TextSecondary,
                    )
                    Text("Every command is read-only. None of them can modify your phone or data.", style = MaterialTheme.typography.labelMedium, color = DwColors.CalmGreen)
                }
            }
        }

        items(AdbDeepForensicsParser.SAFE_COMMANDS) { cmd ->
            Card(colors = CardDefaults.cardColors(containerColor = DwColors.Surface)) {
                Column(Modifier.padding(12.dp)) {
                    Text(cmd.command, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall, color = DwColors.ElectricBlue)
                    Text(cmd.purpose, style = MaterialTheme.typography.labelSmall, color = DwColors.TextSecondary)
                }
            }
        }

        item {
            OutlinedTextField(
                value = paste,
                onValueChange = { paste = it },
                modifier = Modifier.fillMaxWidth().heightIn(min = 160.dp),
                label = { Text("Paste command output here (one or many commands)") },
                textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
            )
            Button(onClick = { vm.analyse(paste) }, modifier = Modifier.fillMaxWidth()) {
                Text("Analyse on-device")
            }
        }

        if (state.analysed) {
            item {
                Text(
                    if (state.findings.isEmpty()) "No deep-system red flags in the pasted output."
                    else "${state.findings.size} deep finding(s):",
                    style = MaterialTheme.typography.titleMedium,
                    color = if (state.findings.isEmpty()) DwColors.CalmGreen else DwColors.WarnOrange,
                )
            }
            items(state.findings) { FindingCard(it) }
            item {
                Card(colors = CardDefaults.cardColors(containerColor = DwColors.Surface)) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text("Not covered by this paste", style = MaterialTheme.typography.titleSmall, color = DwColors.WarnOrange)
                        state.limitations.forEach { Text("• $it", style = MaterialTheme.typography.bodySmall, color = DwColors.TextSecondary) }
                    }
                }
            }
        }
    }
}

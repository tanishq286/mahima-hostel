package com.deepwarden.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.deepwarden.app.core.PermanentLimitations
import com.deepwarden.app.ui.theme.DwColors

/**
 * Honest onboarding: capabilities AND limitations, before any scan runs.
 * Trust is built by saying what we cannot do.
 */
@Composable
fun OnboardingScreen(onDone: () -> Unit) {
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("DeepWarden", style = MaterialTheme.typography.headlineLarge, color = DwColors.ElectricBlue)
        Text("Sees deeper. Deletes nothing.", style = MaterialTheme.typography.titleMedium, color = DwColors.TextSecondary)

        InfoCard(
            "Zero data loss, guaranteed",
            "DeepWarden is read-only. It never uninstalls, never clears data, never resets anything by itself. " +
                "Every suggestion explains exactly what it touches, how to undo it, and starts in Safe Mode where only fully reversible steps are shown.",
        )
        InfoCard(
            "Six layers, genuinely deep",
            "Package forensics, behavioral heuristics, system integrity, network forensics, " +
                "an expert ADB deep mode that reads what normal apps can't, and optional on-device message analysis.",
        )
        InfoCard(
            "100% local & private",
            "All analysis happens on this phone. No accounts, no uploads. Optional features that use the network are OFF by default and clearly labelled.",
        )
        Card(colors = CardDefaults.cardColors(containerColor = DwColors.SurfaceHigh)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("What we honestly cannot see (without root):", style = MaterialTheme.typography.titleSmall, color = DwColors.WarnOrange)
                PermanentLimitations.WITHOUT_ROOT.forEach {
                    Text("• $it", style = MaterialTheme.typography.bodySmall, color = DwColors.TextSecondary)
                }
                Text(
                    "Any product claiming 100% detection without root is overclaiming. We'd rather be honest than impressive.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }

        Spacer(Modifier.height(8.dp))
        Button(onClick = onDone, modifier = Modifier.fillMaxWidth()) {
            Text("I understand — start protecting")
        }
    }
}

@Composable
private fun InfoCard(title: String, body: String) {
    Card(colors = CardDefaults.cardColors(containerColor = DwColors.Surface)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(title, style = MaterialTheme.typography.titleSmall, color = DwColors.CalmGreen)
            Text(body, style = MaterialTheme.typography.bodyMedium, color = DwColors.TextSecondary)
        }
    }
}

package com.deepwarden.app.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

/**
 * DeepWarden visual identity — "dark professional security":
 * deep black canvas, electric blue trust accents, red/orange strictly
 * reserved for danger, calm green for safety. The palette is deliberately
 * restrained: a security app must feel like an instrument, not a casino.
 */
object DwColors {
    val DeepBlack = Color(0xFF070A0F)
    val Surface = Color(0xFF0E141D)
    val SurfaceHigh = Color(0xFF16202D)
    val ElectricBlue = Color(0xFF2F8BFF)
    val ElectricBlueDim = Color(0xFF1B4F8F)
    val DangerRed = Color(0xFFFF4D5E)
    val WarnOrange = Color(0xFFFF9A3D)
    val CalmGreen = Color(0xFF35D49A)
    val TextPrimary = Color(0xFFE8EEF6)
    val TextSecondary = Color(0xFF93A3B8)
}

private val DarkScheme = darkColorScheme(
    primary = DwColors.ElectricBlue,
    onPrimary = Color.White,
    primaryContainer = DwColors.ElectricBlueDim,
    onPrimaryContainer = DwColors.TextPrimary,
    secondary = DwColors.CalmGreen,
    onSecondary = DwColors.DeepBlack,
    error = DwColors.DangerRed,
    onError = Color.White,
    background = DwColors.DeepBlack,
    onBackground = DwColors.TextPrimary,
    surface = DwColors.Surface,
    onSurface = DwColors.TextPrimary,
    surfaceVariant = DwColors.SurfaceHigh,
    onSurfaceVariant = DwColors.TextSecondary,
    outline = Color(0xFF2A3648),
)

@Composable
fun DeepWardenTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    // Security context reads best dark; we use the dark scheme in both modes
    // for consistent severity-colour semantics.
    MaterialTheme(colorScheme = DarkScheme, content = content)
}

/** Severity → colour mapping used across all screens. */
fun severityColor(severityName: String): Color = when (severityName) {
    "CRITICAL" -> DwColors.DangerRed
    "HIGH" -> DwColors.WarnOrange
    "MEDIUM" -> Color(0xFFFFD24D)
    "LOW" -> DwColors.ElectricBlue
    else -> DwColors.TextSecondary
}

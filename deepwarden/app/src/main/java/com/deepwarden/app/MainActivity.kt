package com.deepwarden.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import com.deepwarden.app.selfprotect.SelfIntegrityChecker
import com.deepwarden.app.ui.DeepWardenRoot
import com.deepwarden.app.ui.theme.DeepWardenTheme
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject

@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    @Inject lateinit var selfIntegrity: SelfIntegrityChecker

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        // Self-protection runs before anything else; a tampered scanner must
        // announce itself, not pretend to scan.
        val integrity = selfIntegrity.check()
        setContent {
            DeepWardenTheme {
                DeepWardenRoot(integrityProblems = integrity.problems)
            }
        }
    }
}

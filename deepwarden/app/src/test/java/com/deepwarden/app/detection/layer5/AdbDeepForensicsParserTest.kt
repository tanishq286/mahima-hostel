package com.deepwarden.app.detection.layer5

import com.deepwarden.app.core.Severity
import com.google.common.truth.Truth.assertThat
import org.junit.Test

class AdbDeepForensicsParserTest {

    private val parser = AdbDeepForensicsParser()

    @Test
    fun `empty paste returns no findings with a limitation`() {
        val (findings, limitations) = parser.parse("")
        assertThat(findings).isEmpty()
        assertThat(limitations).isNotEmpty()
    }

    @Test
    fun `apk in data local tmp is flagged critical`() {
        val paste = """
            package:/data/app/~~abc==/com.normal.app-xyz==/base.apk=com.normal.app
            package:/data/local/tmp/payload.apk=com.fake.update
        """.trimIndent()
        val (findings, _) = parser.parse(paste)
        val hit = findings.single { it.subjectPackage == "com.fake.update" }
        assertThat(hit.severity).isEqualTo(Severity.CRITICAL)
        assertThat(hit.confidence).isAtLeast(85)
    }

    @Test
    fun `normal package paths produce no findings`() {
        val paste = "package:/data/app/~~abc==/com.normal.app-xyz==/base.apk=com.normal.app"
        val (findings, limitations) = parser.parse(paste)
        assertThat(findings).isEmpty()
        // and getprop limitation should be present since we didn't paste props
        assertThat(limitations.any { it.contains("getprop") }).isTrue()
    }

    @Test
    fun `dangerous getprop values are flagged`() {
        val paste = """
            [ro.build.tags]: [release-keys]
            [ro.debuggable]: [1]
            [ro.boot.verifiedbootstate]: [orange]
        """.trimIndent()
        val (findings, _) = parser.parse(paste)
        assertThat(findings).hasSize(2)
        assertThat(findings.map { it.title }.any { it.contains("ro.debuggable") }).isTrue()
        assertThat(findings.map { it.title }.any { it.contains("verifiedbootstate") }).isTrue()
    }

    @Test
    fun `clean getprop output produces no findings`() {
        val paste = """
            [ro.build.tags]: [release-keys]
            [ro.debuggable]: [0]
            [ro.secure]: [1]
            [ro.boot.verifiedbootstate]: [green]
        """.trimIndent()
        val (findings, _) = parser.parse(paste)
        assertThat(findings).isEmpty()
    }

    @Test
    fun `su binary path from which su is critical`() {
        val (findings, _) = parser.parse("/system/xbin/su\n")
        assertThat(findings).hasSize(1)
        assertThat(findings.first().severity).isEqualTo(Severity.CRITICAL)
    }

    @Test
    fun `test-keys kernel is flagged`() {
        val paste = "Linux version 6.1.0-custom (builder@evil) (clang) #1 SMP test-keys"
        val (findings, _) = parser.parse(paste)
        assertThat(findings.any { it.title.contains("kernel", ignoreCase = true) }).isTrue()
    }
}

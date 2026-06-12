package com.deepwarden.app.remediation

import androidx.test.core.app.ApplicationProvider
import com.google.common.truth.Truth.assertThat
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File

/**
 * The personal-data firewall, verified. If any of these fail, the build is
 * not allowed to ship — this is the "never touches personal photos" promise.
 */
@RunWith(RobolectricTestRunner::class)
class SafeCleanEngineTest {

    private val engine = SafeCleanEngine(ApplicationProvider.getApplicationContext())

    @Test
    fun `photos are protected anywhere`() {
        assertThat(engine.isProtected(File("/sdcard/Download/random.jpg"))).isTrue()
        assertThat(engine.isProtected(File("/sdcard/DCIM/Camera/IMG_001.jpg"))).isTrue()
        assertThat(engine.isProtected(File("/tmp/whatever/pic.HEIC"))).isTrue()
    }

    @Test
    fun `whatsapp directory subtree is protected regardless of file type`() {
        assertThat(engine.isProtected(File("/sdcard/WhatsApp/Media/x.tmp"))).isTrue()
        assertThat(engine.isProtected(File("/sdcard/Android/media/WhatsApp/Databases/msgstore.db"))).isTrue()
    }

    @Test
    fun `documents and backups are protected`() {
        assertThat(engine.isProtected(File("/sdcard/Download/cv.pdf"))).isTrue()
        assertThat(engine.isProtected(File("/sdcard/Download/contacts.vcf"))).isTrue()
        assertThat(engine.isProtected(File("/sdcard/Download/backup.zip"))).isTrue()
    }

    @Test
    fun `voice notes are protected`() {
        assertThat(engine.isProtected(File("/sdcard/Download/note.opus"))).isTrue()
        assertThat(engine.isProtected(File("/sdcard/Recordings/call.amr"))).isTrue()
    }

    @Test
    fun `stale junk types in download are deletable`() {
        assertThat(engine.isProtected(File("/sdcard/Download/installer.apk"))).isFalse()
        assertThat(engine.isProtected(File("/sdcard/Download/partial.crdownload"))).isFalse()
        assertThat(engine.isProtected(File("/sdcard/Download/old.tmp"))).isFalse()
    }

    @Test
    fun `protected directories are never entered`() {
        assertThat(engine.isProtectedDir(File("/sdcard/DCIM"))).isTrue()
        assertThat(engine.isProtectedDir(File("/sdcard/Pictures"))).isTrue()
        assertThat(engine.isProtectedDir(File("/sdcard/WhatsApp"))).isTrue()
        assertThat(engine.isProtectedDir(File("/sdcard/Download"))).isFalse()
    }
}

package com.deepwarden.app.detection.common

import android.content.Context
import android.content.pm.PackageManager

/**
 * Installer-source trust.
 *
 * The single biggest source of false positives in a non-root scanner is
 * treating a legitimately store-installed app the same as a sideloaded one.
 * Apps like PhonePe, BHIM, Truecaller and Amazon LEGITIMATELY read OTP SMS and
 * auto-start at boot — that is normal for payment/messaging apps and is NOT a
 * threat when the app came from a vetted store and is store-signed.
 *
 * We use the recorded installer package as a strong (not absolute) trust
 * signal: malware planted by an abuser is almost always sideloaded (null
 * installer) or installed via a package installer / ADB, never via Play.
 */
object InstallerTrust {

    /** App stores whose installs we treat as vetted-by-default. */
    val TRUSTED_INSTALLERS: Set<String> = setOf(
        "com.android.vending",                 // Google Play Store
        "com.google.android.feedback",         // legacy Play installer id
        "com.android.packageinstaller",        // some OEMs report this for Play
        "com.google.android.packageinstaller",
        "com.sec.android.app.samsungapps",     // Samsung Galaxy Store
        "com.amazon.venezia",                  // Amazon Appstore
        "com.xiaomi.market", "com.xiaomi.mipicks", // Mi GetApps
        "com.heytap.market",                   // Oppo/Realme App Market
        "com.vivo.appstore",                   // Vivo
        "com.huawei.appmarket",                // Huawei AppGallery
        "com.oneplus.store",                   // OnePlus
        "com.aurora.store",                    // Aurora (Play proxy)
    )

    /** Installers commonly used to plant apps manually — explicitly untrusted. */
    val SIDELOAD_INSTALLERS: Set<String> = setOf(
        "com.google.android.packageinstaller", // bare APK tap (also OEM Play — context-dependent)
        "com.android.shell",                   // ADB push install — high suspicion
    )

    data class Source(val installer: String?, val trusted: Boolean, val viaAdb: Boolean)

    fun of(context: Context, packageName: String): Source {
        val installer = runCatching {
            context.packageManager.getInstallSourceInfo(packageName).installingPackageName
        }.getOrNull()
        val viaAdb = installer == "com.android.shell"
        val trusted = installer != null && installer in TRUSTED_INSTALLERS && !viaAdb
        return Source(installer, trusted, viaAdb)
    }
}

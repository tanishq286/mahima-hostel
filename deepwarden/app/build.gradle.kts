/*
 * DeepWarden app module.
 *
 * Targets Android 15 (SDK 35), supports back to Android 9 (SDK 28).
 * Clean Architecture: ui/ -> domain (detection/, remediation/) -> data/.
 */
plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.ksp)
    alias(libs.plugins.hilt)
}

android {
    namespace = "com.deepwarden.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.deepwarden.app"
        minSdk = 28
        targetSdk = 35
        versionCode = 1
        versionName = "1.0.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    // Release signing. The keystore + passwords are supplied via environment
    // variables (generated/held by CI). A real release signature greatly
    // reduces Play Protect's hard-blocking of sideloaded installs compared to
    // the throwaway debug key — without touching any app permission (SMS stays).
    signingConfigs {
        create("release") {
            val storePath = System.getenv("DW_KEYSTORE_PATH")
            if (storePath != null) {
                storeFile = file(storePath)
                storePassword = System.getenv("DW_STORE_PASSWORD")
                keyAlias = System.getenv("DW_KEY_ALIAS")
                keyPassword = System.getenv("DW_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            // Shrinking OFF for these self-built APKs: it guarantees the release
            // installs and runs without R8 surprises (we can't hand-test here).
            isMinifyEnabled = false
            isShrinkResources = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            // Use the release signing config only when CI provided a keystore;
            // otherwise fall back so local `assembleRelease` still works.
            signingConfig = if (System.getenv("DW_KEYSTORE_PATH") != null) {
                signingConfigs.getByName("release")
            } else {
                signingConfigs.getByName("debug")
            }
        }
        debug {
            applicationIdSuffix = ".debug"
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
        freeCompilerArgs += listOf("-opt-in=kotlin.RequiresOptIn")
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    testOptions {
        unitTests {
            isIncludeAndroidResources = true
            isReturnDefaultValues = true
        }
    }
    packaging {
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.activity.compose)

    // Compose / Material 3
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons)
    implementation(libs.androidx.navigation.compose)
    debugImplementation(libs.androidx.compose.ui.tooling)

    // DI
    implementation(libs.hilt.android)
    ksp(libs.hilt.compiler)
    implementation(libs.hilt.navigation.compose)
    implementation(libs.hilt.work)
    ksp(libs.hilt.work.compiler)

    // Persistence: Room for scan history & findings, DataStore for settings
    implementation(libs.room.runtime)
    implementation(libs.room.ktx)
    ksp(libs.room.compiler)
    implementation(libs.androidx.datastore.preferences)

    // Background scheduled scans
    implementation(libs.androidx.work.runtime.ktx)

    // Serialization for the local IOC database + JSON forensic reports
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.coroutines.android)

    // Device/environment attestation signal (used as ONE signal, never sole proof)
    implementation(libs.play.integrity)

    // Unit tests for scoring + parsers (the heart of the product)
    testImplementation(libs.junit)
    testImplementation(libs.truth)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.robolectric)
    testImplementation(libs.androidx.test.core) // ApplicationProvider for Robolectric tests
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}

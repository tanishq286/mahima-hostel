# DeepWarden R8 rules.
# Keep serializable threat-intel models (loaded reflectively by kotlinx.serialization).
-keep,includedescriptorclasses class com.deepwarden.app.data.threatintel.**$$serializer { *; }
-keepclassmembers class com.deepwarden.app.data.threatintel.** {
    *** Companion;
}
-keepclasseswithmembers class com.deepwarden.app.data.threatintel.** {
    kotlinx.serialization.KSerializer serializer(...);
}
# Self-protection: keep integrity checker entry points so tamper checks survive shrinking.
-keep class com.deepwarden.app.selfprotect.SelfIntegrityChecker { *; }

# DeepWarden

> **Sees deeper. Deletes nothing.**

A non-root Android deep threat & stalkerware detection app with a **Zero Data Loss guarantee** — built for the worried user with limited storage who is afraid of losing photos, chats and documents.

---

## Play Store listing

**Short description (80 chars):**
> Find hidden spyware deep in your phone — read-only, honest, zero data loss.

**Long description:**

> **Worried someone is watching your phone? DeepWarden looks deeper than ordinary scanners — and guarantees it will never touch your data.**
>
> **SIX LAYERS OF DEEP DETECTION**
> 🔍 **Package forensics** — every app inventoried, including hidden and disabled ones: fake "System Update" apps, sideloaded installs, hidden launcher icons, signature analysis.
> 🧠 **Behavioral heuristics** — weighted permission-combination scoring (the exact patterns stalkerware needs), background-runtime anomalies, battery-exemption abuse.
> 🛡 **System integrity** — accessibility-service abuse, device admins resisting uninstall, USB debugging residue, root traces, missing screen lock.
> 🌐 **Network forensics** — rogue proxies, suspicious Private DNS, unknown VPNs intercepting your traffic.
> 💻 **ADB Deep Forensics (expert mode)** — guided, read-only computer commands reveal what no installed app can see: staged APKs in /data/local/tmp, unlocked bootloaders, debug builds, su binaries, live-bound accessibility services.
> ✉️ **Message analysis (optional)** — on-device phishing/smishing detection. Your messages never leave the phone.
>
> **ZERO DATA LOSS, BY DESIGN**
> DeepWarden is read-only. It never uninstalls, never wipes, never resets. Safe Mode (on by default) only ever suggests fully reversible steps — disable instead of uninstall, revoke instead of remove. Every suggestion shows exactly what it touches, why it's safe, and how to undo it.
>
> **HONEST, NOT SCARY**
> We tell you plainly what a non-root scanner cannot see (true kernel rootkits, some encrypted exfiltration). Every finding shows a confidence %, the evidence, and how the technique works. A calm instrument, not a fear machine.
>
> **PRIVATE BY DEFAULT**
> 100% local analysis. No account. No uploads. The only network features (threat-intel updates, anonymous IOC contribution) are opt-in and clearly labelled.
>
> **BONUS: Smart Safe Clean** — recover storage from caches and stale junk only. Photos, WhatsApp media, voice notes and documents are protected by a hard firewall in the code, verified by automated tests.

---

## Project structure

```
deepwarden/
├── settings.gradle.kts / build.gradle.kts / gradle.properties
├── gradle/libs.versions.toml            # version catalog (Kotlin 2.1, AGP 8.7, Compose BOM 2024.12)
└── app/
    ├── build.gradle.kts                 # SDK 35, minSdk 28, Hilt + Room + WorkManager + DataStore
    ├── proguard-rules.pro
    └── src/
        ├── main/
        │   ├── AndroidManifest.xml      # permission philosophy documented inline
        │   ├── assets/threat_intel/ioc_rules.json   # responsible local IOC DB
        │   ├── res/...                  # dark security theme, adaptive icon, backup-exclusion rules
        │   └── java/com/deepwarden/app/
        │       ├── core/                # Finding, SafeAction (zero-data-loss types), ScanModels
        │       ├── detection/
        │       │   ├── layer1/          # PackageForensicsScanner — static & package forensics
        │       │   ├── layer2/          # PermissionScoring table + BehavioralHeuristicsScanner
        │       │   ├── layer3/          # SystemIntegrityScanner — settings/admin/accessibility/root
        │       │   ├── layer4/          # NetworkForensicsScanner — proxy/VPN/DNS
        │       │   ├── layer5/          # AdbDeepForensicsParser — expert deep mode (pure, testable)
        │       │   ├── layer6/          # PhishingRules + ContentAnalysisScanner (opt-in)
        │       │   └── engine/          # ScanOrchestrator + ThreatScoringEngine (multi-dimensional)
        │       ├── remediation/         # SafeRemediationEngine (Safe Mode) + SafeCleanEngine (storage)
        │       ├── report/              # ForensicReportExporter (PDF + JSON)
        │       ├── work/                # ScheduledScanWorker (WorkManager)
        │       ├── selfprotect/         # SelfIntegrityChecker (anti-tampering)
        │       ├── data/                # Room history+diff, DataStore settings, ThreatIntelRepository
        │       └── ui/                  # Compose M3: Dashboard, Scan, ADB, Clean, History, Settings, Onboarding
        └── test/                        # unit tests: scoring, parser, phishing, remediation, clean firewall
```

## The 6-layer detection model (summary)

| Layer | Visibility | Key catches |
|---|---|---|
| 1 Static forensics | PackageManager (incl. disabled/hidden pkgs) | fake system apps, sideloads, hidden icons, boot/SMS receivers, bad certs |
| 2 Behavioral | UsageStats + PowerManager + scoring table | stalkerware permission combos, "never opened but always running", battery-exemption abuse |
| 3 System integrity | Settings/DPM/AccessibilityManager | accessibility abuse, device admins, USB debugging, no screen lock, root heuristics |
| 4 Network | ConnectivityManager + Settings.Global | global proxy, unknown VPN, rogue Private DNS |
| 5 ADB deep mode | `shell` UID via user-run read-only commands | /data/local/tmp APKs, ro.debuggable/ro.secure, unlocked bootloader, su, live accessibility bindings |
| 6 Content (opt-in) | SMS provider, local regex rules | smishing, credential bait, APK links, SMS-C2 command shapes |

Findings carry **severity, confidence %, evidence, the detecting layer, a safe action, undo steps, and data-loss impact** — enforced by the type system (`Finding`/`SafeAction` constructors reject dishonest values).

## Build & run

Requirements: JDK 17, Android Studio Ladybug+ (AGP 8.7), SDK 35.

```bash
# from the deepwarden/ directory
gradle wrapper --gradle-version 8.10.2   # first time only (wrapper binaries aren't committed)
./gradlew assembleDebug                  # build
./gradlew testDebugUnitTest              # run the unit-test suite (scoring/parser/firewall)
./gradlew installDebug                   # install on a connected device
```

## Testing the ADB Deep Mode (Layer 5)

1. Build & install the app, open the **Deep** tab.
2. On the phone: Settings → About → tap *Build number* 7× → Developer options → **USB debugging ON** (temporarily!).
3. On a trusted computer with platform-tools:
   ```bash
   adb shell pm list packages -f -u   > out.txt
   adb shell getprop                 >> out.txt
   adb shell cat /proc/version       >> out.txt
   adb shell which su                >> out.txt
   adb shell dumpsys accessibility   >> out.txt
   ```
4. Paste `out.txt` contents into the app's analysis box → **Analyse on-device**.
5. Quick synthetic test: append a line `package:/data/local/tmp/x.apk=com.fake.update` to the paste — the parser must flag it CRITICAL.
6. **Turn USB debugging OFF.** (Layer 3 will flag it on the next scan if you forget — by design.)

## Play Store policy compliance notes (security apps, 2026)

- **QUERY_ALL_PACKAGES**: declared as core functionality (anti-stalkerware scanning) in the Play Console permissions declaration form; the app is a security/antivirus category app, which is an accepted use case.
- **READ_SMS (Layer 6)**: SMS is a restricted permission. For Play, either (a) apply under the "device security" exception with a demo video, or (b) ship the Play flavor **without** Layer 6 (remove the permission in a product flavor; the layer already degrades gracefully and reports itself as skipped). Recommendation: (b) for fastest approval; keep Layer 6 in the website/F-Droid build.
- **PACKAGE_USAGE_STATS**: special access granted by the user in Settings; show the in-app rationale before deep-linking (already implemented in scan limitations text).
- **Stalkerware policy**: DeepWarden *detects* stalkerware and contains no tracking functionality — it complies with Play's stalkerware policy rather than being restricted by it. The IOC database contains behavioral patterns only, no malware code.
- **Data safety form**: declare "no data collected, no data shared"; both optional network features send no user/device data (intel update is a plain download; IOC contribution is opt-in, anonymous hashes only — implement server-side before enabling the toggle's network path).
- **Foreground services / WorkManager**: scheduled scans use WorkManager (no exempt FGS types needed on Android 14+).
- **Backup exclusions**: scan reports and the findings DB are excluded from cloud backup & device transfer so an abuser restoring a victim's backup cannot read the evidence (see `backup_rules.xml`).

## Honest limitations (also shown in-app)

Without root, no app — including this one — can detect true kernel rootkits, fully inspect /data, or guarantee detection of well-disguised encrypted exfiltration. Layer 5 narrows the gap using the `shell` UID; it does not close it. We say this everywhere, on purpose.

## License

MIT (see LICENSE).

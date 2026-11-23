/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.report

import com.awakekt.releaseguard.model.AuditFinding
import com.awakekt.releaseguard.model.CheckStatus

/** Plain-English explanation translating a technical check ID into real-world attacker impact. */
public data class FindingExplanation(
    public val attackerLevel: String,
    public val plainEnglishImpact: String,
    public val passingMeaning: String,
)

/**
 * Translates technical Release Guard check IDs into clear, jargon-free descriptions of what an
 * attacker or rookie reverse-engineer can see or exploit when a check fails.
 */
public object FindingExplainer {
    private val catalog: Map<String, FindingExplanation> = mapOf(
        "desktop.jars.present" to FindingExplanation(
            attackerLevel = "Build Pipeline",
            plainEnglishImpact = "No desktop JAR files were found to verify, so release obfuscation was not validated.",
            passingMeaning = "Desktop release JARs were located and inspected.",
        ),
        "desktop.obfuscation.readability" to FindingExplanation(
            attackerLevel = "Rookie (5 min with JD-GUI / Jadx)",
            plainEnglishImpact = "A rookie developer can drag your JAR into a free Java decompiler and read your game's real class, field, and method names almost like original source code, making it easy to copy logic or find cheat hooks.",
            passingMeaning = "Your own desktop classes and methods are scrambled into short meaningless names, forcing reverse-engineers to trace raw logic instead of reading names.",
        ),
        "desktop.obfuscation.project_packages" to FindingExplanation(
            attackerLevel = "Rookie (ZIP viewer)",
            plainEnglishImpact = "Unzipping your JAR still reveals your folder/package layout (such as combat, economy, or networking packages), acting like a table of contents for reverse-engineers.",
            passingMeaning = "Your internal package hierarchy is flattened so attackers cannot browse features by folder name.",
        ),
        "desktop.metadata.source_file" to FindingExplanation(
            attackerLevel = "Rookie (Decompiler / stack trace)",
            plainEnglishImpact = "Original .kt/.java filenames remain attached to compiled classes, telling anyone inspecting a crash or decompiler which files each obfuscated class came from.",
            passingMeaning = "Original source filenames are scrubbed so stack traces and decompilers only see a generic SourceFile label.",
        ),
        "desktop.metadata.debug_tables" to FindingExplanation(
            attackerLevel = "Rookie to Intermediate (Decompiler)",
            plainEnglishImpact = "Even if classes are renamed, surviving @kotlin.Metadata, LocalVariableTable, or MethodParameters act like a cheat-sheet that reveals original Kotlin property names, local variable names, and parameter signatures.",
            passingMeaning = "Debug variable tables and Kotlin metadata cheat-sheets are stripped from desktop bytecode.",
        ),
        "desktop.bytecode.verify" to FindingExplanation(
            attackerLevel = "Runtime Stability Blocker",
            plainEnglishImpact = "ProGuard rewrote bytecode in a way the JVM rejects with VerifyError, meaning real players will crash immediately when those classes load.",
            passingMeaning = "Every obfuscated class passed JVM bytecode verification cleanly with zero VerifyErrors.",
        ),
        "desktop.mapping.hygiene" to FindingExplanation(
            attackerLevel = "Rookie (Unzip)",
            plainEnglishImpact = "Shipping mapping.txt inside a JAR hands attackers the exact translation dictionary to undo all obfuscation in one click (or missing an archived copy leaves you unable to decode player crash logs).",
            passingMeaning = "No mapping dictionary is leaked inside shipped JARs.",
        ),
        "desktop.native.hardening" to FindingExplanation(
            attackerLevel = "Intermediate (Native Debugger / strings)",
            plainEnglishImpact = "Bundled native libraries (.dll/.so/.dylib) lack OS exploit mitigations (ASLR/DEP/RELRO/NX) or leak your developer machine's local .pdb debug path.",
            passingMeaning = "Desktop native libraries enable OS memory mitigations and scrub local debug paths.",
        ),
        "desktop.jpackage.config" to FindingExplanation(
            attackerLevel = "Rookie (Attach Debugger)",
            plainEnglishImpact = "Debug JVM flags (such as JDWP remote debugging or assertions) are baked into the shipped launcher config, letting anyone attach a debugger to the live desktop app.",
            passingMeaning = "Launcher .cfg files contain no JDWP or debug JVM flags.",
        ),
        "desktop.assets.encryption" to FindingExplanation(
            attackerLevel = "Rookie (Unzip / Asset Viewer)",
            plainEnglishImpact = "Packaged content bundles are plaintext, letting anyone extract 3D models, textures, and game data straight from the install folder.",
            passingMeaning = "Packaged content bundles carry encrypted v2 headers.",
        ),
        "desktop.secrets.scan" to FindingExplanation(
            attackerLevel = "Rookie (strings command)",
            plainEnglishImpact = "A rookie can run 'strings' on your JAR and extract embedded API keys, private keys, .env files, or local dev URLs in seconds.",
            passingMeaning = "No private keys, high-entropy tokens, or sensitive key/.env files were found in desktop JARs.",
        ),
        "android.artifact.present" to FindingExplanation(
            attackerLevel = "Build Pipeline",
            plainEnglishImpact = "No Android APK or AAB was found at the configured path, so Android release posture was not verified.",
            passingMeaning = "Android release archive was located and inspected.",
        ),
        "android.obfuscation.readability" to FindingExplanation(
            attackerLevel = "Rookie (5 min with Jadx-GUI)",
            plainEnglishImpact = "Anyone can drop your APK/AAB into Jadx-GUI and read your app's real Kotlin class, screen, shop, and protocol names like original source code.",
            passingMeaning = "R8 minified and scrambled non-framework classes and members below the readability threshold.",
        ),
        "android.metadata.kotlin_metadata" to FindingExplanation(
            attackerLevel = "Rookie to Intermediate (Jadx)",
            plainEnglishImpact = "Surviving @kotlin.Metadata annotations inside DEX files expose original Kotlin property names, default parameters, and sealed-class structures.",
            passingMeaning = "No @kotlin.Metadata descriptors remain inside release DEX files.",
        ),
        "android.manifest.debuggable" to FindingExplanation(
            attackerLevel = "Rookie (USB cable + Android Studio)",
            plainEnglishImpact = "With android:debuggable=true, anyone with a USB cable can attach a debugger, read private app storage with 'run-as', pause gameplay, and edit variables in memory.",
            passingMeaning = "android:debuggable is disabled, blocking standard USB debugger attachment and 'run-as' file access.",
        ),
        "android.manifest.network_and_backup" to FindingExplanation(
            attackerLevel = "Rookie (Wi-Fi proxy / adb backup)",
            plainEnglishImpact = "Enabling allowBackup lets users pull private app data over ADB, while usesCleartextTraffic allows unencrypted HTTP traffic that anyone on the same Wi-Fi can read or tamper with.",
            passingMeaning = "ADB backup and unencrypted HTTP cleartext traffic are both disabled.",
        ),
        "android.manifest.test_only_and_sdk" to FindingExplanation(
            attackerLevel = "Store / Platform Blocker",
            plainEnglishImpact = "android:testOnly=true blocks normal installation outside ADB, and outdated targetSdkVersion misses newer Android platform security restrictions and Play Store compliance.",
            passingMeaning = "Manifest is free of testOnly flags and satisfies targetSdkVersion requirements.",
        ),
        "android.manifest.exported_components" to FindingExplanation(
            attackerLevel = "Intermediate (Malicious App / ADB Intent)",
            plainEnglishImpact = "An exported Activity, Service, Receiver, or ContentProvider without a permission guard can be triggered directly by other apps on the phone or via ADB to bypass screens or read internal data.",
            passingMeaning = "Only intended launcher or permission-protected components are exported.",
        ),
        "android.manifest.network_security_config" to FindingExplanation(
            attackerLevel = "Rookie (Burp Suite / mitmproxy)",
            plainEnglishImpact = "Trusting user-installed certificates or leaving <debug-overrides> lets anyone install a proxy cert on their phone and silently decrypt/modify all HTTPS API traffic.",
            passingMeaning = "network_security_config does not trust user CA certificates or ship debug overrides.",
        ),
        "android.signing.release_cert" to FindingExplanation(
            attackerLevel = "Rookie / Play Store Blocker",
            plainEnglishImpact = "An unsigned, debug-signed (CN=Android Debug), or v1-only APK cannot ship safely (and v1-only APKs are vulnerable to Janus tampering without breaking signatures).",
            passingMeaning = "Signed with a production release certificate using modern APK Signature Scheme v2/v3.",
        ),
        "android.native.elf_hardening" to FindingExplanation(
            attackerLevel = "Intermediate (Memory Exploit / Android 15+ Crash)",
            plainEnglishImpact = "Native C++/JNI .so libraries missing Full RELRO, NX, PIE, or stripping are easier to reverse-engineer or exploit; 64-bit .so files below 16 KB alignment fail Google Play's Android 15+ requirement and crash on 16 KB devices.",
            passingMeaning = "All native .so libraries enable Full RELRO, NX, PIE, symbol stripping, and 16 KB page alignment.",
        ),
        "android.packaging.debug_artifacts" to FindingExplanation(
            attackerLevel = "Rookie (Unzip APK)",
            plainEnglishImpact = "Debug artifacts (coroutine probes, Vulkan validation layers, tooling metadata) or sensitive files (.env, .jks, .pem) were left inside the APK/AAB, bloating downloads and exposing internals.",
            passingMeaning = "Debug probes, validation layers, and sensitive files are stripped from the Android archive.",
        ),
        "android.assets.encryption" to FindingExplanation(
            attackerLevel = "Rookie (Unzip APK)",
            plainEnglishImpact = "Unencrypted game content bundles sit inside assets/, allowing anyone who unzips the APK to extract art, maps, and definitions directly.",
            passingMeaning = "Packaged Android content bundles carry encrypted v2 headers.",
        ),
        "android.secrets.scan" to FindingExplanation(
            attackerLevel = "Rookie (Jadx / strings)",
            plainEnglishImpact = "Hardcoded credentials, private keys, or localhost dev endpoints are readable directly in DEX or assets by anyone running 'strings' or Jadx.",
            passingMeaning = "No private keys, high-entropy secrets, or forbidden endpoints were found in the Android archive.",
        ),
        "web.bundle.present" to FindingExplanation(
            attackerLevel = "Build Pipeline",
            plainEnglishImpact = "Web distribution directory was not found, so browser-delivered code could not be audited.",
            passingMeaning = "Web bundle directory was located and inspected.",
        ),
        "web.sourcemaps.absent" to FindingExplanation(
            attackerLevel = "Rookie (Browser F12 DevTools)",
            plainEnglishImpact = "Shipping .map source maps lets any player press F12 in Chrome/Firefox and browse your original, unminified source files line by line.",
            passingMeaning = "No .map files or JS/CSS sourceMappingURL pointers are shipped to browsers.",
        ),
        "web.wasm.debug_sections" to FindingExplanation(
            attackerLevel = "Rookie (Browser DevTools / wasm2wat)",
            plainEnglishImpact = "Unstripped WASM 'name' or '.debug*' sections give anyone opening browser DevTools every internal function name in your compiled WebAssembly module.",
            passingMeaning = "WASM custom debug, name, and producer sections are stripped from the production binary.",
        ),
        "web.wasm.exports" to FindingExplanation(
            attackerLevel = "Rookie (Browser Console)",
            plainEnglishImpact = "Excessive WASM exports expose internal functions directly to JavaScript in the browser console.",
            passingMeaning = "WASM export surface is minimal and tightly scoped.",
        ),
        "web.obfuscation.readability" to FindingExplanation(
            attackerLevel = "Rookie (Browser DevTools / strings)",
            plainEnglishImpact = "Too many recognisable identifiers survive in your WASM/JS bundle, making it much easier for someone in browser DevTools to map out game systems.",
            passingMeaning = "Web bundle identifier readability sits safely within the production threshold.",
        ),
        "web.metadata.source_paths" to FindingExplanation(
            attackerLevel = "Rookie (strings on .wasm)",
            plainEnglishImpact = "Your local machine's username, directory layout, and exact .kt filenames are embedded inside the public .wasm file downloaded by every browser.",
            passingMeaning = "No local project .kt build paths are leaked inside the web bundle.",
        ),
        "web.metadata.fqn_classes" to FindingExplanation(
            attackerLevel = "Rookie (strings on .wasm)",
            plainEnglishImpact = "Fully-qualified Kotlin class names inside the WASM module reveal your internal architecture even after function names are stripped.",
            passingMeaning = "Qualified class name exposure in WASM is within configured limits.",
        ),
        "web.headers.security" to FindingExplanation(
            attackerLevel = "Rookie to Intermediate (XSS / Clickjacking)",
            plainEnglishImpact = "Without strict CSP, X-Content-Type-Options, X-Frame-Options/frame-ancestors, and Referrer-Policy in _headers, attackers can more easily embed your site in a spoofed iframe (clickjacking) or run injected scripts inside the game tab.",
            passingMeaning = "Static hosting _headers enforces strict CSP, clickjacking protection, nosniff, and Referrer-Policy.",
        ),
        "web.html.sri" to FindingExplanation(
            attackerLevel = "Intermediate (CDN Supply-Chain Tampering)",
            plainEnglishImpact = "Loading external scripts or stylesheets without an integrity='sha384-...' hash means if that third-party CDN is compromised, malicious code runs straight inside your player's browser. (Dynamic font CDNs like Google Fonts cannot use static SRI; self-host fonts or allowlist them explicitly.)",
            passingMeaning = "External scripts and stylesheets are self-hosted, SRI-pinned, or explicitly allowlisted.",
        ),
        "web.runtime.insecure_endpoints" to FindingExplanation(
            attackerLevel = "Rookie (Public Wi-Fi Sniffing / DevTools)",
            plainEnglishImpact = "Plaintext http:// or ws:// URLs expose player traffic over untrusted networks, and leftover 'debugger;' statements freeze the browser when DevTools opens.",
            passingMeaning = "No cleartext http:// or ws:// endpoints or debugger; statements exist in the web bundle.",
        ),
        "web.packaging.sensitive_files" to FindingExplanation(
            attackerLevel = "Rookie (Direct URL GET /.env)",
            plainEnglishImpact = "Files like .env, .git, .pem, or .sqlite inside the web dist directory can be downloaded directly by anyone guessing the URL.",
            passingMeaning = "No .env, .git, private key, or database files exist inside the web distribution folder.",
        ),
        "web.secrets.scan" to FindingExplanation(
            attackerLevel = "Rookie (Browser DevTools / strings)",
            plainEnglishImpact = "Every byte of a web bundle is downloaded by the user's browser; any embedded API key, private key, or localhost dev URL is immediately visible to anyone. (If a Firebase/GCP web API key is intentionally public, lock it down with HTTP referrer restrictions in GCP Console and allowlist it in policy.)",
            passingMeaning = "No leaked private keys, secret tokens, or forbidden endpoints were found in the web bundle.",
        ),
        "ios.binary.present" to FindingExplanation(
            attackerLevel = "Build Pipeline",
            plainEnglishImpact = "No iOS Mach-O binary was found to audit.",
            passingMeaning = "iOS Mach-O binary was located and inspected.",
        ),
        "ios.macho.dwarf_absent" to FindingExplanation(
            attackerLevel = "Rookie (nm / Hopper / Ghidra)",
            plainEnglishImpact = "An embedded __DWARF debug segment ships full source-level debug info inside your iOS binary, letting disassemblers show exact source file lines, struct layouts, and variable names.",
            passingMeaning = "Debug DWARF info is separated into dSYMs and stripped from the shipped Mach-O binary.",
        ),
        "ios.macho.symbols_stripped" to FindingExplanation(
            attackerLevel = "Rookie (nm / Hopper / Ghidra)",
            plainEnglishImpact = "Unstripped STAB or local project symbols let anyone running 'nm' or Ghidra list your private internal Kotlin/Swift function names.",
            passingMeaning = "Mach-O debug and local project symbols are cleanly stripped.",
        ),
        "ios.macho.hardening" to FindingExplanation(
            attackerLevel = "Intermediate (Memory Patching / Tampering)",
            plainEnglishImpact = "Missing MH_PIE disables ASLR memory randomization (making memory patches/offsets static), and missing LC_CODE_SIGNATURE means the IPA binary is unsigned.",
            passingMeaning = "Mach-O binaries enable PIE (ASLR) and carry code signatures.",
        ),
        "ios.macho.build_paths" to FindingExplanation(
            attackerLevel = "Rookie (strings)",
            plainEnglishImpact = "Workstation paths (/Users/...) embedded in the binary leak developer usernames and local project folder layout.",
            passingMeaning = "No developer workstation build paths are leaked in Mach-O strings.",
        ),
        "ios.plist.ats" to FindingExplanation(
            attackerLevel = "Rookie (Wi-Fi MITM)",
            plainEnglishImpact = "Disabling App Transport Security (NSAllowsArbitraryLoads or insecure HTTP exception domains) lets the iOS app talk over unencrypted HTTP that attackers on shared Wi-Fi can inspect or alter.",
            passingMeaning = "App Transport Security (ATS) remains strictly enforced in Info.plist.",
        ),
        "ios.ipa.provisioning" to FindingExplanation(
            attackerLevel = "Rookie (Xcode / lldb Attach)",
            plainEnglishImpact = "get-task-allow=true in embedded.mobileprovision allows anyone to attach a debugger to the release app and dump or modify live memory.",
            passingMeaning = "Provisioning profile disables get-task-allow for production distribution.",
        ),
        "ios.plist.privacy_manifest" to FindingExplanation(
            attackerLevel = "App Store Review Blocker",
            plainEnglishImpact = "Missing PrivacyInfo.xcprivacy can cause App Store Connect rejection when using required-reason Apple APIs.",
            passingMeaning = "PrivacyInfo.xcprivacy manifest is bundled.",
        ),
        "ios.secrets.scan" to FindingExplanation(
            attackerLevel = "Rookie (strings)",
            plainEnglishImpact = "Hardcoded secrets or private keys inside an iOS binary or Info.plist can be extracted in seconds with 'strings'.",
            passingMeaning = "No leaked private keys or secret tokens were found in the iOS artifact.",
        ),
        "tls.spki.configured" to FindingExplanation(
            attackerLevel = "Intermediate (MITM Proxy)",
            plainEnglishImpact = "Without TLS SPKI pinning, anyone who installs a custom root certificate on their own device can intercept and inspect HTTPS game traffic.",
            passingMeaning = "TLS SPKI pinning rules are configured.",
        ),
        "tls.spki.syntax" to FindingExplanation(
            attackerLevel = "Runtime Connection Failure",
            plainEnglishImpact = "Malformed SPKI pin syntax will fail at startup or silently disable pinning protection.",
            passingMeaning = "All TLS SPKI pin entries use valid 32-byte Base64 SHA-256 hashes.",
        ),
        "tls.spki.rotation_backup" to FindingExplanation(
            attackerLevel = "Operational Lockout Risk",
            plainEnglishImpact = "Pinning only a single key per host risks locking out every player if your TLS certificate is ever rotated unexpectedly.",
            passingMeaning = "Every pinned host includes at least one backup pin for safe certificate rotation.",
        ),
        "tls.spki.live_match" to FindingExplanation(
            attackerLevel = "Outage Blocker",
            plainEnglishImpact = "Your configured SPKI pins do not match the live server certificate chain — shipping this build will immediately break player logins.",
            passingMeaning = "Live TLS endpoints match the configured SPKI pins.",
        ),
        "supplychain.dependencies.snapshots" to FindingExplanation(
            attackerLevel = "Supply-Chain / Reproducibility Risk",
            plainEnglishImpact = "Shipping mutable -SNAPSHOT dependencies means two builds from the same commit can silently pull different code.",
            passingMeaning = "All resolved release dependencies are pinned to immutable versions.",
        ),
    )

    /** Returns a plain-English [FindingExplanation] for [finding]. */
    public fun explain(finding: AuditFinding): FindingExplanation = catalog[finding.checkId] ?: FindingExplanation(
        attackerLevel = when (finding.severity.rank) {
            4, 3 -> "Rookie to Intermediate"
            2 -> "Intermediate"
            else -> "Hygiene Polish"
        },
        plainEnglishImpact = finding.summary,
        passingMeaning = finding.summary,
    )

    /** Returns the most relevant plain-English sentence for [finding] based on its current [AuditFinding.status]. */
    public fun narrativeFor(finding: AuditFinding): String {
        val exp = explain(finding)
        return when (finding.status) {
            CheckStatus.PASS -> exp.passingMeaning
            CheckStatus.SKIP -> "Skipped for this run (${finding.summary})."
            CheckStatus.WARN, CheckStatus.FAIL -> exp.plainEnglishImpact
        }
    }
}

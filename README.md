# Release Guard

Reusable, Apache-2.0, zero-Python build hardening, binary verification, and weighted release-hygiene
scoring for Kotlin Multiplatform (KMP) applications and games — covering **Desktop JVM**, **Android
(APK & AAB)**, **Web (Kotlin/Wasm + JS)**, **iOS (`.framework`, `.xcframework`, `.ipa`)**, **TLS
SPKI pinning**, and **Supply Chain** checks.

All binary parsers (JVM `.class`, Dalvik `.dex`, Android AXML & AAB Protobuf manifests, APK v1/v2/v3
Signing Blocks, ELF `.so`, Windows PE32/PE32+ `.dll`/`.exe`, WebAssembly `.wasm`, Apple Mach-O &
Universal Fat binaries, and Apple binary `bplist00`) are implemented in pure Kotlin with hard memory
and ZIP-bomb read limits — no Python, `apktool`, `dexdump`, `readelf`, `wasm-opt`, or `nm` required.

## Trust boundary

Release Guard audits **static obfuscation, binary hardening, packaging hygiene, and transport
configuration**. It raises reverse-engineering cost and blocks accidental debug/secret leaks before
shipping, but **never replaces server-authoritative logic, entitlement validation, or runtime RASP**.

## Modules

| Module | Coordinate | Purpose |
| --- | --- | --- |
| `:release-guard-core` | `com.awakekt.releaseguard:release-guard-core` | Pure-Kotlin binary inspectors, web stripper, weighted scorer, plain-English attacker-impact explainer, baseline diff engine, and Console/JSON/Markdown/HTML/SARIF 2.1.0 renderers. |
| `:release-guard-cli` | `com.awakekt.releaseguard:release-guard-cli` | Standalone CLI (`audit`, `strip-web`, `print-tls-pins`, `init-policy`). |
| `:release-guard-gradle-plugin` | `com.awakekt.release-guard` | Configuration-cache-safe Gradle plugin generating ProGuard/R8 rules, collecting library keep rules, stripping web bundles, wiring KMP/AGP release hardening, and gating CI builds. |

## What Release Guard checks

| Target | Checks |
| --- | --- |
| **Desktop JVM** | Constant-pool readability (excluding library & JDK overrides), project package flattening, `SourceFile` scrubbing, `@kotlin.Metadata` / `LocalVariableTable` / `MethodParameters` stripping, JVM `VerifyError` bytecode linking, `mapping.txt` hygiene, native PE/ELF/Mach-O hardening (ASLR, DEP, RELRO, NX, leaked `.pdb` paths), `jpackage` `.cfg` JDWP/debug flags, optional `.awkb` asset encryption, high-entropy + regex secret & sensitive-file scan. |
| **Android (APK & AAB)** | DEX readability & kept classes, `@kotlin.Metadata` in DEX, binary AXML & AAB Protobuf `AndroidManifest.xml` (`debuggable`, `allowBackup`, `usesCleartextTraffic`, `testOnly`, `targetSdkVersion`, unguarded `android:exported="true"` components), `network_security_config.xml` (`<certificates src="user"/>`, `<debug-overrides>`), v2/v3 release signing (rejecting debug certs and v1-only Janus APKs), native ELF `.so` hardening (Full RELRO, NX, PIE, symbol stripping, **Android 15+ 16 KB page alignment**), forbidden debug/Vulkan validation artifacts & sensitive files, optional `.awkb` encryption, secrets. |
| **Web (WASM/JS)** | `.map` & JS/CSS `sourceMappingURL` exclusion, lossless WASM `name`/`producers`/`.debug*` custom section stripping & export audit, bundle readability, leaked `.kt` repo paths (with allowlisted CI library paths), FQN class count, `_headers` presence + CSP directive quality grading, Subresource Integrity (SRI) on external scripts/stylesheets, cleartext `http://`/`ws://` & `debugger;` residue, sensitive dist files (`.env`, `.git`), secrets. |
| **iOS (Framework / XCFramework / IPA)** | Multi-slice `.xcframework` and `.ipa` inspection, `__DWARF` absence, unstripped STAB/local symbols, `MH_PIE` (ASLR) & `LC_CODE_SIGNATURE`, leaked workstation build paths, XML & binary `bplist00` `Info.plist` ATS (`NSAllowsArbitraryLoads` & insecure `NSExceptionDomains`), `embedded.mobileprovision` (`get-task-allow=true`, ad-hoc profiles), `PrivacyInfo.xcprivacy`, secrets. |
| **Transport TLS** | SPKI SHA-256 pin syntax, wildcard matching (`*.`, `**.`), rotation backup pin count, optional live TLS handshake verification, and live pin printing. |
| **Supply Chain & Baselines** | Gradle `-SNAPSHOT` dependency gating, baseline regression diffing (`--baseline` / `--fail-on-regression`), and SARIF 2.1.0 output for GitHub Code Scanning. |

## Installation (Zero-Token Public Maven)

Release Guard is published to **Maven Central** and mirrored (GPG-signed, zero-token) at **`https://awakekt.github.io/release-guard/`**. Add both in `settings.gradle.kts`:

```kotlin
pluginManagement {
    repositories {
        maven("https://awakekt.github.io/release-guard/") {
            content {
                includeGroup("com.awakekt.releaseguard")
                includeGroup("com.awakekt.release-guard")
            }
        }
        gradlePluginPortal()
        mavenCentral()
    }
}
```

Then apply the plugin or add the core library:

```kotlin
plugins {
    id("com.awakekt.release-guard") version "<version>"
}

// Or as a standalone Kotlin/JVM library:
dependencies {
    implementation("com.awakekt.releaseguard:release-guard-core:<version>")
}
```

## Gradle plugin quick start

```kotlin
plugins {
    id("com.awakekt.release-guard") version "<version>"
}

releaseGuard {
    projectPackages.add("com.example.game")
    projectKeywords.add("harbortown")
    minScore.set(85)
    failOnSeverity.set("HIGH")

    rules {
        mainClass.set("com.example.game.desktop.MainKt")
        desktopDontOptimize.set(true)
        stripKotlinMetadata.set(false)
    }

    desktop {
        enabled.set(true)
        gameJarsDir.set(layout.buildDirectory.dir("obfuscated/jars"))
        librariesDir.set(layout.buildDirectory.dir("install/desktopApp/lib"))
        nativeLibsDir.set(layout.buildDirectory.dir("install/desktopApp/natives"))
    }

    web {
        enabled.set(true)
        inputDir.set(layout.buildDirectory.dir("dist/wasmJs/productionExecutable"))
    }

    android {
        enabled.set(true)
        artifactFile.set(layout.buildDirectory.file("outputs/bundle/release/app-release.aab"))
    }

    ios {
        enabled.set(false)
        artifactPath.set(layout.buildDirectory.file("ios/GameRelease.ipa").map { it.asFile.absolutePath })
    }

    tls {
        enabled.set(true)
        spkiPins.set(providers.environmentVariable("APP_TLS_SPKI_PINS"))
    }

    supplyChain {
        enabled.set(true)
    }

    reports {
        baselineFile.set(layout.projectDirectory.file("security-baseline.json"))
        failOnRegression.set(true)
    }
}
```

## CLI quick start

```bash
# Generate a starter policy
./gradlew :release-guard-cli:run --args="init-policy --preset strict --project-package com.example.game --output release-guard.json"

# Harden a Kotlin/Wasm bundle (strip WASM debug sections, drop maps, emit CSP _headers)
./gradlew :release-guard-cli:run --args="strip-web --input app/webApp/build/dist/wasmJs/productionExecutable --output build/web-hardened"

# Audit artifacts, compare against baseline, and emit HTML dashboard + JSON + Markdown + SARIF 2.1.0
./gradlew :release-guard-cli:run --args="audit --config release-guard.json --android-aab app-release.aab --web-dir build/web-hardened --ios-artifact Game.ipa --baseline baseline.json --fail-on-regression --html-out build/scorecard.html --json-out build/scorecard.json --markdown-out build/scorecard.md --sarif-out build/scorecard.sarif"
```

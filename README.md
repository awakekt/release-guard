# Release Guard

Reusable, Apache-2.0, zero-Python build hardening, binary verification, and weighted release-hygiene
scoring for Kotlin Multiplatform (KMP) applications and games — covering **Desktop JVM**, **Android
(APK & AAB)**, **Web (Kotlin/Wasm + JS)**, **iOS (`.framework`, `.xcframework`, `.ipa`)**, **TLS
SPKI pinning**, and **Supply Chain** checks.

All binary parsers (JVM `.class`, Dalvik `.dex`, Android AXML & AAB Protobuf manifests, APK v1/v2/v3
Signing Blocks, ELF `.so`, Windows PE32/PE32+ `.dll`/`.exe`, WebAssembly `.wasm`, Apple Mach-O &
Universal Fat binaries, and Apple binary `bplist00`) are implemented in pure Kotlin with hard memory
and ZIP-bomb read limits — no Python, `apktool`, `dexdump`, `readelf`, `wasm-opt`, or `nm` required.

## Trust boundary & scope discipline

Release Guard audits **static obfuscation, binary hardening, packaging hygiene, and transport
configuration**. It raises reverse-engineering cost and blocks accidental debug/secret leaks before
shipping, but **never replaces server-authoritative logic, entitlement validation, or runtime RASP**.

To keep Release Guard reusable across any Kotlin Multiplatform app or game, maintain a strict
boundary between **generic release auditing** and **game-specific authoring or runtime security**:

| Belongs in Release Guard (`awakekt/release-guard`) | Does NOT belong here — keep in your game / engine / private security module |
| --- | --- |
| Engine-agnostic open binary & format parsers (`.class`, `.dex`, AXML/Protobuf manifest, ELF, PE, Mach-O, WASM, SPIR-V, WGSL/GLSL, `bplist00`, `glTF`/FBX magic, TLS SPKI) | Game-authoring pipelines & content schemas (world/zone partitioning, character/item tables, scene graphs, sign-in asset sets, proprietary TOC/index layouts) |
| Generic configurable primitives (`forbiddenClasses`, `ownJarNames`, `ContainerHeaderRule`, `minContainerEntropy`, `forbidRawModelExtensions`, secret regex + entropy scans) | Runtime anti-cheat, RASP, Frida/debugger traps, root/jailbreak checks, or hardware attestation |
| Static build-time strippers (WASM debug sections, SPIR-V debug opcodes, `.map` removal, CSP `_headers` generation) | Asset encryption keys, key derivation, runtime decryption, or server-authoritative gameplay/economy checks |
| Pluggable `ReleaseGuardCheck` callback & `ServiceLoader` `ReleaseGuardCheckProvider` SPI | Reverse-proxy / server infrastructure config (Caddy, Nginx, Cloudflare Tunnel/WAF) |

### Writing game-specific authoring checks via callback / SPI

Put game-authoring rules (such as sign-in bundle budgets, encrypted world-key indexes, or proprietary
asset-pack checks) in your own project's `build-logic` or verification tool using `ReleaseGuardCheck`:

```kotlin
package com.example.game.buildlogic

import com.awakekt.releaseguard.analyzers.AnalyzerOutput
import com.awakekt.releaseguard.model.AuditFinding
import com.awakekt.releaseguard.model.AuditTarget
import com.awakekt.releaseguard.model.CheckSeverity
import com.awakekt.releaseguard.model.CheckStatus
import com.awakekt.releaseguard.spi.AuditContext
import com.awakekt.releaseguard.spi.ReleaseGuardCheck

class WorldKeyIndexCheck : ReleaseGuardCheck {
    override fun evaluate(context: AuditContext): AnalyzerOutput {
        val indexFile = context.assets?.assetDirectories?.firstOrNull()?.resolve("project.index.json")
        val ok = indexFile?.isFile == true && indexFile.readText().contains("\"keyId\"")
        return AnalyzerOutput(
            findings = listOf(
                AuditFinding(
                    checkId = "game.authoring.world_key_index",
                    target = AuditTarget.CUSTOM,
                    title = "Encrypted world-key index present",
                    status = if (ok) CheckStatus.PASS else CheckStatus.FAIL,
                    severity = CheckSeverity.HIGH,
                    weight = 15,
                    summary = if (ok) "Encrypted index carries keyId entries." else "Index is missing keyId entries.",
                    attackerLevel = "Rookie (CDN Scraper)",
                    plainEnglishImpact = "Without per-world keyId sealing, anyone can fetch locked-zone assets before earning access.",
                    remediation = "Seal play content with per-world encryption keys before publishing.",
                ),
            ),
        )
    }
}
```

Register it in Gradle (configuration-cache safe) via `customChecks`:

```kotlin
releaseGuard {
    customChecks {
        checkClasses.add("com.example.game.buildlogic.WorldKeyIndexCheck")
        parameters.put("maxSignInMb", "5")
    }
}
```

Or expose a `ReleaseGuardCheckProvider` via `META-INF/services/com.awakekt.releaseguard.spi.ReleaseGuardCheckProvider`
for zero-config auto-discovery on the build classpath. Every custom finding automatically joins the
weighted `0–100` score, `scorecard.html` dashboard, `scorecard.sarif` upload, baseline diff, and CI gate.

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
| **Assets & Shaders** | Unencrypted 3D model leaks (`.glb`, `.gltf`, `.fbx`, `.obj`, plus extensionless `glTF`/FBX binary magic sniffing), encrypted container headers (`.awkb` v2, custom `ContainerHeaderRule`, and Shannon payload entropy), Khronos SPIR-V (`.spv`) debug opcode auditing & lossless stripping (`OpSource`, `OpName`, `OpMemberName`, `OpLine`, `OpString`), and raw shader source / WGSL comment exposure. |
| **Custom Callbacks & SPI** | Pluggable `ReleaseGuardCheck` callbacks and `ServiceLoader` `ReleaseGuardCheckProvider` SPI so game-specific authoring checks (content indexes, per-world encryption keys, sign-in budgets) plug directly into the same `0–100` score, plain-English HTML dashboard, SARIF output, and CI gate. |
| **Supply Chain & Baselines** | Gradle `-SNAPSHOT` dependency gating, forbidden class shrinking checks (bytecode + `mapping.txt`), baseline regression diffing (`--baseline` / `--fail-on-regression`), and SARIF 2.1.0 output for GitHub Code Scanning. |

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
        forbiddenClasses.add("com.example.game.DebugCheatOverlay")
    }

    assets {
        enabled.set(true)
        directories.from(layout.buildDirectory.dir("release-assets"))
    }

    shaders {
        enabled.set(true)
        directories.from(layout.buildDirectory.dir("compiled-shaders"))
    }

    customChecks {
        checkClasses.add("com.example.buildlogic.MyAuthoringCheck")
        parameters.put("maxSignInMb", "5")
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

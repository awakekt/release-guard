/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard

import com.awakekt.releaseguard.analyzers.AndroidAuditInput
import com.awakekt.releaseguard.analyzers.IosAuditInput
import com.awakekt.releaseguard.analyzers.SupplyChainAuditInput
import com.awakekt.releaseguard.analyzers.TlsAuditInput
import com.awakekt.releaseguard.io.BinaryReadLimits
import com.awakekt.releaseguard.io.ZipReadBudget
import com.awakekt.releaseguard.model.AssetEncryptionPolicy
import com.awakekt.releaseguard.model.BaselinePolicy
import com.awakekt.releaseguard.model.CheckStatus
import com.awakekt.releaseguard.model.ReleaseGuardPolicy
import com.awakekt.releaseguard.report.HtmlReportRenderer
import com.awakekt.releaseguard.report.ReleaseGuardReportRenderer
import com.awakekt.releaseguard.report.SarifReportRenderer
import java.io.File
import java.nio.file.Files
import java.util.zip.ZipFile
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class Phase2BinaryInspectorsAndReportingTest {
    @Test
    fun androidApkDetectsExportedComponentsNetworkConfigElf16KbV1OnlyAndKotlinMetadata() {
        val root = Files.createTempDirectory("rg-android-p2-").toFile()
        try {
            val cleanApk = writeHardenedApkFixture(root.resolve("clean-release.apk"))
            val policy = ReleaseGuardPolicy(
                projectPackages = listOf("com.example.game"),
                minScore = 95,
                assetEncryption = AssetEncryptionPolicy(enabled = true),
            )
            val clean = ReleaseGuardAuditor.audit(ReleaseGuardRequest(policy = policy, android = AndroidAuditInput(cleanApk)))
            assertTrue(clean.passedGate, "Hardened v2 APK should pass: ${clean.gateReasons}")
            assertEquals(100, clean.overallScore)

            val badApk = writeDefectiveApkFixture(root.resolve("bad-release.apk"))
            val badPolicy = policy.copy(android = policy.android.copy(minTargetSdkVersion = 34))
            val bad = ReleaseGuardAuditor.audit(ReleaseGuardRequest(policy = badPolicy, android = AndroidAuditInput(badApk)))
            assertFalse(bad.passedGate)
            assertEquals(CheckStatus.WARN, bad.findings.first { it.checkId == "android.metadata.kotlin_metadata" }.status)
            assertEquals(CheckStatus.FAIL, bad.findings.first { it.checkId == "android.manifest.exported_components" }.status)
            assertEquals(CheckStatus.FAIL, bad.findings.first { it.checkId == "android.manifest.network_security_config" }.status)
            assertEquals(CheckStatus.FAIL, bad.findings.first { it.checkId == "android.manifest.test_only_and_sdk" }.status)
            assertEquals(CheckStatus.FAIL, bad.findings.first { it.checkId == "android.native.elf_hardening" }.status)
            assertEquals(CheckStatus.FAIL, bad.findings.first { it.checkId == "android.packaging.debug_artifacts" }.status)
        } finally {
            root.deleteRecursively()
        }
    }

    private fun writeHardenedApkFixture(target: File): File {
        val manifest = """
            <manifest package="com.example.game">
              <uses-sdk android:targetSdkVersion="35" />
              <application android:debuggable="false" android:allowBackup="false" android:usesCleartextTraffic="false">
                <activity android:name=".MainActivity" android:exported="true">
                  <intent-filter>
                    <action android:name="android.intent.action.MAIN" />
                    <category android:name="android.intent.category.LAUNCHER" />
                  </intent-filter>
                </activity>
              </application>
            </manifest>
        """.trimIndent().toByteArray(Charsets.UTF_8)
        val netCfg = """<network-security-config><base-config cleartextTrafficPermitted="false" /></network-security-config>""".toByteArray(Charsets.UTF_8)
        SyntheticFixtures.writeV2SignedApk(
            target,
            mapOf(
                "AndroidManifest.xml" to manifest,
                "classes.dex" to SyntheticFixtures.buildMinimalDexBytes(mapOf("a" to listOf("b", "c"))),
                "res/xml/network_security_config.xml" to netCfg,
                "lib/arm64-v8a/libengine.so" to SyntheticFixtures.buildMinimalElf64Bytes(loadAlignment = 16_384L),
                "assets/pack.awkb" to SyntheticFixtures.buildAwkbHeader(version = 2, encrypted = true),
            ),
        )
        return target
    }

    private fun writeDefectiveApkFixture(target: File): File {
        val manifest = """
            <manifest package="com.example.game">
              <uses-sdk android:targetSdkVersion="30" />
              <application android:debuggable="false" android:allowBackup="false" android:testOnly="true">
                <service android:name=".SyncService" android:exported="true" />
              </application>
            </manifest>
        """.trimIndent().toByteArray(Charsets.UTF_8)
        val netCfg = """<network-security-config><debug-overrides><trust-anchors><certificates src="user"/></trust-anchors></debug-overrides></network-security-config>""".toByteArray(Charsets.UTF_8)
        SyntheticFixtures.writeZip(
            target,
            mapOf(
                "AndroidManifest.xml" to manifest,
                "classes.dex" to SyntheticFixtures.buildMinimalDexBytes(mapOf("a" to listOf("b")), includeKotlinMetadata = true),
                "res/xml/network_security_config.xml" to netCfg,
                "lib/arm64-v8a/libengine.so" to SyntheticFixtures.buildMinimalElf64Bytes(
                    isPie = false,
                    loadAlignment = 4096L,
                    nxStack = false,
                    hasRelro = false,
                    hasBindNow = false,
                    hasDebugSection = true,
                ),
                "assets/.env" to "SECRET=1".toByteArray(Charsets.UTF_8),
            ),
        )
        return target
    }

    @Test
    fun androidAabParsesProtobufManifestDexAndNativeElf() {
        val root = Files.createTempDirectory("rg-aab-").toFile()
        try {
            val aab = root.resolve("app-release.aab")
            SyntheticFixtures.writeZip(
                aab,
                mapOf(
                    "base/manifest/AndroidManifest.xml" to SyntheticFixtures.buildProtobufManifest(
                        packageName = "com.example.game",
                        debuggable = true,
                        exportedServiceName = "com.example.game.InternalSyncService",
                    ),
                    "base/dex/classes.dex" to SyntheticFixtures.buildMinimalDexBytes(mapOf("a" to listOf("b"))),
                    "base/lib/arm64-v8a/libgame.so" to SyntheticFixtures.buildMinimalElf64Bytes(loadAlignment = 16_384L),
                ),
            )
            val result = ReleaseGuardAuditor.audit(
                ReleaseGuardRequest(
                    policy = ReleaseGuardPolicy(projectPackages = listOf("com.example.game")),
                    android = AndroidAuditInput(aab),
                ),
            )
            assertEquals("aab", result.metrics["android.artifactKind"])
            assertEquals("com.example.game", result.metrics["android.packageName"])
            assertEquals(CheckStatus.FAIL, result.findings.first { it.checkId == "android.manifest.debuggable" }.status)
            assertEquals(CheckStatus.FAIL, result.findings.first { it.checkId == "android.manifest.exported_components" }.status)
            assertEquals(CheckStatus.PASS, result.findings.first { it.checkId == "android.native.elf_hardening" }.status)
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun iosIpaParsesBinaryPlistProvisioningProfilePieAndPrivacyManifest() {
        val root = Files.createTempDirectory("rg-ios-ipa-").toFile()
        try {
            val cleanIpa = writeIpaFixture(root.resolve("GameRelease.ipa"), hardened = true)
            val policy = ReleaseGuardPolicy(ios = ReleaseGuardPolicy().ios.copy(requirePrivacyManifest = true))
            val clean = ReleaseGuardAuditor.audit(ReleaseGuardRequest(policy = policy, ios = IosAuditInput(cleanIpa)))
            assertTrue(clean.passedGate, "Clean IPA should pass: ${clean.gateReasons}")
            assertEquals(100, clean.overallScore)

            val badIpa = writeIpaFixture(root.resolve("GameDebug.ipa"), hardened = false)
            val bad = ReleaseGuardAuditor.audit(ReleaseGuardRequest(policy = policy, ios = IosAuditInput(badIpa)))
            assertFalse(bad.passedGate)
            assertEquals(CheckStatus.FAIL, bad.findings.first { it.checkId == "ios.macho.hardening" }.status)
            assertEquals(CheckStatus.WARN, bad.findings.first { it.checkId == "ios.macho.build_paths" }.status)
            assertEquals(CheckStatus.FAIL, bad.findings.first { it.checkId == "ios.plist.ats" }.status)
            assertEquals(CheckStatus.FAIL, bad.findings.first { it.checkId == "ios.ipa.provisioning" }.status)
            assertEquals(CheckStatus.WARN, bad.findings.first { it.checkId == "ios.plist.privacy_manifest" }.status)
        } finally {
            root.deleteRecursively()
        }
    }

    private fun writeIpaFixture(target: File, hardened: Boolean): File {
        val provision = if (hardened) {
            """<plist version="1.0"><dict><key>Entitlements</key><dict><key>get-task-allow</key><false/></dict></dict></plist>"""
        } else {
            """<plist version="1.0"><dict><key>Entitlements</key><dict><key>get-task-allow</key><true/></dict><key>ProvisionedDevices</key><array><string>UDID</string></array></dict></plist>"""
        }
        val entries = linkedMapOf(
            "Payload/Game.app/Game" to SyntheticFixtures.buildMinimalMachO64Bytes(
                isExecutable = true,
                isPie = hardened,
                hasCodeSignature = hardened,
                embeddedStrings = if (hardened) emptyList() else listOf("/Users/dev/project/GameMain.kt"),
            ),
            "Payload/Game.app/Info.plist" to SyntheticFixtures.buildBinaryAtsPlist(
                allowsArbitraryLoads = false,
                insecureExceptionDomain = if (hardened) null else "api.legacy-game.net",
            ),
            "Payload/Game.app/embedded.mobileprovision" to provision.toByteArray(Charsets.UTF_8),
        )
        if (hardened) entries["Payload/Game.app/PrivacyInfo.xcprivacy"] = "<plist/>".toByteArray(Charsets.UTF_8)
        SyntheticFixtures.writeZip(target, entries)
        return target
    }

    @Test
    fun baselineDiffSarifSupplyChainHighEntropyAndZipBudgetEnforceGates() {
        val root = Files.createTempDirectory("rg-cross-").toFile()
        try {
            // 1. High-entropy secret detection + SupplyChain -SNAPSHOT detection + TLS pins
            val pinA = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            val pinB = "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
            val baseline = ReleaseGuardAuditor.audit(
                ReleaseGuardRequest(
                    policy = ReleaseGuardPolicy(minScore = 90),
                    tls = TlsAuditInput("api.example.com=$pinA,$pinB"),
                    supplyChain = SupplyChainAuditInput(listOf("org.jetbrains.kotlin:kotlin-stdlib:2.4.20")),
                ),
            )
            assertEquals(100, baseline.overallScore)

            val regressed = ReleaseGuardAuditor.audit(
                ReleaseGuardRequest(
                    policy = ReleaseGuardPolicy(
                        minScore = 50,
                        failOnSeverity = null,
                        baseline = BaselinePolicy(failOnRegression = true, maxAllowedScoreDrop = 0),
                    ),
                    tls = TlsAuditInput("api.example.com=$pinA,$pinB"),
                    supplyChain = SupplyChainAuditInput(listOf("com.example:sdk:1.0.0-SNAPSHOT")),
                    baseline = baseline,
                ),
            )
            assertFalse(regressed.passedGate, "Baseline regression gate should fail when a -SNAPSHOT dependency is introduced.")
            val diff = assertNotNull(regressed.baselineDiff)
            assertTrue(diff.hasRegressions)
            assertTrue("supplychain.dependencies.snapshots" in diff.newFailures)

            // 2. Verify SARIF 2.1.0, HTML dashboard (with plain-English explanations & escaping), & Markdown
            val sarif = SarifReportRenderer.renderSarif(regressed)
            assertTrue("\"version\": \"2.1.0\"" in sarif)
            assertTrue("\"ruleId\": \"supplychain.dependencies.snapshots\"" in sarif)
            val md = ReleaseGuardReportRenderer.renderMarkdown(regressed)
            assertTrue("Release Hygiene & Obfuscation Score" in md)
            assertTrue("What an attacker sees" in md)
            assertTrue("Baseline Comparison" in md)
            val html = HtmlReportRenderer.renderHtml(regressed)
            assertTrue("<!DOCTYPE html>" in html)
            assertTrue("What an attacker can see / do" in html)
            assertTrue("mutable -SNAPSHOT dependencies" in html)
            assertTrue("Baseline comparison:" in html)

            // 3. Verify ZIP-bomb / bounded read protection rejects oversized archive entry
            val bigZip = root.resolve("oversized.zip")
            SyntheticFixtures.writeZip(bigZip, mapOf("bomb.bin" to ByteArray(4096)))
            assertFailsWith<IllegalArgumentException> {
                ZipFile(bigZip).use { zip ->
                    val budget = ZipReadBudget(BinaryReadLimits(maxZipEntryBytes = 512L, maxTotalZipBytes = 512L))
                    val entry = zip.getEntry("bomb.bin")
                    budget.recordEntry(entry.name)
                    budget.readEntryBytes(zip, entry)
                }
            }
        } finally {
            root.deleteRecursively()
        }
    }
}

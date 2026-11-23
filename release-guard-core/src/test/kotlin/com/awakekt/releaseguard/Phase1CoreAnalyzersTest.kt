/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard

import com.awakekt.releaseguard.analyzers.DesktopAuditInput
import com.awakekt.releaseguard.analyzers.WebAuditInput
import com.awakekt.releaseguard.analyzers.WebBundleStripper
import com.awakekt.releaseguard.model.AssetEncryptionPolicy
import com.awakekt.releaseguard.model.CheckStatus
import com.awakekt.releaseguard.model.ReleaseGuardPolicies
import com.awakekt.releaseguard.model.ReleaseGuardPolicy
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class Phase1CoreAnalyzersTest {
    @Test
    fun desktopAnalyzerDetectsKotlinMetadataNativePePdbJpackageDebugAndAwkbEncryption() {
        val root = Files.createTempDirectory("rg-desktop-p2-").toFile()
        try {
            val input = writeDesktopFixtures(root, hardened = true)
            val policy = ReleaseGuardPolicy(
                projectPackages = listOf("com.example.game"),
                minScore = 95,
                assetEncryption = AssetEncryptionPolicy(enabled = true),
            )
            val clean = ReleaseGuardAuditor.audit(ReleaseGuardRequest(policy = policy, desktop = input))
            assertTrue(clean.passedGate, "Clean desktop should pass: ${clean.gateReasons}")
            assertEquals(100, clean.overallScore)

            val leakyInput = writeDesktopFixtures(root, hardened = false)
            val leaky = ReleaseGuardAuditor.audit(ReleaseGuardRequest(policy = policy, desktop = leakyInput))
            assertFalse(leaky.passedGate)
            assertEquals(CheckStatus.WARN, leaky.findings.first { it.checkId == "desktop.metadata.debug_tables" }.status)
            assertEquals(CheckStatus.FAIL, leaky.findings.first { it.checkId == "desktop.native.hardening" }.status)
            assertEquals(CheckStatus.FAIL, leaky.findings.first { it.checkId == "desktop.jpackage.config" }.status)
            assertEquals(CheckStatus.FAIL, leaky.findings.first { it.checkId == "desktop.assets.encryption" }.status)
        } finally {
            root.deleteRecursively()
        }
    }

    private fun writeDesktopFixtures(root: File, hardened: Boolean): DesktopAuditInput {
        val jars = root.resolve("jars").apply { mkdirs() }
        val natives = root.resolve("natives").apply { mkdirs() }
        val jpkg = root.resolve("jpackage").apply { mkdirs() }
        val assets = root.resolve("assets").apply { mkdirs() }
        SyntheticFixtures.writeZip(
            jars.resolve("game.jar"),
            mapOf(
                "a.class" to SyntheticFixtures.buildMinimalClassBytes(
                    internalName = "a",
                    fieldNames = listOf("b"),
                    methodNames = listOf("c"),
                    sourceFile = "SourceFile",
                    includeKotlinMetadata = !hardened,
                    includeLocalVariableTable = !hardened,
                    includeMethodParameters = !hardened,
                ),
            ),
        )
        natives.resolve("engine.dll").writeBytes(
            SyntheticFixtures.buildMinimalPe64Bytes(
                hasAslr = hardened,
                hasDep = hardened,
                pdbPath = if (hardened) null else """C:\Users\dev\workspace\engine.pdb""",
            ),
        )
        jpkg.resolve("Game.cfg").writeText(
            if (hardened) "[JavaOptions]\njava-options=-Xmx2g\n" else "java-options=-agentlib:jdwp=transport=dt_socket,server=y\n",
            Charsets.UTF_8,
        )
        assets.resolve("world.awkb").writeBytes(
            SyntheticFixtures.buildAwkbHeader(version = if (hardened) 2 else 1, encrypted = hardened),
        )
        return DesktopAuditInput(
            gameJarsDirectory = jars,
            nativeLibsDirectory = natives,
            jpackageAppDirectory = jpkg,
            assetDirectory = assets,
        )
    }

    @Test
    fun webStripperAndAnalyzerCoverCssMapsCspQualitySriCleartextEndpointsAndSensitiveFiles() {
        val root = Files.createTempDirectory("rg-web-p2-").toFile()
        try {
            val rawDist = writeRawWebBundle(root.resolve("raw"))
            val hardened = root.resolve("hardened")
            val stripReport = WebBundleStripper.harden(rawDist, hardened)
            assertEquals(1, stripReport.droppedSourceMaps.size)
            assertEquals(1, stripReport.droppedSensitiveFiles.size)
            assertEquals(2, stripReport.cleanedSourceMapReferences.size)
            assertTrue(stripReport.wroteHeadersFile)
            assertFalse(hardened.resolve(".env").exists())

            val policy = ReleaseGuardPolicies.strictRelease(projectPackages = listOf("com.example.game"))
            val clean = ReleaseGuardAuditor.audit(ReleaseGuardRequest(policy = policy, web = WebAuditInput(hardened)))
            assertTrue(clean.passedGate, "Hardened web bundle should pass: ${clean.gateReasons}")
            assertEquals(100, clean.overallScore)

            injectWebVulnerabilities(hardened)
            val bad = ReleaseGuardAuditor.audit(ReleaseGuardRequest(policy = policy, web = WebAuditInput(hardened)))
            assertFalse(bad.passedGate)
            assertEquals(CheckStatus.FAIL, bad.findings.first { it.checkId == "web.headers.security" }.status)
            assertEquals(CheckStatus.FAIL, bad.findings.first { it.checkId == "web.html.sri" }.status)
            assertEquals(CheckStatus.FAIL, bad.findings.first { it.checkId == "web.runtime.insecure_endpoints" }.status)
            assertEquals(CheckStatus.FAIL, bad.findings.first { it.checkId == "web.packaging.sensitive_files" }.status)

            hardened.resolve("index.html").writeText(
                """<html><head><link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter" /></head></html>""",
                Charsets.UTF_8,
            )
            val fontWarn = ReleaseGuardAuditor.audit(ReleaseGuardRequest(policy = policy, web = WebAuditInput(hardened)))
            assertEquals(CheckStatus.WARN, fontWarn.findings.first { it.checkId == "web.html.sri" }.status)
            val allowPolicy = policy.copy(web = policy.web.copy(sriAllowlistHosts = setOf("fonts.googleapis.com")))
            val fontPass = ReleaseGuardAuditor.audit(ReleaseGuardRequest(policy = allowPolicy, web = WebAuditInput(hardened)))
            assertEquals(CheckStatus.PASS, fontPass.findings.first { it.checkId == "web.html.sri" }.status)
        } finally {
            root.deleteRecursively()
        }
    }

    private fun writeRawWebBundle(rawDist: File): File {
        rawDist.mkdirs()
        rawDist.resolve("index.html").writeText("""<html><head><script>window.boot=1;</script></head><body></body></html>""", Charsets.UTF_8)
        rawDist.resolve("app.css").writeText("body{margin:0}\n/*# sourceMappingURL=app.css.map */\n", Charsets.UTF_8)
        rawDist.resolve("app.css.map").writeText("{}", Charsets.UTF_8)
        rawDist.resolve(".env").writeText("DB_PASS=secret", Charsets.UTF_8)
        rawDist.resolve("a1b2c3d4e5f60718.js").writeText("const x=1;\n//# sourceMappingURL=app.js.map\n", Charsets.UTF_8)
        rawDist.resolve("a1b2c3d4e5f60718.wasm").writeBytes(
            SyntheticFixtures.buildMinimalWasmBytes(
                customSections = listOf("name" to "GameCombat".toByteArray(), "producers" to "kt".toByteArray()),
                exports = listOf("memory", "main"),
                dataStrings = listOf("ok", "a1", "b2", "c3"),
            ),
        )
        return rawDist
    }

    private fun injectWebVulnerabilities(hardened: File) {
        hardened.resolve("_headers").writeText(
            "/*\n  X-Content-Type-Options: nosniff\n  X-Frame-Options: DENY\n  Referrer-Policy: no-referrer\n" +
                "  Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' *\n",
            Charsets.UTF_8,
        )
        hardened.resolve("index.html").writeText("""<html><head><script src="https://cdn.example.net/lib.js"></script></head></html>""", Charsets.UTF_8)
        hardened.resolve("a1b2c3d4e5f60718.js").writeText("""const s = new WebSocket("ws://api.gameworld.net/live"); debugger;""", Charsets.UTF_8)
        hardened.resolve(".env.production").writeText("API_SECRET=topsecret", Charsets.UTF_8)
    }
}

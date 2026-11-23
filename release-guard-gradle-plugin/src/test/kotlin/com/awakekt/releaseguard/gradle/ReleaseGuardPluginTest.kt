/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.gradle

import org.gradle.testkit.runner.GradleRunner
import org.gradle.testkit.runner.TaskOutcome
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.File
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ReleaseGuardPluginTest {
    @Test
    fun proGuardRuleGeneratorProducesCuratedDesktopAndAndroidRules() {
        val cfg = ProGuardRuleConfig(
            mainClass = "com.example.game.desktop.MainKt",
            stripKotlinMetadata = true,
            extraRules = listOf("-dontwarn org.slf4j.**"),
        )
        val desktop = ProGuardRuleGenerator.generateDesktopRules(cfg)
        assertTrue("-dontoptimize" in desktop)
        assertTrue("-keep class com.example.game.desktop.MainKt" in desktop)
        assertTrue("-keep interface * extends com.sun.jna.Library" in desktop)
        assertTrue("kotlin.Metadata" in desktop)
        assertTrue("-dontwarn org.slf4j.**" in desktop)

        val android = ProGuardRuleGenerator.generateAndroidRules(cfg)
        assertFalse("-dontoptimize" in android)
        assertTrue("ModifierNodeElement" in android)
        assertTrue("android.util.Log" in android)
    }

    @Test
    fun gradlePluginExecutesFullWorkflowWithConfigurationCacheAndSarifOutput() {
        val projectDir = Files.createTempDirectory("rg-gradle-e2e-").toFile()
        try {
            prepareSampleProject(projectDir)

            val firstRun = GradleRunner.create()
                .withProjectDir(projectDir)
                .withPluginClasspath()
                .withArguments("generateReleaseGuardRules", "hardenWebBundle", "verifyReleaseGuard", "--configuration-cache", "--stacktrace")
                .build()
            assertEquals(TaskOutcome.SUCCESS, firstRun.task(":generateReleaseGuardRules")?.outcome)
            assertEquals(TaskOutcome.SUCCESS, firstRun.task(":hardenWebBundle")?.outcome)
            assertEquals(TaskOutcome.SUCCESS, firstRun.task(":verifyReleaseGuard")?.outcome)
            assertTrue("100/100 (A+) [PASS]" in firstRun.output, firstRun.output)

            val sarifReport = projectDir.resolve("build/reports/release-guard/scorecard.sarif")
            assertTrue(projectDir.resolve("build/reports/release-guard/scorecard.json").isFile)
            assertTrue(projectDir.resolve("build/reports/release-guard/scorecard.md").isFile)
            assertTrue(sarifReport.isFile && "\"version\": \"2.1.0\"" in sarifReport.readText())
            assertFalse(projectDir.resolve("build/release-guard/web-hardened/a1b2c3d4e5f60718.js.map").exists())

            val secondRun = GradleRunner.create()
                .withProjectDir(projectDir)
                .withPluginClasspath()
                .withArguments("generateReleaseGuardRules", "hardenWebBundle", "verifyReleaseGuard", "--configuration-cache")
                .build()
            assertTrue(secondRun.output.contains("Configuration cache entry reused."), secondRun.output)
            assertEquals(TaskOutcome.UP_TO_DATE, secondRun.task(":generateReleaseGuardRules")?.outcome)
            assertEquals(TaskOutcome.UP_TO_DATE, secondRun.task(":hardenWebBundle")?.outcome)
            assertEquals(TaskOutcome.SUCCESS, secondRun.task(":verifyReleaseGuard")?.outcome)

            projectDir.resolve("build/release-guard/web-hardened/.env").writeText("API_KEY=leaked", Charsets.UTF_8)
            val failedRun = GradleRunner.create()
                .withProjectDir(projectDir)
                .withPluginClasspath()
                .withArguments("verifyReleaseGuard", "--configuration-cache")
                .buildAndFail()
            assertTrue("web.packaging.sensitive_files" in failedRun.output, failedRun.output)
        } finally {
            projectDir.deleteRecursively()
        }
    }

    private fun prepareSampleProject(projectDir: File) {
        val gameJarsDir = projectDir.resolve("fixtures/desktop-jars").apply { mkdirs() }
        writeMinimalJar(gameJarsDir.resolve("game.jar"), "a", listOf("b"), "SourceFile")

        val rawWebDir = projectDir.resolve("fixtures/web-raw").apply { mkdirs() }
        rawWebDir.resolve("index.html").writeText("<html><body><script>window.ok=1;</script></body></html>", Charsets.UTF_8)
        rawWebDir.resolve("a1b2c3d4e5f60718.js").writeText("const a=1;\n//# sourceMappingURL=a.js.map\n", Charsets.UTF_8)
        rawWebDir.resolve("a1b2c3d4e5f60718.js.map").writeText("{}", Charsets.UTF_8)
        rawWebDir.resolve("a1b2c3d4e5f60718.wasm").writeBytes(buildMinimalWasmWithDebugSection())

        projectDir.resolve("settings.gradle.kts").writeText("rootProject.name = \"sample-game\"\n", Charsets.UTF_8)
        val pinA = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        val pinB = "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
        projectDir.resolve("build.gradle.kts").writeText(
            """
            plugins { id("com.awakekt.release-guard") }
            releaseGuard {
                projectPackages.add("com.example.game")
                minScore.set(95)
                failOnSeverity.set("HIGH")
                rules { mainClass.set("com.example.game.desktop.MainKt"); stripKotlinMetadata.set(true) }
                desktop { enabled.set(true); gameJarsDir.set(layout.projectDirectory.dir("fixtures/desktop-jars")); verifyBytecode.set(false) }
                web { enabled.set(true); inputDir.set(layout.projectDirectory.dir("fixtures/web-raw")) }
                tls { enabled.set(true); spkiPins.set("api.example.com=$pinA,$pinB") }
            }
            """.trimIndent() + "\n",
            Charsets.UTF_8,
        )
    }

    private fun writeMinimalJar(target: File, internalName: String, methods: List<String>, sourceFile: String) {
        val pool = mutableListOf<ByteArray>()
        fun addUtf8(s: String): Int {
            val b = s.toByteArray(Charsets.UTF_8)
            val e = ByteArrayOutputStream()
            DataOutputStream(e).use { d -> d.writeByte(1); d.writeShort(b.size); d.write(b) }
            pool += e.toByteArray()
            return pool.size
        }
        fun addClass(idx: Int): Int {
            val e = ByteArrayOutputStream()
            DataOutputStream(e).use { d -> d.writeByte(7); d.writeShort(idx) }
            pool += e.toByteArray()
            return pool.size
        }
        val thisIdx = addClass(addUtf8(internalName))
        val superIdx = addClass(addUtf8("java/lang/Object"))
        val descIdx = addUtf8("()V")
        val mIdxs = methods.map(::addUtf8)
        val sfName = addUtf8("SourceFile")
        val sfVal = addUtf8(sourceFile)
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { d ->
            d.writeInt(0xCAFEBABE.toInt()); d.writeShort(0); d.writeShort(52)
            d.writeShort(pool.size + 1); pool.forEach(d::write)
            d.writeShort(0x0021); d.writeShort(thisIdx); d.writeShort(superIdx)
            d.writeShort(0); d.writeShort(0)
            d.writeShort(mIdxs.size)
            mIdxs.forEach { m -> d.writeShort(0x0001); d.writeShort(m); d.writeShort(descIdx); d.writeShort(0) }
            d.writeShort(1); d.writeShort(sfName); d.writeInt(2); d.writeShort(sfVal)
        }
        ZipOutputStream(target.outputStream()).use { zos ->
            zos.putNextEntry(ZipEntry("$internalName.class"))
            zos.write(out.toByteArray())
            zos.closeEntry()
        }
    }

    private fun buildMinimalWasmWithDebugSection(): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(byteArrayOf(0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00))
        val data = "a1\u0000b2\u0000c3".toByteArray(Charsets.UTF_8)
        out.write(11); out.write(data.size); out.write(data)
        val nameSec = byteArrayOf(4, 'n'.code.toByte(), 'a'.code.toByte(), 'm'.code.toByte(), 'e'.code.toByte(), 1, 2)
        out.write(0); out.write(nameSec.size); out.write(nameSec)
        return out.toByteArray()
    }
}

/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.cli

import com.awakekt.releaseguard.analyzers.SecretScanner
import com.awakekt.releaseguard.model.SecretScanPolicy
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ReleaseGuardCliTest {
    @Test
    fun cliInitPolicyAuditBaselineAndSarifWorkEndToEnd() {
        val root = Files.createTempDirectory("rg-cli-test-").toFile()
        try {
            val policyFile = root.resolve("policy.json")
            assertEquals(0, runCli("init-policy", "--preset", "balanced", "--project-package", "com.example.game", "--output", policyFile.absolutePath).first)
            assertTrue(policyFile.isFile)

            val pinA = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            val pinB = "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
            val baselineJson = root.resolve("baseline.json")
            val sarifOut = root.resolve("report.sarif")
            val mdOut = root.resolve("report.md")
            val htmlOut = root.resolve("report.html")

            val (passCode, passOut) = runCli(
                "audit", "--config", policyFile.absolutePath, "--tls-pins", "api.example.com=$pinA,$pinB",
                "--json-out", baselineJson.absolutePath, "--markdown-out", mdOut.absolutePath,
                "--sarif-out", sarifOut.absolutePath, "--html-out", htmlOut.absolutePath,
            )
            assertEquals(0, passCode, passOut)
            assertTrue(baselineJson.isFile && mdOut.isFile && sarifOut.isFile && htmlOut.isFile)
            assertTrue("\"version\": \"2.1.0\"" in sarifOut.readText())
            assertTrue("Release Guard - Static Release Hygiene" in htmlOut.readText())

            val (failCode, failOut) = runCli(
                "audit",
                "--preset",
                "dev",
                "--tls-pins",
                "api.example.com=$pinA",
                "--baseline",
                baselineJson.absolutePath,
                "--fail-on-regression",
            )
            assertEquals(1, failCode, failOut)
            assertTrue("Baseline diff:" in failOut)
        } finally {
            root.deleteRecursively()
        }
    }

    private fun runCli(vararg args: String): Pair<Int, String> {
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val code = ReleaseGuardCli.execute(arrayOf(*args), PrintStream(out), PrintStream(err))
        return code to (out.toString() + "\n" + err.toString())
    }

    @Test
    fun highEntropySecretScannerCatchesUnknownHighEntropyApiKeys() {
        val matches = SecretScanner.scanSecrets(
            location = "config.js",
            texts = listOf("""const api_key = "k9X2mP7vQ4rT8nL1zW6bY3cF5hJ0sD9aE2uG";"""),
            policy = SecretScanPolicy(enabled = true, enableHighEntropyScan = true, minEntropyThreshold = 4.5),
        )
        assertTrue(matches.any { it.ruleName == "high_entropy_secret" }, "Expected high-entropy token match, got $matches")
    }
}

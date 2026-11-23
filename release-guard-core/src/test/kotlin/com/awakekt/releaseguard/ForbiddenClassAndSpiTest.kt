/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard

import com.awakekt.releaseguard.analyzers.AnalyzerOutput
import com.awakekt.releaseguard.analyzers.ForbiddenClassInspector
import com.awakekt.releaseguard.model.AuditFinding
import com.awakekt.releaseguard.model.AuditTarget
import com.awakekt.releaseguard.model.CheckSeverity
import com.awakekt.releaseguard.model.CheckStatus
import com.awakekt.releaseguard.model.ReleaseGuardPolicy
import com.awakekt.releaseguard.report.HtmlReportRenderer
import com.awakekt.releaseguard.report.ReleaseGuardReportRenderer
import com.awakekt.releaseguard.spi.AuditContext
import com.awakekt.releaseguard.spi.ReleaseGuardCheck
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

public class SampleAuthoringCheck : ReleaseGuardCheck {
    override fun evaluate(context: AuditContext): AnalyzerOutput {
        val expected = context.customParameters["expectedKeyId"] ?: "missing"
        return AnalyzerOutput(
            findings = listOf(
                AuditFinding(
                    checkId = "game.authoring.world_key",
                    target = AuditTarget.CUSTOM,
                    title = "Custom world key check",
                    status = if (expected == "world-1") CheckStatus.PASS else CheckStatus.FAIL,
                    severity = CheckSeverity.HIGH,
                    weight = 15,
                    summary = "Checked custom world keyId=$expected.",
                    attackerLevel = "Intermediate (Content Ripper)",
                    plainEnglishImpact = "Missing world key partitioning lets signed-in players decrypt locked zones early.",
                    remediation = "Assign per-world keys during content bundling.",
                ),
            ),
            metrics = mapOf("custom.worldKeyId" to expected),
        )
    }
}

class ForbiddenClassAndSpiTest {
    @Test
    fun forbiddenClassInspectorCatchesBothBytecodeAndObfuscatedMappingEntries() {
        val tempDir = Files.createTempDirectory("rg-forbid").toFile()
        try {
            val mapping = File(tempDir, "mapping.txt").apply {
                writeText(
                    """
                    com.example.game.OfflineSim -> a.b:
                        1:10:void tick() -> a
                    com.example.game.MainKt -> com.example.game.MainKt:
                    """.trimIndent(),
                )
            }
            val failed = ForbiddenClassInspector.check(
                checkId = "desktop.obfuscation.forbidden_classes",
                target = AuditTarget.DESKTOP_JVM,
                compiledInternalNames = listOf("a/b", "com/example/game/MainKt"),
                mappingFile = mapping,
                forbiddenClasses = listOf("com.example.game.OfflineSim"),
            )
            assertEquals(CheckStatus.FAIL, failed.status)
            assertTrue(failed.evidence.any { it.contains("mapping:com.example.game.OfflineSim -> a.b") })

            val passed = ForbiddenClassInspector.check(
                checkId = "desktop.obfuscation.forbidden_classes",
                target = AuditTarget.DESKTOP_JVM,
                compiledInternalNames = listOf("com/example/game/MainKt"),
                mappingFile = mapping,
                forbiddenClasses = listOf("com.example.game.DebugCheatMenu"),
            )
            assertEquals(CheckStatus.PASS, passed.status)
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun pluggableCallbacksAndClassNameChecksIntegrateIntoScorecardAndHtml() {
        val lambdaCheck = ReleaseGuardCheck.findingsOnly {
            listOf(
                AuditFinding(
                    checkId = "game.authoring.signin_budget",
                    target = AuditTarget.CUSTOM,
                    title = "Sign-in bundle size budget",
                    status = CheckStatus.PASS,
                    severity = CheckSeverity.MEDIUM,
                    weight = 10,
                    summary = "Sign-in set is under 5 MB budget.",
                ),
            )
        }
        val failingCard = ReleaseGuardAuditor.audit(
            ReleaseGuardRequest(
                policy = ReleaseGuardPolicy(minScore = 80),
                customChecks = listOf(lambdaCheck),
                customCheckClassNames = listOf(SampleAuthoringCheck::class.java.name),
                loadServiceProviderChecks = false,
                customParameters = mapOf("expectedKeyId" to "wrong"),
            ),
        )
        assertFalse(failingCard.passedGate)
        assertEquals("wrong", failingCard.metrics["custom.worldKeyId"])
        val html = HtmlReportRenderer.renderHtml(failingCard)
        val md = ReleaseGuardReportRenderer.renderMarkdown(failingCard)
        assertTrue(html.contains("Intermediate (Content Ripper)"))
        assertTrue(html.contains("decrypt locked zones early"))
        assertTrue(md.contains("Intermediate (Content Ripper)"))

        val passingCard = ReleaseGuardAuditor.audit(
            ReleaseGuardRequest(
                policy = ReleaseGuardPolicy(minScore = 80),
                customChecks = listOf(lambdaCheck),
                customCheckClassNames = listOf(SampleAuthoringCheck::class.java.name),
                loadServiceProviderChecks = false,
                customParameters = mapOf("expectedKeyId" to "world-1"),
            ),
        )
        assertTrue(passingCard.passedGate)
        assertEquals(100, passingCard.overallScore)
    }

    @Test
    fun throwingCustomCheckIsIsolatedIntoFailureFinding() {
        val throwingCheck = ReleaseGuardCheck { error("simulated callback crash") }
        val card = ReleaseGuardAuditor.audit(
            ReleaseGuardRequest(
                policy = ReleaseGuardPolicy(minScore = 80),
                customChecks = listOf(throwingCheck),
                loadServiceProviderChecks = false,
            ),
        )
        assertFalse(card.passedGate)
        assertTrue(card.findings.any { it.checkId == "custom.check.execution_error" && it.status == CheckStatus.FAIL })
    }
}

/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.report

import com.awakekt.releaseguard.model.AuditFinding
import com.awakekt.releaseguard.model.BaselineDiff
import com.awakekt.releaseguard.model.CheckStatus
import com.awakekt.releaseguard.model.ReleaseScorecard
import kotlinx.serialization.json.Json

/**
 * Formats a [ReleaseScorecard] for terminal logs, CI Markdown summaries, or machine-readable JSON
 * artifacts.
 */
public object ReleaseGuardReportRenderer {
    private val json: Json = Json {
        prettyPrint = true
        encodeDefaults = true
        ignoreUnknownKeys = true
    }

    /** Serializes [scorecard] as pretty-printed JSON. */
    public fun renderJson(scorecard: ReleaseScorecard): String =
        json.encodeToString(ReleaseScorecard.serializer(), scorecard) + "\n"

    /** Deserializes a previously exported baseline [ReleaseScorecard] from JSON [content]. */
    public fun parseJson(content: String): ReleaseScorecard =
        json.decodeFromString(ReleaseScorecard.serializer(), content)

    /** Formats [scorecard] as a concise human-readable console report. */
    public fun renderConsole(scorecard: ReleaseScorecard): String = buildString {
        val gateLabel = if (scorecard.passedGate) "PASS" else "FAIL"
        appendLine("================================================================")
        appendLine("Release Guard - Release Hygiene & Obfuscation Score: ${scorecard.overallScore}/100 (${scorecard.grade.label}) [$gateLabel]")
        appendLine("Note: Static deterrence & packaging audit only; does not replace server authority or runtime RASP.")
        appendLine("================================================================")
        if (scorecard.targets.isEmpty()) {
            appendLine("No targets were audited.")
        } else {
            for (target in scorecard.targets) {
                appendLine(
                    "  ${target.target.displayName}: ${target.score}/100 (${target.grade.label}) " +
                        "[pass=${target.passedChecks}, warn=${target.warnedChecks}, fail=${target.failedChecks}, skip=${target.skippedChecks}]",
                )
            }
        }
        scorecard.baselineDiff?.let { appendConsoleBaseline(this, it) }
        appendLine()
        for (finding in scorecard.findings) {
            appendConsoleFinding(this, finding)
        }
        if (scorecard.metrics.isNotEmpty()) {
            appendLine("Metrics:")
            for ((key, value) in scorecard.metrics) {
                appendLine("  $key = $value")
            }
        }
        if (scorecard.gateReasons.isNotEmpty()) {
            appendLine()
            appendLine("Gate failures:")
            for (reason in scorecard.gateReasons) {
                appendLine("  - $reason")
            }
        }
    }

    /** Formats [scorecard] as GitHub-flavored Markdown suitable for PR comments or step summaries. */
    public fun renderMarkdown(scorecard: ReleaseScorecard): String = buildString {
        val gateBadge = if (scorecard.passedGate) "PASS" else "FAIL"
        appendLine("## Release Guard — Release Hygiene & Obfuscation Score: ${scorecard.overallScore}/100 (${scorecard.grade.label}) - $gateBadge")
        appendLine()
        appendLine("> Static obfuscation, binary hardening, and packaging hygiene audit. Never replaces server-authoritative validation or runtime RASP.")
        appendLine()
        if (scorecard.targets.isNotEmpty()) {
            appendLine("| Target | Score | Grade | Pass | Warn | Fail | Skip |")
            appendLine("| --- | ---: | :---: | ---: | ---: | ---: | ---: |")
            for (target in scorecard.targets) {
                appendLine(
                    "| ${target.target.displayName} | ${target.score}/100 | ${target.grade.label} | " +
                        "${target.passedChecks} | ${target.warnedChecks} | ${target.failedChecks} | ${target.skippedChecks} |",
                )
            }
            appendLine()
        }
        scorecard.baselineDiff?.let { appendMarkdownBaseline(this, it) }
        appendLine("### Findings")
        appendLine()
        appendLine("| Status | Severity | Check | Summary |")
        appendLine("| :---: | :---: | --- | --- |")
        for (finding in scorecard.findings) {
            val cleanSummary = finding.summary.replace("|", "\\|").replace("\n", " ")
            appendLine("| ${finding.status} | ${finding.severity} | `${finding.checkId}` | $cleanSummary |")
        }
        appendMarkdownRemediation(this, scorecard)
    }

    private fun appendConsoleFinding(out: StringBuilder, finding: AuditFinding) {
        out.appendLine("[${finding.status}] (${finding.severity}, w=${finding.weight}) ${finding.checkId}: ${finding.summary}")
        if (finding.evidence.isNotEmpty() && finding.status != CheckStatus.PASS) {
            out.appendLine("       evidence: ${finding.evidence.take(8).joinToString(", ")}")
        }
        if (finding.remediation.isNotBlank() && finding.status != CheckStatus.PASS && finding.status != CheckStatus.SKIP) {
            out.appendLine("       fix: ${finding.remediation}")
        }
    }

    private fun appendConsoleBaseline(out: StringBuilder, diff: BaselineDiff) {
        val sign = if (diff.scoreDelta >= 0) "+" else ""
        out.appendLine("Baseline diff: ${diff.baselineScore} -> ${diff.currentScore} ($sign${diff.scoreDelta}), regressions=${diff.hasRegressions}")
        if (diff.newFailures.isNotEmpty()) out.appendLine("  new failures: ${diff.newFailures.joinToString()}")
        if (diff.statusRegressions.isNotEmpty()) out.appendLine("  regressions: ${diff.statusRegressions.joinToString()}")
        if (diff.resolvedFailures.isNotEmpty()) out.appendLine("  resolved: ${diff.resolvedFailures.joinToString()}")
    }

    private fun appendMarkdownBaseline(out: StringBuilder, diff: BaselineDiff) {
        val sign = if (diff.scoreDelta >= 0) "+" else ""
        out.appendLine("### Baseline Comparison")
        out.appendLine()
        out.appendLine("- **Score delta:** `${diff.baselineScore}` -> `${diff.currentScore}` (`$sign${diff.scoreDelta}`)")
        if (diff.newFailures.isNotEmpty()) out.appendLine("- **New failures:** ${diff.newFailures.joinToString(", ") { "`$it`" }}")
        if (diff.statusRegressions.isNotEmpty()) out.appendLine("- **Status regressions:** ${diff.statusRegressions.joinToString(", ") { "`$it`" }}")
        if (diff.resolvedFailures.isNotEmpty()) out.appendLine("- **Resolved failures:** ${diff.resolvedFailures.joinToString(", ") { "`$it`" }}")
        out.appendLine()
    }

    private fun appendMarkdownRemediation(out: StringBuilder, scorecard: ReleaseScorecard) {
        val actionable = scorecard.findings.filter { it.status == CheckStatus.FAIL || it.status == CheckStatus.WARN }
        if (actionable.isNotEmpty()) {
            out.appendLine()
            out.appendLine("### Actionable Remediation")
            out.appendLine()
            for (finding in actionable) {
                out.appendLine("- **`${finding.checkId}`** (${finding.status}, ${finding.severity}): ${finding.summary}")
                if (finding.evidence.isNotEmpty()) {
                    out.appendLine("  - Evidence: ${finding.evidence.take(5).joinToString(", ") { "`$it`" }}")
                }
                if (finding.remediation.isNotBlank()) {
                    out.appendLine("  - Fix: ${finding.remediation}")
                }
            }
        }
        if (scorecard.gateReasons.isNotEmpty()) {
            out.appendLine()
            out.appendLine("### Gate Failures")
            out.appendLine()
            for (reason in scorecard.gateReasons) {
                out.appendLine("- $reason")
            }
        }
    }
}

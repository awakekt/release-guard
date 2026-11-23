/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.report

import com.awakekt.releaseguard.model.AuditFinding
import com.awakekt.releaseguard.model.BaselineDiff
import com.awakekt.releaseguard.model.CheckStatus
import com.awakekt.releaseguard.model.ReleaseGrade
import com.awakekt.releaseguard.model.ReleaseGuardPolicy
import com.awakekt.releaseguard.model.ReleaseScorecard
import com.awakekt.releaseguard.model.TargetScorecard
import kotlin.math.roundToInt

/**
 * Computes weighted 0-to-100 release hygiene & obfuscation scores, letter grades, baseline
 * regression diffs, and CI gate decisions from raw check findings.
 *
 * Scoring formula per non-skipped check:
 * - [CheckStatus.PASS] earns 100% of its weight.
 * - [CheckStatus.WARN] earns 50% of its weight.
 * - [CheckStatus.FAIL] earns 0% of its weight.
 * - [CheckStatus.SKIP] is excluded from both numerator and denominator.
 */
public object ReleaseGuardScorer {
    /** Evaluates [rawFindings] under [policy], optionally comparing against [baseline]. */
    public fun score(
        rawFindings: List<AuditFinding>,
        policy: ReleaseGuardPolicy,
        metrics: Map<String, String> = emptyMap(),
        baseline: ReleaseScorecard? = null,
    ): ReleaseScorecard {
        val findings = rawFindings.map { finding -> applyPolicyOverrides(finding, policy) }
        val targetScorecards = findings
            .groupBy { it.target }
            .entries
            .sortedBy { it.key.ordinal }
            .map { (target, targetFindings) ->
                val targetScore = computeWeightedScore(targetFindings)
                TargetScorecard(
                    target = target,
                    score = targetScore,
                    grade = ReleaseGrade.fromScore(targetScore),
                    passedChecks = targetFindings.count { it.status == CheckStatus.PASS },
                    warnedChecks = targetFindings.count { it.status == CheckStatus.WARN },
                    failedChecks = targetFindings.count { it.status == CheckStatus.FAIL },
                    skippedChecks = targetFindings.count { it.status == CheckStatus.SKIP },
                    findings = targetFindings,
                )
            }

        val overallScore = computeWeightedScore(findings)
        val diff = baseline?.let { computeBaselineDiff(overallScore, findings, it, policy) }
        val gateReasons = evaluateGate(overallScore, findings, policy, diff)
        return ReleaseScorecard(
            overallScore = overallScore,
            grade = ReleaseGrade.fromScore(overallScore),
            passedGate = gateReasons.isEmpty(),
            gateReasons = gateReasons,
            targets = targetScorecards,
            findings = findings,
            metrics = metrics.toSortedMap(),
            baselineDiff = diff,
        )
    }

    /** Computes a [BaselineDiff] between [currentFindings]/[currentScore] and a previous [baseline] scorecard. */
    public fun computeBaselineDiff(
        currentScore: Int,
        currentFindings: List<AuditFinding>,
        baseline: ReleaseScorecard,
        policy: ReleaseGuardPolicy = ReleaseGuardPolicy(),
    ): BaselineDiff {
        val prevById = baseline.findings.associateBy { it.checkId }
        val currById = currentFindings.associateBy { it.checkId }

        val newFailures = mutableListOf<String>()
        val resolvedFailures = mutableListOf<String>()
        val statusRegressions = mutableListOf<String>()

        for ((id, curr) in currById) {
            val prev = prevById[id]
            if (curr.status == CheckStatus.FAIL && prev?.status != CheckStatus.FAIL) {
                newFailures += id
            }
            if (prev != null && curr.status.severityRank > prev.status.severityRank && prev.status != CheckStatus.SKIP) {
                statusRegressions += "$id (${prev.status} -> ${curr.status})"
            }
        }
        for ((id, prev) in prevById) {
            val curr = currById[id]
            if (prev.status == CheckStatus.FAIL && curr != null && curr.status != CheckStatus.FAIL) {
                resolvedFailures += id
            }
        }
        val delta = currentScore - baseline.overallScore
        val scoreDroppedBeyondLimit = delta < -policy.baseline.maxAllowedScoreDrop.coerceAtLeast(0)
        val hasRegressions = scoreDroppedBeyondLimit || newFailures.isNotEmpty() || statusRegressions.isNotEmpty()
        return BaselineDiff(
            baselineScore = baseline.overallScore,
            currentScore = currentScore,
            scoreDelta = delta,
            newFailures = newFailures.sorted(),
            resolvedFailures = resolvedFailures.sorted(),
            statusRegressions = statusRegressions.sorted(),
            hasRegressions = hasRegressions,
        )
    }

    private fun applyPolicyOverrides(finding: AuditFinding, policy: ReleaseGuardPolicy): AuditFinding {
        val overriddenSeverity = policy.severityOverrides[finding.checkId] ?: finding.severity
        val overriddenWeight = (policy.weightOverrides[finding.checkId] ?: finding.weight).coerceAtLeast(0)
        val suppressed = finding.checkId in policy.disabledChecks
        return finding.copy(
            status = if (suppressed) CheckStatus.SKIP else finding.status,
            severity = overriddenSeverity,
            weight = overriddenWeight,
            summary = if (suppressed) "Suppressed by policy (${finding.checkId})." else finding.summary,
        )
    }

    private fun computeWeightedScore(findings: List<AuditFinding>): Int {
        var totalWeight = 0.0
        var earnedWeight = 0.0
        for (finding in findings) {
            if (finding.status == CheckStatus.SKIP || finding.weight <= 0) continue
            totalWeight += finding.weight
            earnedWeight += when (finding.status) {
                CheckStatus.PASS -> finding.weight.toDouble()
                CheckStatus.WARN -> finding.weight * 0.5
                CheckStatus.FAIL -> 0.0
                CheckStatus.SKIP -> 0.0
            }
        }
        if (totalWeight <= 0.0) return 100
        return ((earnedWeight / totalWeight) * 100.0).roundToInt().coerceIn(0, 100)
    }

    private fun evaluateGate(
        overallScore: Int,
        findings: List<AuditFinding>,
        policy: ReleaseGuardPolicy,
        diff: BaselineDiff?,
    ): List<String> = buildList {
        if (overallScore < policy.minScore) {
            add("Overall release hygiene score $overallScore is below minimum threshold ${policy.minScore}.")
        }
        val threshold = policy.failOnSeverity
        if (threshold != null) {
            findings
                .filter { it.status == CheckStatus.FAIL && it.severity.rank >= threshold.rank }
                .forEach { finding ->
                    add("[${finding.severity}] ${finding.checkId}: ${finding.summary}")
                }
        }
        if (policy.baseline.failOnRegression && diff != null && diff.hasRegressions) {
            add(
                "Baseline regression detected (delta=${diff.scoreDelta}, " +
                    "newFailures=${diff.newFailures.size}, regressions=${diff.statusRegressions.size}).",
            )
        }
    }
}

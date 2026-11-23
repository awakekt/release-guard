/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.analyzers

import com.awakekt.releaseguard.model.AuditFinding
import com.awakekt.releaseguard.model.AuditTarget
import com.awakekt.releaseguard.model.CheckSeverity
import com.awakekt.releaseguard.model.CheckStatus
import com.awakekt.releaseguard.model.ReleaseGuardPolicy

/** Inputs for build supply-chain hygiene checks (for example resolved Gradle dependency coordinates). */
public data class SupplyChainAuditInput(
    public val resolvedDependencies: List<String> = emptyList(),
)

/** Audits build dependency coordinates for non-reproducible `-SNAPSHOT` versions in release builds. */
public object SupplyChainAnalyzer {
    /** Evaluates [input] under [policy]. */
    public fun analyze(input: SupplyChainAuditInput, policy: ReleaseGuardPolicy): AnalyzerOutput {
        if (!policy.supplyChain.forbidSnapshotDependencies) {
            return AnalyzerOutput(
                findings = listOf(
                    AuditFinding(
                        checkId = "supplychain.dependencies.snapshots",
                        target = AuditTarget.SUPPLY_CHAIN,
                        title = "No -SNAPSHOT dependencies in release",
                        status = CheckStatus.SKIP,
                        severity = CheckSeverity.HIGH,
                        weight = 15,
                        summary = "Snapshot dependency check disabled by policy.",
                    ),
                ),
            )
        }
        val snapshots = input.resolvedDependencies
            .filter { it.contains("-SNAPSHOT", ignoreCase = true) }
            .distinct()
            .sorted()
        val passed = snapshots.isEmpty()
        return AnalyzerOutput(
            findings = listOf(
                AuditFinding(
                    checkId = "supplychain.dependencies.snapshots",
                    target = AuditTarget.SUPPLY_CHAIN,
                    title = "No -SNAPSHOT dependencies in release",
                    status = if (passed) CheckStatus.PASS else CheckStatus.FAIL,
                    severity = CheckSeverity.HIGH,
                    weight = 15,
                    summary = if (passed) {
                        "Verified ${input.resolvedDependencies.size} resolved dependency(s) with 0 -SNAPSHOT versions."
                    } else {
                        "Found ${snapshots.size} mutable -SNAPSHOT dependency(s) in release build."
                    },
                    evidence = snapshots.take(10),
                    remediation = "Pin every release dependency to an immutable version before publishing.",
                ),
            ),
            metrics = mapOf(
                "supplychain.dependencyCount" to input.resolvedDependencies.size.toString(),
                "supplychain.snapshotCount" to snapshots.size.toString(),
            ),
        )
    }
}

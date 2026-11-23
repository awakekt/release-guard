/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.model

import kotlinx.serialization.Serializable

/** Platform or artifact surface inspected during a Release Guard audit. */
@Serializable
public enum class AuditTarget(public val displayName: String) {
    /** Desktop JVM JARs, native desktop libraries, and packaged launcher configs. */
    DESKTOP_JVM("Desktop JVM"),

    /** Android release APK or Android App Bundle (AAB). */
    ANDROID("Android (APK/AAB)"),

    /** Kotlin/Wasm and JavaScript web distribution. */
    WEB_WASM("Web (WASM/JS)"),

    /** iOS `.framework`, `.xcframework`, `.ipa`, or standalone Mach-O binary. */
    IOS("iOS (Framework/IPA)"),

    /** TLS SPKI pinning configuration and optional live endpoint verification. */
    TRANSPORT_TLS("Transport TLS"),

    /** Build supply-chain and dependency hygiene checks (such as `-SNAPSHOT` gating). */
    SUPPLY_CHAIN("Supply Chain"),

    /** Packaged 3D models, encrypted content containers, and SPIR-V / WGSL shaders. */
    ASSETS_AND_SHADERS("Assets & Shaders"),

    /** Game- or organization-specific checks contributed via `ReleaseGuardCheck` callbacks or SPI. */
    CUSTOM("Custom Checks"),
}

/** Severity level assigned to a Release Guard finding. */
@Serializable
public enum class CheckSeverity(public val rank: Int) {
    /** Informational signal with no inherent release failure impact. */
    INFO(0),

    /** Low-impact release hygiene gap. */
    LOW(1),

    /** Moderate hardening or packaging gap. */
    MEDIUM(2),

    /** High-impact obfuscation, metadata, binary-hardening, or manifest weakness. */
    HIGH(3),

    /** Critical release defect such as debug signing, debuggable flag, VerifyError, or leaked secret. */
    CRITICAL(4),
}

/** Evaluation outcome of an individual check. */
@Serializable
public enum class CheckStatus(public val severityRank: Int) {
    /** Check was suppressed or not applicable to the provided inputs. */
    SKIP(0),

    /** Check satisfied its configured threshold or invariant. */
    PASS(1),

    /** Check found a non-blocking concern or partial hardening gap. */
    WARN(2),

    /** Check violated its configured release requirement. */
    FAIL(3),
}

/** Letter grade summarizing a 0-to-100 release hygiene and obfuscation score. */
@Serializable
public enum class ReleaseGrade(public val label: String) {
    /** 95 to 100. */
    A_PLUS("A+"),

    /** 90 to 94. */
    A("A"),

    /** 80 to 89. */
    B("B"),

    /** 70 to 79. */
    C("C"),

    /** 60 to 69. */
    D("D"),

    /** Below 60. */
    F("F"),
    ;

    public companion object {
        /** Maps a normalized 0..100 [score] to its [ReleaseGrade]. */
        public fun fromScore(score: Int): ReleaseGrade = when {
            score >= 95 -> A_PLUS
            score >= 90 -> A
            score >= 80 -> B
            score >= 70 -> C
            score >= 60 -> D
            else -> F
        }
    }
}

/** Result of evaluating one concrete release-hygiene or static-hardening check. */
@Serializable
public data class AuditFinding(
    public val checkId: String,
    public val target: AuditTarget,
    public val title: String,
    public val status: CheckStatus,
    public val severity: CheckSeverity,
    public val weight: Int,
    public val summary: String,
    public val evidence: List<String> = emptyList(),
    public val remediation: String = "",
    public val attackerLevel: String = "",
    public val plainEnglishImpact: String = "",
)

/** Score breakdown for a single audited [target]. */
@Serializable
public data class TargetScorecard(
    public val target: AuditTarget,
    public val score: Int,
    public val grade: ReleaseGrade,
    public val passedChecks: Int,
    public val warnedChecks: Int,
    public val failedChecks: Int,
    public val skippedChecks: Int,
    public val findings: List<AuditFinding>,
)

/** Regression delta comparing a current scorecard against a previously captured baseline scorecard. */
@Serializable
public data class BaselineDiff(
    public val baselineScore: Int,
    public val currentScore: Int,
    public val scoreDelta: Int,
    public val newFailures: List<String> = emptyList(),
    public val resolvedFailures: List<String> = emptyList(),
    public val statusRegressions: List<String> = emptyList(),
    public val hasRegressions: Boolean = false,
)

/** Aggregate release hygiene and static hardening scorecard across all inspected targets. */
@Serializable
public data class ReleaseScorecard(
    public val overallScore: Int,
    public val grade: ReleaseGrade,
    public val passedGate: Boolean,
    public val gateReasons: List<String>,
    public val targets: List<TargetScorecard>,
    public val findings: List<AuditFinding>,
    public val metrics: Map<String, String> = emptyMap(),
    public val baselineDiff: BaselineDiff? = null,
)

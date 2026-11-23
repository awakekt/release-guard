/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard

import com.awakekt.releaseguard.analyzers.AndroidArtifactAnalyzer
import com.awakekt.releaseguard.analyzers.AndroidAuditInput
import com.awakekt.releaseguard.analyzers.DesktopAuditInput
import com.awakekt.releaseguard.analyzers.DesktopJarAnalyzer
import com.awakekt.releaseguard.analyzers.IosArtifactAnalyzer
import com.awakekt.releaseguard.analyzers.IosAuditInput
import com.awakekt.releaseguard.analyzers.SupplyChainAnalyzer
import com.awakekt.releaseguard.analyzers.SupplyChainAuditInput
import com.awakekt.releaseguard.analyzers.TlsAuditInput
import com.awakekt.releaseguard.analyzers.TlsPinAnalyzer
import com.awakekt.releaseguard.analyzers.WebAuditInput
import com.awakekt.releaseguard.analyzers.WebBundleAnalyzer
import com.awakekt.releaseguard.io.BinaryReadLimits
import com.awakekt.releaseguard.model.AuditFinding
import com.awakekt.releaseguard.model.ReleaseGuardPolicy
import com.awakekt.releaseguard.model.ReleaseScorecard
import com.awakekt.releaseguard.report.ReleaseGuardScorer

/** Complete input specification for a multi-target KMP Release Guard audit. */
public data class ReleaseGuardRequest(
    public val policy: ReleaseGuardPolicy = ReleaseGuardPolicy(),
    public val desktop: DesktopAuditInput? = null,
    public val android: AndroidAuditInput? = null,
    public val web: WebAuditInput? = null,
    public val ios: IosAuditInput? = null,
    public val tls: TlsAuditInput? = null,
    public val supplyChain: SupplyChainAuditInput? = null,
    public val baseline: ReleaseScorecard? = null,
    public val readLimits: BinaryReadLimits = BinaryReadLimits(),
)

/**
 * Orchestrates static release hardening and hygiene audits across any combination of KMP targets
 * (Desktop JVM, Android APK/AAB, Web Kotlin/Wasm, iOS Framework/XCFramework/IPA, TLS SPKI pinning,
 * and Supply Chain) and produces a weighted [ReleaseScorecard].
 */
public object ReleaseGuardAuditor {
    /** Runs every configured analyzer in [request] and returns the aggregate [ReleaseScorecard]. */
    public fun audit(request: ReleaseGuardRequest): ReleaseScorecard {
        val findings = mutableListOf<AuditFinding>()
        val metrics = linkedMapOf<String, String>()

        request.desktop?.let { input ->
            val out = DesktopJarAnalyzer.analyze(input, request.policy, request.readLimits)
            findings += out.findings
            metrics.putAll(out.metrics)
        }
        request.android?.let { input ->
            val out = AndroidArtifactAnalyzer.analyze(input, request.policy, request.readLimits)
            findings += out.findings
            metrics.putAll(out.metrics)
        }
        request.web?.let { input ->
            val out = WebBundleAnalyzer.analyze(input, request.policy, request.readLimits)
            findings += out.findings
            metrics.putAll(out.metrics)
        }
        request.ios?.let { input ->
            val out = IosArtifactAnalyzer.analyze(input, request.policy, request.readLimits)
            findings += out.findings
            metrics.putAll(out.metrics)
        }
        request.tls?.let { input ->
            val out = TlsPinAnalyzer.analyze(input, request.policy)
            findings += out.findings
            metrics.putAll(out.metrics)
        }
        request.supplyChain?.let { input ->
            val out = SupplyChainAnalyzer.analyze(input, request.policy)
            findings += out.findings
            metrics.putAll(out.metrics)
        }

        return ReleaseGuardScorer.score(findings, request.policy, metrics, request.baseline)
    }
}

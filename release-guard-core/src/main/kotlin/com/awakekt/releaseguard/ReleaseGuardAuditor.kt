/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard

import com.awakekt.releaseguard.analyzers.AndroidArtifactAnalyzer
import com.awakekt.releaseguard.analyzers.AndroidAuditInput
import com.awakekt.releaseguard.analyzers.AssetAuditInput
import com.awakekt.releaseguard.analyzers.DesktopAuditInput
import com.awakekt.releaseguard.analyzers.DesktopJarAnalyzer
import com.awakekt.releaseguard.analyzers.IosArtifactAnalyzer
import com.awakekt.releaseguard.analyzers.IosAuditInput
import com.awakekt.releaseguard.analyzers.ShaderAndAssetAnalyzer
import com.awakekt.releaseguard.analyzers.SupplyChainAnalyzer
import com.awakekt.releaseguard.analyzers.SupplyChainAuditInput
import com.awakekt.releaseguard.analyzers.TlsAuditInput
import com.awakekt.releaseguard.analyzers.TlsPinAnalyzer
import com.awakekt.releaseguard.analyzers.WebAuditInput
import com.awakekt.releaseguard.analyzers.WebBundleAnalyzer
import com.awakekt.releaseguard.io.BinaryReadLimits
import com.awakekt.releaseguard.model.AuditFinding
import com.awakekt.releaseguard.model.AuditTarget
import com.awakekt.releaseguard.model.CheckSeverity
import com.awakekt.releaseguard.model.CheckStatus
import com.awakekt.releaseguard.model.ReleaseGuardPolicy
import com.awakekt.releaseguard.model.ReleaseScorecard
import com.awakekt.releaseguard.report.ReleaseGuardScorer
import com.awakekt.releaseguard.spi.AuditContext
import com.awakekt.releaseguard.spi.ReleaseGuardCheck
import com.awakekt.releaseguard.spi.ReleaseGuardCheckProvider
import java.util.ServiceLoader

/** Complete input specification for a multi-target KMP Release Guard audit. */
public data class ReleaseGuardRequest(
    public val policy: ReleaseGuardPolicy = ReleaseGuardPolicy(),
    public val desktop: DesktopAuditInput? = null,
    public val android: AndroidAuditInput? = null,
    public val web: WebAuditInput? = null,
    public val ios: IosAuditInput? = null,
    public val tls: TlsAuditInput? = null,
    public val supplyChain: SupplyChainAuditInput? = null,
    public val assets: AssetAuditInput? = null,
    public val baseline: ReleaseScorecard? = null,
    public val readLimits: BinaryReadLimits = BinaryReadLimits(),
    public val customChecks: List<ReleaseGuardCheck> = emptyList(),
    public val customCheckClassNames: List<String> = emptyList(),
    public val loadServiceProviderChecks: Boolean = true,
    public val customParameters: Map<String, String> = emptyMap(),
)

/**
 * Orchestrates static release hardening and hygiene audits across any combination of KMP targets
 * (Desktop JVM, Android APK/AAB, Web Kotlin/Wasm, iOS Framework/XCFramework/IPA, Assets & Shaders,
 * TLS SPKI pinning, Supply Chain, and pluggable [ReleaseGuardCheck] callbacks) and produces a
 * weighted [ReleaseScorecard].
 */
public object ReleaseGuardAuditor {
    /** Runs every configured analyzer and pluggable custom check in [request] and returns the aggregate [ReleaseScorecard]. */
    public fun audit(request: ReleaseGuardRequest): ReleaseScorecard {
        val findings = mutableListOf<AuditFinding>()
        val metrics = linkedMapOf<String, String>()

        runBuiltInAnalyzers(request, findings, metrics)
        runCustomChecks(request, findings, metrics)

        return ReleaseGuardScorer.score(findings, request.policy, metrics, request.baseline)
    }

    private fun runBuiltInAnalyzers(
        request: ReleaseGuardRequest,
        findings: MutableList<AuditFinding>,
        metrics: MutableMap<String, String>,
    ) {
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
        request.assets?.let { input ->
            val out = ShaderAndAssetAnalyzer.analyze(input, request.policy, request.readLimits)
            findings += out.findings
            metrics.putAll(out.metrics)
        }
    }

    private fun runCustomChecks(
        request: ReleaseGuardRequest,
        findings: MutableList<AuditFinding>,
        metrics: MutableMap<String, String>,
    ) {
        val resolvedChecks = mutableListOf<ReleaseGuardCheck>()
        resolvedChecks += request.customChecks

        if (request.loadServiceProviderChecks) {
            ServiceLoader.load(ReleaseGuardCheckProvider::class.java).forEach { provider ->
                resolvedChecks += provider.createChecks()
            }
        }
        for (className in request.customCheckClassNames) {
            loadCustomCheckByName(className, resolvedChecks, findings)
        }
        if (resolvedChecks.isEmpty()) return

        val context = AuditContext(
            policy = request.policy,
            desktop = request.desktop,
            android = request.android,
            web = request.web,
            ios = request.ios,
            assets = request.assets,
            readLimits = request.readLimits,
            builtInFindings = findings.toList(),
            builtInMetrics = metrics.toMap(),
            customParameters = request.customParameters,
        )
        for ((index, check) in resolvedChecks.withIndex()) {
            evaluateSingleCheck(index, check, context, findings, metrics)
        }
    }

    private fun loadCustomCheckByName(
        className: String,
        target: MutableList<ReleaseGuardCheck>,
        findings: MutableList<AuditFinding>,
    ) {
        val trimmed = className.trim()
        if (trimmed.isEmpty()) return
        runCatching {
            val clazz = Class.forName(trimmed)
            val instance = clazz.getDeclaredConstructor().newInstance()
            when (instance) {
                is ReleaseGuardCheck -> target += instance
                is ReleaseGuardCheckProvider -> target += instance.createChecks()
                else -> error("Class $trimmed must implement ReleaseGuardCheck or ReleaseGuardCheckProvider.")
            }
        }.onFailure { err ->
            findings += AuditFinding(
                checkId = "custom.check.load_error",
                target = AuditTarget.CUSTOM,
                title = "Custom check class loading",
                status = CheckStatus.FAIL,
                severity = CheckSeverity.HIGH,
                weight = 10,
                summary = "Failed to instantiate custom check '$trimmed': ${err.message}",
                remediation = "Ensure '$trimmed' is on the build classpath with a public no-arg constructor implementing ReleaseGuardCheck or ReleaseGuardCheckProvider.",
            )
        }
    }

    private fun evaluateSingleCheck(
        index: Int,
        check: ReleaseGuardCheck,
        context: AuditContext,
        findings: MutableList<AuditFinding>,
        metrics: MutableMap<String, String>,
    ) {
        runCatching { check.evaluate(context) }
            .onSuccess { out ->
                findings += out.findings
                metrics.putAll(out.metrics)
            }
            .onFailure { err ->
                val name = check::class.java.simpleName.ifBlank { "CustomCheck#$index" }
                findings += AuditFinding(
                    checkId = "custom.check.execution_error",
                    target = AuditTarget.CUSTOM,
                    title = "Custom check execution ($name)",
                    status = CheckStatus.FAIL,
                    severity = CheckSeverity.HIGH,
                    weight = 10,
                    summary = "Custom check '$name' threw ${err::class.java.simpleName}: ${err.message}",
                    remediation = "Fix the exception inside custom ReleaseGuardCheck '$name'.",
                )
            }
    }
}

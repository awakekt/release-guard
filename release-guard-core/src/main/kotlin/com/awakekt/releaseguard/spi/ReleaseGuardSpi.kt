/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.spi

import com.awakekt.releaseguard.analyzers.AnalyzerOutput
import com.awakekt.releaseguard.analyzers.AndroidAuditInput
import com.awakekt.releaseguard.analyzers.AssetAuditInput
import com.awakekt.releaseguard.analyzers.DesktopAuditInput
import com.awakekt.releaseguard.analyzers.IosAuditInput
import com.awakekt.releaseguard.analyzers.WebAuditInput
import com.awakekt.releaseguard.io.BinaryReadLimits
import com.awakekt.releaseguard.model.AuditFinding
import com.awakekt.releaseguard.model.ReleaseGuardPolicy

/**
 * Read-only audit snapshot passed to pluggable [ReleaseGuardCheck] callbacks so game- or
 * organization-specific authoring checks can inspect artifacts and built-in results without
 * coupling [com.awakekt.releaseguard.ReleaseGuardAuditor] to a specific engine or asset schema.
 */
public data class AuditContext(
    public val policy: ReleaseGuardPolicy,
    public val desktop: DesktopAuditInput? = null,
    public val android: AndroidAuditInput? = null,
    public val web: WebAuditInput? = null,
    public val ios: IosAuditInput? = null,
    public val assets: AssetAuditInput? = null,
    public val readLimits: BinaryReadLimits = BinaryReadLimits(),
    public val builtInFindings: List<AuditFinding> = emptyList(),
    public val builtInMetrics: Map<String, String> = emptyMap(),
    public val customParameters: Map<String, String> = emptyMap(),
)

/**
 * Pluggable audit callback contributing custom [AuditFinding]s and metrics into the weighted
 * Release Guard scorecard, HTML/Markdown/SARIF reports, baseline diff, and CI gate.
 */
public fun interface ReleaseGuardCheck {
    /** Evaluates this custom check against [context] and returns findings and optional metrics. */
    public fun evaluate(context: AuditContext): AnalyzerOutput

    public companion object {
        /** Convenience helper wrapping a lambda that only emits [AuditFinding]s. */
        public fun findingsOnly(block: (AuditContext) -> List<AuditFinding>): ReleaseGuardCheck =
            ReleaseGuardCheck { ctx -> AnalyzerOutput(findings = block(ctx)) }
    }
}

/**
 * [java.util.ServiceLoader] SPI allowing external plugins, engine adapters, or Gradle `build-logic`
 * jars to register custom [ReleaseGuardCheck] implementations automatically while remaining
 * configuration-cache-safe.
 */
public interface ReleaseGuardCheckProvider {
    /** Stable identifier for diagnostics and logging. */
    public val id: String

    /** Returns the custom checks contributed by this provider. */
    public fun createChecks(): List<ReleaseGuardCheck>
}

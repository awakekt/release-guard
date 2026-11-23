/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.model

import kotlinx.serialization.Serializable

/** Deployment mode governing web bundle audit strictness. */
@Serializable
public enum class WebAuditMode {
    /** Enforces stripped debug sections, source map removal, and readability ceiling. */
    PRODUCTION,

    /** Allows WASM name/debug sections for preview stack traces while still checking source maps and repo paths. */
    PREVIEW,
}

/** Configuration for auditing Desktop JVM release JARs, native desktop libs, and launcher configs. */
@Serializable
public data class DesktopAuditPolicy(
    public val maxOwnReadability: Double = 0.02,
    public val maxKeptProjectClasses: Int = 10,
    public val verifyBytecode: Boolean = true,
    public val forbidOriginalSourceFileAttribute: Boolean = true,
    public val forbidDebugTablesAndKotlinMetadata: Boolean = true,
    public val requireMappingFile: Boolean = false,
    public val inspectNativeLibraries: Boolean = true,
    public val requirePeAslrAndDep: Boolean = true,
    public val forbidLeakedPdbPaths: Boolean = true,
    public val forbidJpackageDebugFlags: Boolean = true,
)

/** Configuration for auditing Android release APK and Android App Bundle (AAB) packages. */
@Serializable
public data class AndroidAuditPolicy(
    public val maxOwnReadability: Double = 0.05,
    public val maxKeptProjectClasses: Int = 20,
    public val forbidKotlinMetadata: Boolean = true,
    public val forbidDebuggable: Boolean = true,
    public val forbidAllowBackup: Boolean = true,
    public val forbidCleartextTraffic: Boolean = true,
    public val forbidTestOnly: Boolean = true,
    public val minTargetSdkVersion: Int? = null,
    public val forbidExportedComponentsWithoutPermission: Boolean = true,
    public val allowedExportedComponents: Set<String> = emptySet(),
    public val forbidWeakNetworkSecurityConfig: Boolean = true,
    public val forbidDebugSigningCert: Boolean = true,
    public val requireV2OrV3Signing: Boolean = true,
    public val expectedSigningDigestsSha256: Set<String> = emptySet(),
    public val inspectNativeElfLibraries: Boolean = true,
    public val requireElfHardening: Boolean = true,
    public val requireElf16KbAlignment: Boolean = true,
    public val forbiddenArtifactPatterns: List<String> = DEFAULT_FORBIDDEN_ARTIFACTS,
    public val forbidSensitiveBundledFiles: Boolean = true,
    public val requireMappingFile: Boolean = false,
) {
    public companion object {
        /** Default debug and validation artifacts that must not ship inside release APKs or AABs. */
        public val DEFAULT_FORBIDDEN_ARTIFACTS: List<String> = listOf(
            "DebugProbesKt.bin",
            "kotlin-tooling-metadata.json",
            "META-INF/version-control-info.textproto",
            "libVkLayer_khronos_validation.so",
            "mapping.txt",
        )
    }
}

/** Configuration for auditing Kotlin/Wasm and JavaScript web bundles. */
@Serializable
public data class WebAuditPolicy(
    public val mode: WebAuditMode = WebAuditMode.PRODUCTION,
    public val maxReadability: Double = 0.25,
    public val forbidSourceMaps: Boolean = true,
    public val forbidDebugSections: Boolean = true,
    public val forbidProjectSourcePaths: Boolean = true,
    public val maxQualifiedProjectClasses: Int? = null,
    public val requireSecurityHeaders: Boolean = true,
    public val gradeCspQuality: Boolean = true,
    public val allowWasmUnsafeEvalInCsp: Boolean = true,
    public val requireSubresourceIntegrity: Boolean = true,
    public val sriAllowlistHosts: Set<String> = emptySet(),
    public val forbidInsecureWebEndpoints: Boolean = true,
    public val forbidDebuggerStatements: Boolean = true,
    public val forbidSensitiveDistFiles: Boolean = true,
    public val maxWasmExports: Int? = null,
)

/** Configuration for auditing iOS `.framework`, `.xcframework`, `.ipa`, and Mach-O binaries. */
@Serializable
public data class IosAuditPolicy(
    public val forbidDwarfSections: Boolean = true,
    public val maxUnstrippedProjectSymbols: Int = 0,
    public val forbidArbitraryLoads: Boolean = true,
    public val forbidAtsHttpExceptions: Boolean = true,
    public val forbidDebugProvisioningProfile: Boolean = true,
    public val requireMachOPie: Boolean = true,
    public val requireCodeSignatureForIpa: Boolean = true,
    public val forbidLeakedBuildPaths: Boolean = true,
    public val requirePrivacyManifest: Boolean = false,
)

/** Configuration for auditing TLS SPKI pin specs. */
@Serializable
public data class TlsAuditPolicy(
    public val requirePins: Boolean = false,
    public val minPinsPerHost: Int = 2,
    public val probeLiveHosts: Boolean = false,
    public val probeHosts: List<String> = emptyList(),
)

/** Configuration for scanning release binaries and bundles for high-confidence leaked secrets. */
@Serializable
public data class SecretScanPolicy(
    public val enabled: Boolean = true,
    public val enableHighEntropyScan: Boolean = true,
    public val minEntropyThreshold: Double = 4.5,
    public val forbidLocalhostEndpointsInRelease: Boolean = false,
    public val extraPatterns: Map<String, String> = emptyMap(),
    public val allowlistRegexes: List<String> = emptyList(),
)

/** Configuration for verifying that packaged content bundles carry encryption headers. */
@Serializable
public data class AssetEncryptionPolicy(
    public val enabled: Boolean = false,
    public val bundleExtensions: Set<String> = setOf("awkb"),
    public val requireAwkbV2EncryptedFlag: Boolean = true,
)

/** Configuration for baseline regression gating against a previous scorecard. */
@Serializable
public data class BaselinePolicy(
    public val failOnRegression: Boolean = false,
    public val maxAllowedScoreDrop: Int = 0,
)

/** Configuration for build supply-chain hygiene checks. */
@Serializable
public data class SupplyChainPolicy(
    public val forbidSnapshotDependencies: Boolean = true,
)

/**
 * Full configurable Release Guard audit and scoring policy.
 *
 * Static release auditing raises reverse-engineering cost and prevents debug/packaging leaks; it
 * complements (never replaces) server-authoritative gameplay, entitlements, or runtime RASP.
 */
@Serializable
public data class ReleaseGuardPolicy(
    public val projectPackages: List<String> = emptyList(),
    public val projectKeywords: List<String> = emptyList(),
    public val minScore: Int = 80,
    public val failOnSeverity: CheckSeverity? = CheckSeverity.HIGH,
    public val allowedLibraryPathPatterns: List<String> = DEFAULT_ALLOWED_LIBRARY_PATHS,
    public val disabledChecks: Set<String> = emptySet(),
    public val severityOverrides: Map<String, CheckSeverity> = emptyMap(),
    public val weightOverrides: Map<String, Int> = emptyMap(),
    public val desktop: DesktopAuditPolicy = DesktopAuditPolicy(),
    public val android: AndroidAuditPolicy = AndroidAuditPolicy(),
    public val web: WebAuditPolicy = WebAuditPolicy(),
    public val ios: IosAuditPolicy = IosAuditPolicy(),
    public val tls: TlsAuditPolicy = TlsAuditPolicy(),
    public val secrets: SecretScanPolicy = SecretScanPolicy(),
    public val assetEncryption: AssetEncryptionPolicy = AssetEncryptionPolicy(),
    public val baseline: BaselinePolicy = BaselinePolicy(),
    public val supplyChain: SupplyChainPolicy = SupplyChainPolicy(),
) {
    public companion object {
        /** Build-machine path prefixes belonging to upstream libraries rather than the audited app. */
        public val DEFAULT_ALLOWED_LIBRARY_PATHS: List<String> = listOf(
            """(?:/Users|/home)/runner/work/(?:awake|basekt)/""",
            """/opt/buildAgent/work/""",
            """/mnt/agent/work/""",
            """[A-Za-z]:[/\\]BuildAgent[/\\]work[/\\]""",
        )
    }
}

/** Curated [ReleaseGuardPolicy] presets for common release stages. */
public object ReleaseGuardPolicies {
    /** Strict production release policy enforcing tight obfuscation, binary hardening, and release hygiene. */
    public fun strictRelease(
        projectPackages: List<String> = emptyList(),
        projectKeywords: List<String> = emptyList(),
        minScore: Int = 90,
    ): ReleaseGuardPolicy = ReleaseGuardPolicy(
        projectPackages = projectPackages,
        projectKeywords = projectKeywords,
        minScore = minScore,
        failOnSeverity = CheckSeverity.HIGH,
        desktop = DesktopAuditPolicy(requireMappingFile = true),
        android = AndroidAuditPolicy(requireMappingFile = true),
        web = WebAuditPolicy(mode = WebAuditMode.PRODUCTION),
        ios = IosAuditPolicy(requirePrivacyManifest = true),
        tls = TlsAuditPolicy(requirePins = false, minPinsPerHost = 2, probeLiveHosts = false),
        secrets = SecretScanPolicy(enabled = true, enableHighEntropyScan = true, forbidLocalhostEndpointsInRelease = true),
        baseline = BaselinePolicy(failOnRegression = true, maxAllowedScoreDrop = 0),
    )

    /** Balanced release policy suitable for most KMP apps and games adopting release gates incrementally. */
    public fun balancedRelease(
        projectPackages: List<String> = emptyList(),
        projectKeywords: List<String> = emptyList(),
        minScore: Int = 80,
    ): ReleaseGuardPolicy = ReleaseGuardPolicy(
        projectPackages = projectPackages,
        projectKeywords = projectKeywords,
        minScore = minScore,
        failOnSeverity = CheckSeverity.HIGH,
    )

    /** Non-blocking audit preset for preview or development builds that still reports every finding and score. */
    public fun developmentAudit(
        projectPackages: List<String> = emptyList(),
        projectKeywords: List<String> = emptyList(),
    ): ReleaseGuardPolicy = ReleaseGuardPolicy(
        projectPackages = projectPackages,
        projectKeywords = projectKeywords,
        minScore = 0,
        failOnSeverity = null,
        web = WebAuditPolicy(
            mode = WebAuditMode.PREVIEW,
            requireSecurityHeaders = false,
            gradeCspQuality = false,
        ),
    )
}

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
import java.io.File
import java.util.Locale

internal fun missingAndroidArtifactOutput(file: File): AnalyzerOutput = AnalyzerOutput(
    findings = listOf(
        AuditFinding(
            checkId = "android.artifact.present",
            target = AuditTarget.ANDROID,
            title = "Android APK/AAB present",
            status = CheckStatus.FAIL,
            severity = CheckSeverity.CRITICAL,
            weight = 25,
            summary = "Android APK/AAB file does not exist: ${file.path}.",
            remediation = "Assemble the Android release APK or AAB before running Release Guard.",
        ),
    ),
)

internal fun collectAndroidElfIssues(
    path: String,
    elf: ElfInspectionResult,
    policy: ReleaseGuardPolicy,
): List<String> = buildList {
    if (policy.android.requireElfHardening) {
        if (!elf.isPieOrShared) add("$path: not ET_DYN/PIE")
        if (!elf.hasNxStack) add("$path: executable stack (missing NX)")
        if (!elf.hasFullRelro) add("$path: missing Full RELRO (RELRO=${elf.hasRelro})")
        if (elf.hasDebugSections || elf.hasSymbolTable) add("$path: unstripped debug/symbol sections")
    }
    if (policy.android.requireElf16KbAlignment && elf.is64Bit && !elf.is16KbAligned) {
        add("$path: PT_LOAD alignment ${elf.minLoadAlignment} < 16384 (fails Android 15+ 16 KB page requirement)")
    }
}

internal fun checkAndroidKotlinMetadata(dexSummaries: List<DexSummary>, policy: ReleaseGuardPolicy): AuditFinding {
    if (!policy.android.forbidKotlinMetadata) {
        return AuditFinding(
            checkId = "android.metadata.kotlin_metadata",
            target = AuditTarget.ANDROID,
            title = "Android DEX @kotlin.Metadata stripped",
            status = CheckStatus.SKIP,
            severity = CheckSeverity.LOW,
            weight = 5,
            summary = "DEX @kotlin.Metadata check disabled by policy.",
        )
    }
    val hasMeta = dexSummaries.any { it.hasKotlinMetadataDescriptor }
    return AuditFinding(
        checkId = "android.metadata.kotlin_metadata",
        target = AuditTarget.ANDROID,
        title = "Android DEX @kotlin.Metadata stripped",
        status = if (!hasMeta) CheckStatus.PASS else CheckStatus.WARN,
        severity = CheckSeverity.LOW,
        weight = 5,
        summary = if (!hasMeta) {
            "No @kotlin.Metadata descriptors found in DEX files."
        } else {
            "@kotlin.Metadata descriptors survive in DEX (may expose Kotlin parameter/property names)."
        },
        remediation = "Avoid broad '-keep class kotlin.Metadata' rules unless kotlin-reflect is required at runtime.",
    )
}

internal fun checkAndroidManifestDebuggable(flags: AndroidManifestFlags, policy: ReleaseGuardPolicy): AuditFinding = when {
    !policy.android.forbidDebuggable -> AuditFinding(
        checkId = "android.manifest.debuggable",
        target = AuditTarget.ANDROID,
        title = "Android manifest android:debuggable disabled",
        status = CheckStatus.SKIP,
        severity = CheckSeverity.CRITICAL,
        weight = 15,
        summary = "Manifest debuggable check disabled by policy.",
    )
    !flags.debuggable -> AuditFinding(
        checkId = "android.manifest.debuggable",
        target = AuditTarget.ANDROID,
        title = "Android manifest android:debuggable disabled",
        status = CheckStatus.PASS,
        severity = CheckSeverity.CRITICAL,
        weight = 15,
        summary = "AndroidManifest.xml does not set android:debuggable=true.",
    )
    else -> AuditFinding(
        checkId = "android.manifest.debuggable",
        target = AuditTarget.ANDROID,
        title = "Android manifest android:debuggable disabled",
        status = CheckStatus.FAIL,
        severity = CheckSeverity.CRITICAL,
        weight = 15,
        summary = "AndroidManifest.xml sets android:debuggable=true in a release artifact.",
        remediation = "Ensure release buildType keeps isDebuggable = false and never hardcode android:debuggable=\"true\".",
    )
}

internal fun checkAndroidBackupAndCleartext(flags: AndroidManifestFlags, policy: ReleaseGuardPolicy): AuditFinding {
    if (!policy.android.forbidAllowBackup && !policy.android.forbidCleartextTraffic) {
        return AuditFinding(
            checkId = "android.manifest.network_and_backup",
            target = AuditTarget.ANDROID,
            title = "Android backup & cleartext traffic hardening",
            status = CheckStatus.SKIP,
            severity = CheckSeverity.MEDIUM,
            weight = 8,
            summary = "Manifest backup/cleartext checks disabled by policy.",
        )
    }
    val issues = buildList {
        if (policy.android.forbidAllowBackup && flags.allowBackup == true) add("android:allowBackup=true")
        if (policy.android.forbidCleartextTraffic && flags.usesCleartextTraffic == true) add("android:usesCleartextTraffic=true")
    }
    val passed = issues.isEmpty()
    return AuditFinding(
        checkId = "android.manifest.network_and_backup",
        target = AuditTarget.ANDROID,
        title = "Android backup & cleartext traffic hardening",
        status = if (passed) CheckStatus.PASS else CheckStatus.FAIL,
        severity = CheckSeverity.MEDIUM,
        weight = 8,
        summary = if (passed) "Manifest does not enable allowBackup or cleartext traffic." else "Insecure manifest flag(s) enabled: ${issues.joinToString()}.",
        evidence = issues,
        remediation = "Set android:allowBackup=\"false\" and android:usesCleartextTraffic=\"false\" in AndroidManifest.xml.",
    )
}

internal fun checkAndroidTestOnlyAndSdk(flags: AndroidManifestFlags, policy: ReleaseGuardPolicy): AuditFinding {
    val issues = buildList {
        if (policy.android.forbidTestOnly && flags.testOnly) add("android:testOnly=true")
        val minTarget = policy.android.minTargetSdkVersion
        if (minTarget != null && flags.targetSdkVersion != null && flags.targetSdkVersion < minTarget) {
            add("targetSdkVersion=${flags.targetSdkVersion} < minimum $minTarget")
        }
    }
    val passed = issues.isEmpty()
    return AuditFinding(
        checkId = "android.manifest.test_only_and_sdk",
        target = AuditTarget.ANDROID,
        title = "Android manifest testOnly & targetSdk hygiene",
        status = if (passed) CheckStatus.PASS else CheckStatus.FAIL,
        severity = CheckSeverity.MEDIUM,
        weight = 5,
        summary = if (passed) "Manifest does not set testOnly=true and meets targetSdk requirements." else "Manifest hygiene violation(s): ${issues.joinToString()}.",
        evidence = issues,
        remediation = "Remove android:testOnly=\"true\" and target the current Google Play API level.",
    )
}

internal fun checkAndroidExportedComponents(
    flags: AndroidManifestFlags,
    policy: ReleaseGuardPolicy,
    metrics: MutableMap<String, String>,
): AuditFinding {
    if (!policy.android.forbidExportedComponentsWithoutPermission) {
        return AuditFinding(
            checkId = "android.manifest.exported_components",
            target = AuditTarget.ANDROID,
            title = "Android exported components guarded",
            status = CheckStatus.SKIP,
            severity = CheckSeverity.HIGH,
            weight = 10,
            summary = "Exported component check disabled by policy.",
        )
    }
    val unguarded = flags.exportedComponents.filter { comp ->
        !comp.isLauncherActivity && !comp.hasPermissionGuard && comp.name !in policy.android.allowedExportedComponents
    }
    metrics["android.unguardedExportedComponents"] = unguarded.size.toString()
    val passed = unguarded.isEmpty()
    return AuditFinding(
        checkId = "android.manifest.exported_components",
        target = AuditTarget.ANDROID,
        title = "Android exported components guarded",
        status = if (passed) CheckStatus.PASS else CheckStatus.FAIL,
        severity = CheckSeverity.HIGH,
        weight = 10,
        summary = if (passed) {
            "No unguarded non-launcher exported components found in AndroidManifest.xml."
        } else {
            "Found ${unguarded.size} exported Android component(s) without an android:permission guard."
        },
        evidence = unguarded.take(10).map { "${it.kind}:${it.name}" },
        remediation = "Set android:exported=\"false\" on internal components or protect exported ones with android:permission.",
    )
}

internal fun checkAndroidNetworkSecurityConfig(
    configs: List<Pair<String, NetworkSecurityConfigSummary>>,
    policy: ReleaseGuardPolicy,
): AuditFinding {
    if (!policy.android.forbidWeakNetworkSecurityConfig || configs.isEmpty()) {
        return AuditFinding(
            checkId = "android.manifest.network_security_config",
            target = AuditTarget.ANDROID,
            title = "Android network_security_config hardening",
            status = CheckStatus.SKIP,
            severity = CheckSeverity.HIGH,
            weight = 8,
            summary = if (!policy.android.forbidWeakNetworkSecurityConfig) "network_security_config check disabled by policy." else "No network_security_config.xml resource found in archive.",
        )
    }
    val issues = configs.flatMap { (path, summary) -> summary.issues.map { "$path: $it" } }
    val passed = issues.isEmpty()
    return AuditFinding(
        checkId = "android.manifest.network_security_config",
        target = AuditTarget.ANDROID,
        title = "Android network_security_config hardening",
        status = if (passed) CheckStatus.PASS else CheckStatus.FAIL,
        severity = CheckSeverity.HIGH,
        weight = 8,
        summary = if (passed) "Verified ${configs.size} network_security_config resource(s) without user CA trust or debug overrides." else "Weak network_security_config directive(s) found in release archive.",
        evidence = issues.take(8),
        remediation = "Remove <certificates src=\"user\"/>, <debug-overrides>, and cleartextTrafficPermitted=\"true\" from release configs.",
    )
}

internal fun checkAndroidSigningCertificate(
    signing: ApkSigningSummary,
    isAab: Boolean,
    policy: ReleaseGuardPolicy,
    metrics: MutableMap<String, String>,
): AuditFinding {
    val schemes = buildList {
        if (signing.hasV1Signature) add("v1")
        if (signing.hasV2OrV3Signature) add("v2/v3")
    }.joinToString(",").ifEmpty { "unsigned" }
    metrics["android.signingSchemes"] = schemes
    signing.certificates.firstOrNull()?.let { metrics["android.signingCertSha256"] = it.sha256Hex }

    val debugCerts = signing.certificates.filter { it.isAndroidDebugCert }
    val expected = policy.android.expectedSigningDigestsSha256.map { it.lowercase(Locale.ROOT) }.toSet()
    val actual = signing.certificates.map { it.sha256Hex.lowercase(Locale.ROOT) }.toSet()
    val v1OnlyApk = !isAab && policy.android.requireV2OrV3Signing && signing.hasV1Signature && !signing.hasV2OrV3Signature

    val verdict = when {
        !signing.isSigned -> SigningVerdict(CheckStatus.FAIL, CheckSeverity.CRITICAL, "Artifact is unsigned (no v1 JAR signature or v2/v3 APK Signing Block found).", emptyList())
        policy.android.forbidDebugSigningCert && debugCerts.isNotEmpty() -> SigningVerdict(CheckStatus.FAIL, CheckSeverity.CRITICAL, "Artifact is signed with an Android Debug certificate (CN=Android Debug).", debugCerts.map { "${it.subjectDn} (${it.sha256Hex.take(16)}...)" })
        expected.isNotEmpty() && actual.none { it in expected } -> SigningVerdict(CheckStatus.FAIL, CheckSeverity.CRITICAL, "Signing certificate SHA-256 does not match any expected release digest.", actual.toList())
        v1OnlyApk -> SigningVerdict(CheckStatus.FAIL, CheckSeverity.HIGH, "APK is signed with v1 JAR scheme only (vulnerable to Janus); missing APK Signature Scheme v2/v3.", emptyList())
        else -> SigningVerdict(CheckStatus.PASS, CheckSeverity.CRITICAL, "Release signing verified ($schemes, ${signing.certificates.size} cert(s)).", emptyList())
    }
    return AuditFinding(
        checkId = "android.signing.release_cert",
        target = AuditTarget.ANDROID,
        title = "Android release signing certificate & scheme",
        status = verdict.status,
        severity = verdict.severity,
        weight = 15,
        summary = verdict.summary,
        evidence = verdict.evidence,
        remediation = "Sign release APKs with apksigner enabling v2/v3 and a production release keystore.",
    )
}

internal fun checkAndroidForbiddenArtifacts(
    entryNames: List<String>,
    sensitiveFiles: List<String>,
    mappingFile: File?,
    policy: ReleaseGuardPolicy,
): AuditFinding {
    val hits = entryNames.filter { entry ->
        policy.android.forbiddenArtifactPatterns.any { p -> entry == p || entry.endsWith("/$p") || entry.endsWith(p) }
    }
    val allBad = hits + sensitiveFiles.map { "sensitive:$it" }
    val missingMapping = policy.android.requireMappingFile && (mappingFile == null || !mappingFile.isFile || mappingFile.length() == 0L)
    val status = when {
        allBad.isNotEmpty() -> CheckStatus.FAIL
        missingMapping -> CheckStatus.WARN
        else -> CheckStatus.PASS
    }
    val summary = when {
        allBad.isNotEmpty() -> "Found ${hits.size} forbidden debug/validation artifact(s) and ${sensitiveFiles.size} sensitive file(s)."
        missingMapping -> "No forbidden artifacts inside archive, but expected external R8 mapping.txt is missing."
        else -> "No debug probes, tooling metadata, Vulkan validation layers, or sensitive key/env files bundled."
    }
    return AuditFinding(
        checkId = "android.packaging.debug_artifacts",
        target = AuditTarget.ANDROID,
        title = "Android debug & sensitive artifact stripping",
        status = status,
        severity = CheckSeverity.HIGH,
        weight = 12,
        summary = summary,
        evidence = allBad.take(10),
        remediation = "Exclude debug probes, validation layers, .env, .jks, and .pem files from release packaging.",
    )
}

internal fun checkAndroidSecrets(matches: List<SecretMatch>, policy: ReleaseGuardPolicy): AuditFinding = when {
    !policy.secrets.enabled -> AuditFinding(
        checkId = "android.secrets.scan",
        target = AuditTarget.ANDROID,
        title = "Android artifact secret scan",
        status = CheckStatus.SKIP,
        severity = CheckSeverity.CRITICAL,
        weight = 12,
        summary = "Secret scanning disabled by policy.",
    )
    matches.isEmpty() -> AuditFinding(
        checkId = "android.secrets.scan",
        target = AuditTarget.ANDROID,
        title = "Android artifact secret scan",
        status = CheckStatus.PASS,
        severity = CheckSeverity.CRITICAL,
        weight = 12,
        summary = "No private keys or high-entropy secret tokens found in Android archive.",
    )
    else -> AuditFinding(
        checkId = "android.secrets.scan",
        target = AuditTarget.ANDROID,
        title = "Android artifact secret scan",
        status = CheckStatus.FAIL,
        severity = CheckSeverity.CRITICAL,
        weight = 12,
        summary = "Found ${matches.size} high-confidence secret or forbidden endpoint match(es) in Android archive.",
        evidence = matches.take(8).map { "${it.ruleName} @ ${it.location} (${it.redactedPreview})" },
        remediation = "Move secrets off the client APK/AAB; issue short-lived tokens from your server.",
    )
}

private data class SigningVerdict(
    val status: CheckStatus,
    val severity: CheckSeverity,
    val summary: String,
    val evidence: List<String>,
)

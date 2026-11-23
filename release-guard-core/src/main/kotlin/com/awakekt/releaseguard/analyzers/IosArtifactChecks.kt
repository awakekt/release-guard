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

internal fun missingIosBinaryOutput(path: File): AnalyzerOutput = AnalyzerOutput(
    findings = listOf(
        AuditFinding(
            checkId = "ios.binary.present",
            target = AuditTarget.IOS,
            title = "iOS Mach-O binary present",
            status = CheckStatus.FAIL,
            severity = CheckSeverity.CRITICAL,
            weight = 30,
            summary = "Could not locate a valid 64-bit Mach-O binary inside ${path.path}.",
            remediation = "Build the release .framework, .xcframework, or .ipa before running Release Guard.",
        ),
    ),
)

internal fun checkIosDwarfAbsent(
    parsed: List<Pair<String, MachOInspectionResult>>,
    policy: ReleaseGuardPolicy,
): AuditFinding {
    if (!policy.ios.forbidDwarfSections) {
        return AuditFinding(
            checkId = "ios.macho.dwarf_absent",
            target = AuditTarget.IOS,
            title = "iOS Mach-O DWARF debug segment stripped",
            status = CheckStatus.SKIP,
            severity = CheckSeverity.HIGH,
            weight = 20,
            summary = "DWARF segment check disabled by policy.",
        )
    }
    val offending = parsed.filter { it.second.hasDwarfSegment }.map { it.first }
    val passed = offending.isEmpty()
    return AuditFinding(
        checkId = "ios.macho.dwarf_absent",
        target = AuditTarget.IOS,
        title = "iOS Mach-O DWARF debug segment stripped",
        status = if (passed) CheckStatus.PASS else CheckStatus.FAIL,
        severity = CheckSeverity.HIGH,
        weight = 20,
        summary = if (passed) {
            "No __DWARF debug segment found across ${parsed.size} Mach-O binary(s)."
        } else {
            "${offending.size} Mach-O binary(s) still embed a __DWARF debug segment."
        },
        evidence = offending.take(10),
        remediation = "Archive with dSYM separation (DEBUG_INFORMATION_FORMAT = dwarf-with-dsym) and strip linked product.",
    )
}

internal fun checkIosSymbolsStripped(
    parsed: List<Pair<String, MachOInspectionResult>>,
    policy: ReleaseGuardPolicy,
    metrics: MutableMap<String, String>,
): AuditFinding {
    val exposedSymbols = parsed.flatMap { it.second.localSymbolNames }.filter { name ->
        matchesIosProjectHint(name, policy) || IdentifierHeuristics.isRecognisableIdentifier(
            name = name.removePrefix("_"),
            projectKeywords = policy.projectKeywords,
            projectPackages = policy.projectPackages,
        )
    }.distinct()
    val stabCount = parsed.sumOf { it.second.debugStabSymbolCount }
    metrics["ios.unstrippedLocalSymbols"] = exposedSymbols.size.toString()

    val limit = policy.ios.maxUnstrippedProjectSymbols
    val passed = stabCount == 0 && exposedSymbols.size <= limit
    return AuditFinding(
        checkId = "ios.macho.symbols_stripped",
        target = AuditTarget.IOS,
        title = "iOS Mach-O debug & local symbols stripped",
        status = if (passed) CheckStatus.PASS else CheckStatus.FAIL,
        severity = CheckSeverity.HIGH,
        weight = 20,
        summary = if (passed) {
            "Mach-O symbol tables are cleanly stripped ($stabCount STAB, ${exposedSymbols.size} recognisable local symbols)."
        } else {
            "Found ${exposedSymbols.size + stabCount} unstripped debug/local symbol(s) ($stabCount STAB, ${exposedSymbols.size} local; limit $limit)."
        },
        evidence = exposedSymbols.take(10),
        remediation = "Enable Xcode Deployment Postprocessing, Strip Linked Product = Yes, and Additional Strip Flags = -rSTx.",
    )
}

internal fun checkIosMachOHardening(
    parsed: List<Pair<String, MachOInspectionResult>>,
    isIpa: Boolean,
    policy: ReleaseGuardPolicy,
): AuditFinding {
    val issues = buildList {
        for ((name, info) in parsed) {
            if (policy.ios.requireMachOPie && info.isExecutable && !info.isPie) add("$name: missing MH_PIE (ASLR disabled)")
            if (isIpa && policy.ios.requireCodeSignatureForIpa && !info.hasCodeSignature) add("$name: missing LC_CODE_SIGNATURE")
        }
    }
    val passed = issues.isEmpty()
    return AuditFinding(
        checkId = "ios.macho.hardening",
        target = AuditTarget.IOS,
        title = "iOS Mach-O PIE (ASLR) & code signature",
        status = if (passed) CheckStatus.PASS else CheckStatus.FAIL,
        severity = CheckSeverity.HIGH,
        weight = 15,
        summary = if (passed) {
            "All ${parsed.size} Mach-O binary(s) satisfy PIE and code-signature requirements."
        } else {
            "Mach-O binary hardening issue(s) found: ${issues.joinToString()}."
        },
        evidence = issues.take(10),
        remediation = "Link iOS executables as PIE (Position Independent Executable) and sign IPA binaries for App Store distribution.",
    )
}

internal fun checkIosLeakedBuildPaths(
    binaries: List<Pair<String, ByteArray>>,
    policy: ReleaseGuardPolicy,
): AuditFinding {
    if (!policy.ios.forbidLeakedBuildPaths) {
        return AuditFinding(
            checkId = "ios.macho.build_paths",
            target = AuditTarget.IOS,
            title = "iOS Mach-O workstation build paths scrubbed",
            status = CheckStatus.SKIP,
            severity = CheckSeverity.LOW,
            weight = 5,
            summary = "Build-path leak check disabled by policy.",
        )
    }
    val leaks = binaries.flatMap { (name, bytes) ->
        SecretScanner.extractLocalBuildPaths(
            IdentifierHeuristics.extractPrintableStrings(bytes),
            policy.allowedLibraryPathPatterns,
        ).map { "$name:$it" }
    }
    val passed = leaks.isEmpty()
    return AuditFinding(
        checkId = "ios.macho.build_paths",
        target = AuditTarget.IOS,
        title = "iOS Mach-O workstation build paths scrubbed",
        status = if (passed) CheckStatus.PASS else CheckStatus.WARN,
        severity = CheckSeverity.LOW,
        weight = 5,
        summary = if (passed) {
            "No workstation build paths leaked in Mach-O strings."
        } else {
            "Found ${leaks.size} leaked workstation build path(s) in Mach-O strings."
        },
        evidence = leaks.take(8),
        remediation = "Remap compiler debug/file prefixes (-ffile-prefix-map / -fdebug-prefix-map) during release archives.",
    )
}

internal fun checkIosInfoPlistAts(
    plists: List<Pair<String, ApplePlistSummary>>,
    policy: ReleaseGuardPolicy,
): AuditFinding = when {
    !policy.ios.forbidArbitraryLoads && !policy.ios.forbidAtsHttpExceptions -> AuditFinding(
        checkId = "ios.plist.ats",
        target = AuditTarget.IOS,
        title = "iOS App Transport Security (ATS)",
        status = CheckStatus.SKIP,
        severity = CheckSeverity.MEDIUM,
        weight = 15,
        summary = "Info.plist ATS check disabled by policy.",
    )
    plists.isEmpty() -> AuditFinding(
        checkId = "ios.plist.ats",
        target = AuditTarget.IOS,
        title = "iOS App Transport Security (ATS)",
        status = CheckStatus.SKIP,
        severity = CheckSeverity.MEDIUM,
        weight = 15,
        summary = "No Info.plist provided or present beside the Mach-O binary.",
    )
    else -> {
        val issues = buildList {
            for ((name, summary) in plists) {
                if (policy.ios.forbidArbitraryLoads && summary.allowsArbitraryLoads) add("$name:NSAllowsArbitraryLoads=true")
                if (policy.ios.forbidAtsHttpExceptions) {
                    summary.insecureExceptionDomains.forEach { domain -> add("$name:NSExceptionAllowsInsecureHTTPLoads($domain)") }
                }
            }
        }
        val passed = issues.isEmpty()
        AuditFinding(
            checkId = "ios.plist.ats",
            target = AuditTarget.IOS,
            title = "iOS App Transport Security (ATS)",
            status = if (passed) CheckStatus.PASS else CheckStatus.FAIL,
            severity = CheckSeverity.MEDIUM,
            weight = 15,
            summary = if (passed) {
                "Info.plist (XML/bplist00) keeps App Transport Security strictly enabled."
            } else {
                "Insecure App Transport Security override(s) found in Info.plist."
            },
            evidence = issues.take(10),
            remediation = "Remove NSAllowsArbitraryLoads and NSExceptionAllowsInsecureHTTPLoads from release Info.plist.",
        )
    }
}

internal fun checkIosProvisioningProfile(profile: ApplePlistSummary?, policy: ReleaseGuardPolicy): AuditFinding = when {
    !policy.ios.forbidDebugProvisioningProfile || profile == null -> AuditFinding(
        checkId = "ios.ipa.provisioning",
        target = AuditTarget.IOS,
        title = "iOS IPA provisioning profile release posture",
        status = CheckStatus.SKIP,
        severity = CheckSeverity.CRITICAL,
        weight = 15,
        summary = "No embedded.mobileprovision present or check disabled.",
    )
    profile.getTaskAllow -> AuditFinding(
        checkId = "ios.ipa.provisioning",
        target = AuditTarget.IOS,
        title = "iOS IPA provisioning profile release posture",
        status = CheckStatus.FAIL,
        severity = CheckSeverity.CRITICAL,
        weight = 15,
        summary = "embedded.mobileprovision enables get-task-allow=true (allows debugger attachment in release!).",
        evidence = listOf("embedded.mobileprovision:get-task-allow=true"),
        remediation = "Sign release IPAs with an App Store / Distribution provisioning profile where get-task-allow is false.",
    )
    profile.hasProvisionedDevices -> AuditFinding(
        checkId = "ios.ipa.provisioning",
        target = AuditTarget.IOS,
        title = "iOS IPA provisioning profile release posture",
        status = CheckStatus.WARN,
        severity = CheckSeverity.MEDIUM,
        weight = 15,
        summary = "embedded.mobileprovision includes ProvisionedDevices (ad-hoc/development profile rather than App Store).",
        evidence = listOf("embedded.mobileprovision:ProvisionedDevices"),
        remediation = "Export App Store release IPAs using an App Store Distribution profile.",
    )
    else -> AuditFinding(
        checkId = "ios.ipa.provisioning",
        target = AuditTarget.IOS,
        title = "iOS IPA provisioning profile release posture",
        status = CheckStatus.PASS,
        severity = CheckSeverity.CRITICAL,
        weight = 15,
        summary = "embedded.mobileprovision disables get-task-allow and is suitable for release distribution.",
    )
}

internal fun checkIosPrivacyManifest(hasPrivacyManifest: Boolean, policy: ReleaseGuardPolicy): AuditFinding = when {
    !policy.ios.requirePrivacyManifest -> AuditFinding(
        checkId = "ios.plist.privacy_manifest",
        target = AuditTarget.IOS,
        title = "iOS PrivacyInfo.xcprivacy present",
        status = CheckStatus.SKIP,
        severity = CheckSeverity.LOW,
        weight = 5,
        summary = "PrivacyInfo.xcprivacy requirement not enabled in policy.",
    )
    hasPrivacyManifest -> AuditFinding(
        checkId = "ios.plist.privacy_manifest",
        target = AuditTarget.IOS,
        title = "iOS PrivacyInfo.xcprivacy present",
        status = CheckStatus.PASS,
        severity = CheckSeverity.LOW,
        weight = 5,
        summary = "PrivacyInfo.xcprivacy bundle manifest found.",
    )
    else -> AuditFinding(
        checkId = "ios.plist.privacy_manifest",
        target = AuditTarget.IOS,
        title = "iOS PrivacyInfo.xcprivacy present",
        status = CheckStatus.WARN,
        severity = CheckSeverity.LOW,
        weight = 5,
        summary = "PrivacyInfo.xcprivacy is missing from iOS bundle.",
        remediation = "Include PrivacyInfo.xcprivacy declaring required-reason API usage for App Store compliance.",
    )
}

internal fun checkIosSecrets(
    binaries: List<Pair<String, ByteArray>>,
    plists: List<Pair<String, ApplePlistSummary>>,
    policy: ReleaseGuardPolicy,
): AuditFinding {
    if (!policy.secrets.enabled) {
        return AuditFinding(
            checkId = "ios.secrets.scan",
            target = AuditTarget.IOS,
            title = "iOS binary secret scan",
            status = CheckStatus.SKIP,
            severity = CheckSeverity.CRITICAL,
            weight = 15,
            summary = "Secret scanning disabled by policy.",
        )
    }
    val matches = buildList {
        binaries.forEach { (name, bytes) -> addAll(SecretScanner.scanSecrets(name, IdentifierHeuristics.extractPrintableStrings(bytes), policy.secrets)) }
        plists.forEach { (name, plist) -> addAll(SecretScanner.scanSecrets(name, plist.stringValues, policy.secrets)) }
    }
    val passed = matches.isEmpty()
    return AuditFinding(
        checkId = "ios.secrets.scan",
        target = AuditTarget.IOS,
        title = "iOS binary secret scan",
        status = if (passed) CheckStatus.PASS else CheckStatus.FAIL,
        severity = CheckSeverity.CRITICAL,
        weight = 15,
        summary = if (passed) {
            "No high-confidence private keys or secret tokens found in iOS artifact."
        } else {
            "Found ${matches.size} high-confidence secret or forbidden endpoint match(es) in iOS artifact."
        },
        evidence = matches.take(8).map { "${it.ruleName} @ ${it.location} (${it.redactedPreview})" },
        remediation = "Never bundle private keys or privileged tokens inside native iOS frameworks or IPAs.",
    )
}

private fun matchesIosProjectHint(symbol: String, policy: ReleaseGuardPolicy): Boolean {
    val lower = symbol.lowercase(Locale.ROOT)
    val kwHit = policy.projectKeywords.any { kw -> kw.isNotBlank() && kw.lowercase(Locale.ROOT) in lower }
    val pkgHit = policy.projectPackages.any { pkg ->
        val clean = pkg.trim().lowercase(Locale.ROOT)
        clean.isNotEmpty() && (clean in lower || clean.replace('.', '_') in lower)
    }
    return kwHit || pkgHit
}

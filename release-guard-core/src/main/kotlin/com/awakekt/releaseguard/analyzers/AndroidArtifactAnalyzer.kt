/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.analyzers

import com.awakekt.releaseguard.io.BinaryReadLimits
import com.awakekt.releaseguard.io.ZipReadBudget
import com.awakekt.releaseguard.model.AuditFinding
import com.awakekt.releaseguard.model.AuditTarget
import com.awakekt.releaseguard.model.CheckSeverity
import com.awakekt.releaseguard.model.CheckStatus
import com.awakekt.releaseguard.model.ReleaseGuardPolicy
import java.io.File
import java.util.Locale
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

/** Inputs for auditing an Android release `.apk` or Android App Bundle (`.aab`). */
public data class AndroidAuditInput(
    public val artifactFile: File,
    public val mappingFile: File? = null,
)

/**
 * Audits Android release APKs and AABs for R8 DEX obfuscation, `@kotlin.Metadata` leaks,
 * `AndroidManifest.xml` flags, exported components, `network_security_config.xml`, v2/v3 release
 * signing, native ELF `.so` hardening (incl. Android 15+ 16 KB alignment), debug/sensitive files,
 * asset encryption, and secrets.
 */
public object AndroidArtifactAnalyzer {
    private class ScanAccumulator {
        val dexSummaries: MutableList<DexSummary> = mutableListOf()
        var manifestFlags: AndroidManifestFlags = AndroidManifestFlags()
        val netConfigs: MutableList<Pair<String, NetworkSecurityConfigSummary>> = mutableListOf()
        val elfResults: MutableList<Pair<String, ElfInspectionResult>> = mutableListOf()
        val entryNames: MutableList<String> = mutableListOf()
        val sensitiveFiles: MutableList<String> = mutableListOf()
        val bundleChecks: MutableList<BundleHeaderCheck> = mutableListOf()
        val secretMatches: MutableList<SecretMatch> = mutableListOf()
    }

    /** Audits [input] (`.apk` or `.aab`) under [policy]. */
    public fun analyze(
        input: AndroidAuditInput,
        policy: ReleaseGuardPolicy,
        limits: BinaryReadLimits = BinaryReadLimits(),
    ): AnalyzerOutput {
        val file = input.artifactFile
        if (!file.isFile) return missingAndroidArtifactOutput(file)

        val isAab = file.name.endsWith(".aab", ignoreCase = true)
        val scan = scanArchive(file, policy, limits)
        val signing = ApkCertificateInspector.inspect(file, limits)
        val metrics = linkedMapOf(
            "android.artifactKind" to if (isAab) "aab" else "apk",
            "android.artifactBytes" to file.length().toString(),
            "android.dexFileCount" to scan.dexSummaries.size.toString(),
            "android.nativeElfCount" to scan.elfResults.size.toString(),
        )
        scan.manifestFlags.packageName?.let { metrics["android.packageName"] = it }
        scan.manifestFlags.targetSdkVersion?.let { metrics["android.targetSdkVersion"] = it.toString() }

        val findings = listOf(
            checkDexObfuscation(scan.dexSummaries, policy, metrics),
            ForbiddenClassInspector.check(
                checkId = "android.obfuscation.forbidden_classes",
                target = AuditTarget.ANDROID,
                compiledInternalNames = scan.dexSummaries.flatMap { it.definedClasses },
                mappingFile = input.mappingFile,
                forbiddenClasses = policy.android.forbiddenClasses,
            ),
            checkAndroidKotlinMetadata(scan.dexSummaries, policy),
            checkAndroidManifestDebuggable(scan.manifestFlags, policy),
            checkAndroidBackupAndCleartext(scan.manifestFlags, policy),
            checkAndroidTestOnlyAndSdk(scan.manifestFlags, policy),
            checkAndroidExportedComponents(scan.manifestFlags, policy, metrics),
            checkAndroidNetworkSecurityConfig(scan.netConfigs, policy),
            checkAndroidSigningCertificate(signing, isAab, policy, metrics),
            checkNativeElfHardening(scan.elfResults, policy, metrics),
            checkAndroidForbiddenArtifacts(scan.entryNames, scan.sensitiveFiles, input.mappingFile, policy),
            AssetEncryptionInspector.toFinding("android.assets.encryption", AuditTarget.ANDROID, scan.bundleChecks, policy.assetEncryption),
            checkAndroidSecrets(scan.secretMatches, policy),
        )
        return AnalyzerOutput(findings = findings, metrics = metrics)
    }

    private fun scanArchive(file: File, policy: ReleaseGuardPolicy, limits: BinaryReadLimits): ScanAccumulator {
        val acc = ScanAccumulator()
        val budget = ZipReadBudget(limits)
        ZipFile(file).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                budget.recordEntry(entry.name)
                if (!entry.isDirectory) scanArchiveEntry(zip, entry, policy, budget, acc)
            }
        }
        return acc
    }

    private fun scanArchiveEntry(
        zip: ZipFile,
        entry: ZipEntry,
        policy: ReleaseGuardPolicy,
        budget: ZipReadBudget,
        acc: ScanAccumulator,
    ) {
        val name = entry.name
        acc.entryNames += name
        if (policy.android.forbidSensitiveBundledFiles && SecretScanner.isSensitivePackagedFile(name)) {
            acc.sensitiveFiles += name
        }
        when {
            name == "AndroidManifest.xml" || name == "base/manifest/AndroidManifest.xml" ->
                acc.manifestFlags = BinaryXmlManifestInspector.parse(budget.readEntryBytes(zip, entry))
            isDexEntry(name) -> scanDexEntry(zip, entry, policy, budget, acc)
            name.endsWith("network_security_config.xml", ignoreCase = true) ->
                acc.netConfigs += name to NetworkSecurityConfigInspector.parse(budget.readEntryBytes(zip, entry))
            isCompiledResXml(name, entry.size) -> scanCompiledResXml(zip, entry, budget, acc)
            policy.android.inspectNativeElfLibraries && isNativeSoEntry(name) -> scanElfEntry(zip, entry, budget, acc)
            policy.assetEncryption.enabled && AssetEncryptionInspector.matchesBundleExtension(name, policy.assetEncryption) ->
                acc.bundleChecks += AssetEncryptionInspector.inspectAwkbHeader(name, budget.readEntryBytes(zip, entry, 64L))
            policy.secrets.enabled && shouldScanAssetEntry(name, entry.size) -> {
                val strings = IdentifierHeuristics.extractPrintableStrings(budget.readEntryBytes(zip, entry, MAX_ASSET_SCAN_BYTES))
                acc.secretMatches += SecretScanner.scanSecrets(name, strings, policy.secrets)
            }
        }
    }

    private fun scanDexEntry(
        zip: ZipFile,
        entry: ZipEntry,
        policy: ReleaseGuardPolicy,
        budget: ZipReadBudget,
        acc: ScanAccumulator,
    ) {
        val summary = DexInspector.parse(budget.readEntryBytes(zip, entry))
        acc.dexSummaries += summary
        if (policy.secrets.enabled) {
            acc.secretMatches += SecretScanner.scanSecrets(entry.name, summary.strings, policy.secrets)
        }
    }

    private fun scanElfEntry(zip: ZipFile, entry: ZipEntry, budget: ZipReadBudget, acc: ScanAccumulator) {
        val bytes = budget.readEntryBytes(zip, entry)
        if (ElfBinaryInspector.isElf(bytes)) {
            acc.elfResults += entry.name to ElfBinaryInspector.parse(bytes)
        }
    }

    private fun scanCompiledResXml(zip: ZipFile, entry: ZipEntry, budget: ZipReadBudget, acc: ScanAccumulator) {
        val bytes = budget.readEntryBytes(zip, entry, MAX_RES_XML_BYTES)
        if (NetworkSecurityConfigInspector.isNetworkSecurityConfig(bytes)) {
            acc.netConfigs += entry.name to NetworkSecurityConfigInspector.parse(bytes)
        }
    }

    private fun checkDexObfuscation(
        dexSummaries: List<DexSummary>,
        policy: ReleaseGuardPolicy,
        metrics: MutableMap<String, String>,
    ): AuditFinding {
        if (dexSummaries.isEmpty()) {
            return AuditFinding(
                checkId = "android.obfuscation.readability",
                target = AuditTarget.ANDROID,
                title = "Android DEX R8 obfuscation",
                status = CheckStatus.FAIL,
                severity = CheckSeverity.HIGH,
                weight = 20,
                summary = "Archive contains no classes*.dex files to verify.",
                remediation = "Verify the Android release APK/AAB build produced valid DEX files.",
            )
        }
        val (ownNames, keptProjectClasses) = collectOwnDexNames(dexSummaries, policy)
        val stats = IdentifierHeuristics.computeReadability(ownNames, policy.projectKeywords, policy.projectPackages)
        metrics["android.dexReadability"] = String.format(Locale.ROOT, "%.4f", stats.score)
        metrics["android.keptProjectClasses"] = keptProjectClasses.size.toString()

        val threshold = policy.android.maxOwnReadability
        val classLimit = policy.android.maxKeptProjectClasses
        val status = when {
            stats.score > threshold -> CheckStatus.FAIL
            policy.projectPackages.isNotEmpty() && keptProjectClasses.size > classLimit -> CheckStatus.WARN
            else -> CheckStatus.PASS
        }
        return AuditFinding(
            checkId = "android.obfuscation.readability",
            target = AuditTarget.ANDROID,
            title = "Android DEX R8 obfuscation",
            status = status,
            severity = CheckSeverity.HIGH,
            weight = 20,
            summary = String.format(
                Locale.ROOT,
                "Non-framework DEX readability is %.3f (%d/%d recognisable; threshold %.3f); %d project class(es) kept (limit %d).",
                stats.score,
                stats.recognisableCount,
                stats.totalCount,
                threshold,
                keptProjectClasses.size,
                classLimit,
            ),
            evidence = (keptProjectClasses.take(5) + stats.examples).distinct().take(10),
            remediation = "Enable R8 release minification (isMinifyEnabled = true), -repackageclasses '', and narrow proguard-rules.pro.",
        )
    }

    private fun checkNativeElfHardening(
        elfResults: List<Pair<String, ElfInspectionResult>>,
        policy: ReleaseGuardPolicy,
        metrics: MutableMap<String, String>,
    ): AuditFinding {
        if (!policy.android.inspectNativeElfLibraries || elfResults.isEmpty()) {
            return AuditFinding(
                checkId = "android.native.elf_hardening",
                target = AuditTarget.ANDROID,
                title = "Android native .so (ELF) hardening & 16 KB alignment",
                status = CheckStatus.SKIP,
                severity = CheckSeverity.HIGH,
                weight = 12,
                summary = if (!policy.android.inspectNativeElfLibraries) {
                    "Native ELF inspection disabled by policy."
                } else {
                    "No native .so libraries found inside archive."
                },
            )
        }
        val issues = elfResults.flatMap { (path, elf) -> collectAndroidElfIssues(path, elf, policy) }
        metrics["android.elfIssues"] = issues.size.toString()
        val passed = issues.isEmpty()
        return AuditFinding(
            checkId = "android.native.elf_hardening",
            target = AuditTarget.ANDROID,
            title = "Android native .so (ELF) hardening & 16 KB alignment",
            status = if (passed) CheckStatus.PASS else CheckStatus.FAIL,
            severity = CheckSeverity.HIGH,
            weight = 12,
            summary = if (passed) {
                "All ${elfResults.size} native .so library(s) passed Full RELRO, NX, PIE, symbol-strip, and 16 KB alignment checks."
            } else {
                "Found ${issues.size} native ELF hardening/alignment issue(s) across ${elfResults.size} .so library(s)."
            },
            evidence = issues.take(10),
            remediation = "Compile JNI libraries with -Wl,-z,relro,-z,now,-z,noexecstack,-z,max-page-size=16384 and strip release .so files.",
        )
    }
}

private fun collectOwnDexNames(
    dexSummaries: List<DexSummary>,
    policy: ReleaseGuardPolicy,
): Pair<List<String>, List<String>> {
    val ownNames = mutableListOf<String>()
    val keptProjectClasses = mutableListOf<String>()
    for (dex in dexSummaries) {
        for (internal in dex.definedClasses) {
            if (DexInspector.isFrameworkClass(internal)) continue
            if (IdentifierHeuristics.matchesProjectPackage(internal, policy.projectPackages)) {
                keptProjectClasses += internal
            }
            ownNames += internal.substringAfterLast('/').substringAfterLast('$').ifEmpty { internal }
            dex.declaredMembersByClass[internal].orEmpty()
                .filterNot { it in IdentifierHeuristics.JDK_STANDARD_MEMBERS }
                .forEach(ownNames::add)
        }
    }
    return ownNames to keptProjectClasses
}

private fun isDexEntry(name: String): Boolean =
    (name.startsWith("classes") && name.endsWith(".dex")) ||
        (name.contains("/dex/classes") && name.endsWith(".dex"))

private fun isNativeSoEntry(name: String): Boolean =
    name.endsWith(".so", ignoreCase = true) && (name.startsWith("lib/") || name.contains("/lib/"))

private fun shouldScanAssetEntry(name: String, size: Long): Boolean {
    val isAsset = name.startsWith("assets/") || name.contains("/assets/")
    val isText = name.endsWith(".json") || name.endsWith(".txt") || name.endsWith(".properties") || name.endsWith(".xml")
    return size <= MAX_ASSET_SCAN_BYTES && isAsset && isText
}

private fun isCompiledResXml(name: String, size: Long): Boolean =
    size in 1..MAX_RES_XML_BYTES &&
        (name.startsWith("res/") || name.startsWith("base/res/")) &&
        name.endsWith(".xml", ignoreCase = true)

private const val MAX_ASSET_SCAN_BYTES: Long = 2L * 1024L * 1024L
private const val MAX_RES_XML_BYTES: Long = 64L * 1024L

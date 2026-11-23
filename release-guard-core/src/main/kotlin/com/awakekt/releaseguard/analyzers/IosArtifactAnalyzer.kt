/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.analyzers

import com.awakekt.releaseguard.io.BinaryReadLimits
import com.awakekt.releaseguard.io.BoundedBinaryIo
import com.awakekt.releaseguard.io.ZipReadBudget
import com.awakekt.releaseguard.model.ReleaseGuardPolicy
import java.io.File
import java.util.zip.ZipFile

/** Inputs for auditing an iOS `.framework`, `.xcframework`, `.ipa`, or standalone Mach-O binary. */
public data class IosAuditInput(
    public val artifactPath: File,
    public val infoPlistFile: File? = null,
)

/**
 * Audits iOS `.framework`, `.xcframework`, `.ipa`, and Mach-O binaries for `__DWARF` debug
 * segments, unstripped symbols, `MH_PIE` (ASLR), `LC_CODE_SIGNATURE`, leaked workstation paths,
 * XML and binary `bplist00` `Info.plist` ATS settings, `embedded.mobileprovision` debug
 * entitlements (`get-task-allow`), privacy manifests, and secrets.
 */
public object IosArtifactAnalyzer {
    private data class IosCollectedArtifacts(
        val isIpa: Boolean,
        val binaries: List<Pair<String, ByteArray>>,
        val plists: List<Pair<String, ApplePlistSummary>>,
        val provisioningProfile: ApplePlistSummary?,
        val hasPrivacyManifest: Boolean,
    )

    /** Audits [input] under [policy]. */
    public fun analyze(
        input: IosAuditInput,
        policy: ReleaseGuardPolicy,
        limits: BinaryReadLimits = BinaryReadLimits(),
    ): AnalyzerOutput {
        val collected = collectArtifacts(input, limits)
        if (collected.binaries.isEmpty()) return missingIosBinaryOutput(input.artifactPath)

        val parsedMachOs = collected.binaries.map { (name, bytes) -> name to MachOInspector.parse(bytes) }
        val metrics = linkedMapOf(
            "ios.artifactKind" to if (collected.isIpa) "ipa" else "framework",
            "ios.binaryCount" to parsedMachOs.size.toString(),
            "ios.sliceCount" to parsedMachOs.sumOf { it.second.sliceCount }.toString(),
            "ios.totalSymbols" to parsedMachOs.sumOf { it.second.totalSymbolCount }.toString(),
            "ios.debugStabSymbols" to parsedMachOs.sumOf { it.second.debugStabSymbolCount }.toString(),
            "ios.hasDwarf" to parsedMachOs.any { it.second.hasDwarfSegment }.toString(),
        )

        val findings = listOf(
            checkIosDwarfAbsent(parsedMachOs, policy),
            checkIosSymbolsStripped(parsedMachOs, policy, metrics),
            checkIosMachOHardening(parsedMachOs, collected.isIpa, policy),
            checkIosLeakedBuildPaths(collected.binaries, policy),
            checkIosInfoPlistAts(collected.plists, policy),
            checkIosProvisioningProfile(collected.provisioningProfile, policy),
            checkIosPrivacyManifest(collected.hasPrivacyManifest, policy),
            checkIosSecrets(collected.binaries, collected.plists, policy),
        )
        return AnalyzerOutput(findings = findings, metrics = metrics)
    }

    private fun collectArtifacts(input: IosAuditInput, limits: BinaryReadLimits): IosCollectedArtifacts {
        val target = input.artifactPath
        return when {
            target.isFile && target.name.endsWith(".ipa", ignoreCase = true) -> collectFromIpa(target, input.infoPlistFile, limits)
            target.isDirectory && target.name.endsWith(".xcframework", ignoreCase = true) -> collectFromXcFramework(target, input.infoPlistFile, limits)
            else -> collectFromFrameworkOrFile(target, input.infoPlistFile, limits)
        }
    }

    private fun collectFromIpa(ipa: File, plistOverride: File?, limits: BinaryReadLimits): IosCollectedArtifacts {
        val binaries = mutableListOf<Pair<String, ByteArray>>()
        val plists = mutableListOf<Pair<String, ApplePlistSummary>>()
        var provisioning: ApplePlistSummary? = null
        var hasPrivacy = false
        val budget = ZipReadBudget(limits)

        ZipFile(ipa).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                budget.recordEntry(entry.name)
                if (entry.isDirectory) continue
                val name = entry.name
                when {
                    name.endsWith("/PrivacyInfo.xcprivacy") -> hasPrivacy = true
                    name.endsWith("/embedded.mobileprovision") -> provisioning = BinaryPlistInspector.parse(budget.readEntryBytes(zip, entry))
                    isAppRootInfoPlist(name) -> plists += name to BinaryPlistInspector.parse(budget.readEntryBytes(zip, entry))
                    isLikelyAppMachO(name) -> {
                        val bytes = budget.readEntryBytes(zip, entry)
                        if (MachOInspector.isMachO(bytes)) binaries += name to bytes
                    }
                }
            }
        }
        plistOverride?.takeIf { it.isFile }?.let { file ->
            plists += file.name to BinaryPlistInspector.parse(BoundedBinaryIo.readFileBounded(file))
        }
        return IosCollectedArtifacts(true, binaries, plists, provisioning, hasPrivacy)
    }

    private fun collectFromXcFramework(xcfw: File, plistOverride: File?, limits: BinaryReadLimits): IosCollectedArtifacts {
        val frameworks = xcfw.walkTopDown()
            .filter { it.isDirectory && it.name.endsWith(".framework", ignoreCase = true) }
            .sortedBy { it.relativeTo(xcfw).invariantSeparatorsPath }
            .toList()
        val binaries = mutableListOf<Pair<String, ByteArray>>()
        val plists = mutableListOf<Pair<String, ApplePlistSummary>>()
        var hasPrivacy = xcfw.walkTopDown().any { it.isFile && it.name == "PrivacyInfo.xcprivacy" }

        for (fw in frameworks) {
            val sub = collectFromFrameworkOrFile(fw, null, limits)
            binaries += sub.binaries.map { (n, b) -> "${fw.relativeTo(xcfw).invariantSeparatorsPath}/$n" to b }
            plists += sub.plists
            if (sub.hasPrivacyManifest) hasPrivacy = true
        }
        plistOverride?.takeIf { it.isFile }?.let { file ->
            plists += file.name to BinaryPlistInspector.parse(BoundedBinaryIo.readFileBounded(file))
        }
        return IosCollectedArtifacts(false, binaries, plists, null, hasPrivacy)
    }

    private fun collectFromFrameworkOrFile(target: File, plistOverride: File?, limits: BinaryReadLimits): IosCollectedArtifacts {
        val binary = resolveBinaryFile(target)
        val binaries = if (binary != null && binary.isFile) {
            val bytes = BoundedBinaryIo.readFileBounded(binary, limits.maxSingleFileBytes)
            if (MachOInspector.isMachO(bytes)) listOf(binary.name to bytes) else emptyList()
        } else {
            emptyList()
        }
        val plistFile = plistOverride ?: target.resolve("Info.plist").takeIf { it.isFile }
        val plists = if (plistFile != null && plistFile.isFile) {
            listOf(plistFile.name to BinaryPlistInspector.parse(BoundedBinaryIo.readFileBounded(plistFile)))
        } else {
            emptyList()
        }
        val hasPrivacy = target.isDirectory && target.walkTopDown().any { it.isFile && it.name == "PrivacyInfo.xcprivacy" }
        return IosCollectedArtifacts(false, binaries, plists, null, hasPrivacy)
    }

    private fun resolveBinaryFile(target: File): File? = when {
        target.isFile -> target
        !target.isDirectory -> null
        else -> {
            val baseName = target.name.removeSuffix(".framework")
            target.resolve(baseName).takeIf { it.isFile } ?: target.listFiles()?.firstOrNull { file ->
                file.isFile && !file.name.endsWith(".plist") && !file.name.endsWith(".h") && file.length() >= 32L
            }
        }
    }

    private fun isAppRootInfoPlist(entryName: String): Boolean =
        Regex("""^Payload/[^/]+\.app/Info\.plist$""").matches(entryName)

    private fun isLikelyAppMachO(entryName: String): Boolean {
        val fileName = entryName.substringAfterLast('/')
        val isAppBinary = Regex("""^Payload/[^/]+\.app/[^/]+$""").matches(entryName) && '.' !in fileName
        val isFrameworkBinary = Regex("""^Payload/[^/]+\.app/Frameworks/([^/]+)\.framework/\1$""").matches(entryName)
        return isAppBinary || isFrameworkBinary
    }
}

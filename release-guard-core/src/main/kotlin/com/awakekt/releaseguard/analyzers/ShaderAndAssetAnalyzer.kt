/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.analyzers

import com.awakekt.releaseguard.io.BinaryReadLimits
import com.awakekt.releaseguard.io.BoundedBinaryIo
import com.awakekt.releaseguard.io.ZipReadBudget
import com.awakekt.releaseguard.model.AssetEncryptionPolicy
import com.awakekt.releaseguard.model.AuditFinding
import com.awakekt.releaseguard.model.AuditTarget
import com.awakekt.releaseguard.model.CheckSeverity
import com.awakekt.releaseguard.model.CheckStatus
import com.awakekt.releaseguard.model.ReleaseGuardPolicy
import java.io.File
import java.util.Locale
import java.util.zip.ZipFile

/** Inputs for generic packaged asset, 3D model, encrypted container, and shader audits. */
public data class AssetAuditInput(
    public val assetDirectories: List<File> = emptyList(),
    public val shaderDirectories: List<File> = emptyList(),
    public val archiveFiles: List<File> = emptyList(),
)

/**
 * Engine-agnostic analyzer verifying:
 * 1. Raw/unencrypted 3D model leaks (by extension and `glTF`/`.glb` + `FBX` binary magic bytes).
 * 2. Encrypted content container headers (`.awkb` v2, custom `ContainerHeaderRule`, and entropy).
 * 3. Khronos SPIR-V (`.spv`) debug opcode stripping (`OpSource`, `OpName`, `OpLine`, `OpString`).
 * 4. Raw shader source leaks (`.glsl`/`.vert`/`.frag`/`.hlsl`/`.asl`) and optional WGSL comment checks.
 */
public object ShaderAndAssetAnalyzer {
    private val glbMagic = byteArrayOf('g'.code.toByte(), 'l'.code.toByte(), 'T'.code.toByte(), 'F'.code.toByte())
    private val fbxMagic = "Kaydara FBX Binary  \u0000".toByteArray(Charsets.US_ASCII)
    private val wgslCommentRegex = Regex("""(?://[^\n]*|/\*[\s\S]*?\*/)""")
    private const val MAGIC_SNIFF_BYTES = 32
    private const val ENTROPY_SAMPLE_BYTES = 65_536

    /** Runs enabled generic asset and shader checks over [input] under [policy]. */
    public fun analyze(
        input: AssetAuditInput,
        policy: ReleaseGuardPolicy,
        limits: BinaryReadLimits = BinaryReadLimits(),
    ): AnalyzerOutput {
        val metrics = linkedMapOf<String, String>()
        val findings = buildList {
            if (policy.assetSecurity.enabled) {
                add(checkRawModelLeaks(input, policy, limits, metrics))
            }
            if (policy.assetEncryption.enabled) {
                add(checkEncryptedContainers(input, policy.assetEncryption, limits, metrics))
            }
            if (policy.shaderSecurity.enabled) {
                add(checkSpirvDebugInfo(input, policy, limits, metrics))
                add(checkShaderSourceExposure(input, policy, limits, metrics))
            }
        }
        return AnalyzerOutput(findings = findings, metrics = metrics)
    }

    private fun checkRawModelLeaks(
        input: AssetAuditInput,
        policy: ReleaseGuardPolicy,
        limits: BinaryReadLimits,
        metrics: MutableMap<String, String>,
    ): AuditFinding {
        val allowed = policy.assetSecurity.allowedPlaintextPathRegexes.map(::Regex)
        val forbiddenExts = policy.assetSecurity.forbidRawModelExtensions.map { it.lowercase(Locale.ROOT).removePrefix(".") }.toSet()
        val leaks = mutableListOf<String>()
        var scanned = 0

        forEachItem(input.assetDirectories, input.archiveFiles, limits) { path, headerReader ->
            if (allowed.any { it.containsMatchIn(path) }) return@forEachItem
            scanned++
            val ext = path.substringAfterLast('.', "").lowercase(Locale.ROOT)
            if (ext in forbiddenExts) {
                leaks += "$path (raw .$ext extension)"
                return@forEachItem
            }
            if (policy.assetSecurity.sniffModelMagicBytes) {
                val magicKind = sniffModelMagic(headerReader(MAGIC_SNIFF_BYTES))
                if (magicKind != null) leaks += "$path ($magicKind binary magic)"
            }
        }
        metrics["assets.scannedFiles"] = scanned.toString()
        metrics["assets.rawModelLeaks"] = leaks.size.toString()

        val passed = leaks.isEmpty()
        return AuditFinding(
            checkId = "assets.models.unencrypted_leak",
            target = AuditTarget.ASSETS_AND_SHADERS,
            title = "Unencrypted 3D model files absent",
            status = if (passed) CheckStatus.PASS else CheckStatus.FAIL,
            severity = CheckSeverity.HIGH,
            weight = 15,
            summary = if (passed) {
                "No unencrypted 3D model files or raw glTF/FBX binaries found across $scanned file(s)."
            } else {
                "Found ${leaks.size} unencrypted 3D model file(s) or raw model binaries in release artifacts."
            },
            evidence = leaks.take(10),
            remediation = "Pack 3D models into encrypted release bundles and exclude raw .glb/.gltf/.fbx files from public folders.",
        )
    }

    private fun checkEncryptedContainers(
        input: AssetAuditInput,
        policy: AssetEncryptionPolicy,
        limits: BinaryReadLimits,
        metrics: MutableMap<String, String>,
    ): AuditFinding {
        val checks = mutableListOf<BundleHeaderCheck>()
        forEachItem(input.assetDirectories, input.archiveFiles, limits) { path, reader ->
            if (!AssetEncryptionInspector.matchesAnyContainer(path, policy)) return@forEachItem
            val sampleBytes = if (policy.minContainerEntropy != null) ENTROPY_SAMPLE_BYTES else 64
            checks += AssetEncryptionInspector.inspectContainer(path, reader(sampleBytes), policy)
        }
        metrics["assets.checkedContainers"] = checks.size.toString()
        metrics["assets.unencryptedContainers"] = checks.count { !it.isEncrypted }.toString()
        return AssetEncryptionInspector.toFinding(
            checkId = "assets.containers.encryption",
            target = AuditTarget.ASSETS_AND_SHADERS,
            checks = checks,
            policy = policy,
        )
    }

    private fun checkSpirvDebugInfo(
        input: AssetAuditInput,
        policy: ReleaseGuardPolicy,
        limits: BinaryReadLimits,
        metrics: MutableMap<String, String>,
    ): AuditFinding {
        if (!policy.shaderSecurity.forbidSpirvDebugInfo) {
            return AuditFinding(
                checkId = "shaders.spirv.debug_info",
                target = AuditTarget.ASSETS_AND_SHADERS,
                title = "SPIR-V shader debug info stripped",
                status = CheckStatus.SKIP,
                severity = CheckSeverity.MEDIUM,
                weight = 10,
                summary = "SPIR-V debug inspection disabled by policy.",
            )
        }
        val allowed = policy.shaderSecurity.allowedShaderPathRegexes.map(::Regex)
        val dirs = (input.shaderDirectories + input.assetDirectories).distinct()
        var spirvCount = 0
        val unstripped = mutableListOf<String>()

        forEachItem(dirs, input.archiveFiles, limits) { path, reader ->
            if (allowed.any { it.containsMatchIn(path) }) return@forEachItem
            val ext = path.substringAfterLast('.', "").lowercase(Locale.ROOT)
            val header = reader(8)
            if (ext != "spv" && !SpirvShaderInspector.isSpirv(header)) return@forEachItem
            val fullBytes = reader(limits.maxZipEntryBytes.coerceAtMost(Int.MAX_VALUE.toLong()).toInt())
            val inspected = SpirvShaderInspector.inspect(path, fullBytes)
            if (!inspected.isValidSpirv) return@forEachItem
            spirvCount++
            if (inspected.debugInstructionCount > 0) {
                val sample = inspected.leakedDebugStrings.firstOrNull()?.let { " e.g. '$it'" }.orEmpty()
                unstripped += "$path (${inspected.debugOpcodeNames.joinToString()}$sample)"
            }
        }
        metrics["shaders.spirvCount"] = spirvCount.toString()
        metrics["shaders.spirvUnstrippedCount"] = unstripped.size.toString()
        return buildSpirvFinding(spirvCount, unstripped)
    }

    private fun buildSpirvFinding(spirvCount: Int, unstripped: List<String>): AuditFinding = when {
        spirvCount == 0 -> AuditFinding(
            checkId = "shaders.spirv.debug_info",
            target = AuditTarget.ASSETS_AND_SHADERS,
            title = "SPIR-V shader debug info stripped",
            status = CheckStatus.SKIP,
            severity = CheckSeverity.MEDIUM,
            weight = 10,
            summary = "No SPIR-V (.spv) binaries found to inspect.",
        )
        unstripped.isEmpty() -> AuditFinding(
            checkId = "shaders.spirv.debug_info",
            target = AuditTarget.ASSETS_AND_SHADERS,
            title = "SPIR-V shader debug info stripped",
            status = CheckStatus.PASS,
            severity = CheckSeverity.MEDIUM,
            weight = 10,
            summary = "All $spirvCount SPIR-V shader(s) have OpSource/OpName/OpLine debug opcodes stripped.",
        )
        else -> AuditFinding(
            checkId = "shaders.spirv.debug_info",
            target = AuditTarget.ASSETS_AND_SHADERS,
            title = "SPIR-V shader debug info stripped",
            status = CheckStatus.FAIL,
            severity = CheckSeverity.MEDIUM,
            weight = 10,
            summary = "${unstripped.size} of $spirvCount SPIR-V shader(s) retain debug names or source metadata.",
            evidence = unstripped.take(10),
            remediation = "Strip SPIR-V debug instructions with `strip-spirv`, `stripSpirvShaders`, or `spirv-opt --strip-debug`.",
        )
    }

    private fun checkShaderSourceExposure(
        input: AssetAuditInput,
        policy: ReleaseGuardPolicy,
        limits: BinaryReadLimits,
        metrics: MutableMap<String, String>,
    ): AuditFinding {
        val allowed = policy.shaderSecurity.allowedShaderPathRegexes.map(::Regex)
        val rawExts = policy.shaderSecurity.forbidRawShaderExtensions.map { it.lowercase(Locale.ROOT).removePrefix(".") }.toSet()
        val dirs = (input.shaderDirectories + input.assetDirectories).distinct()
        val issues = mutableListOf<String>()

        forEachItem(dirs, input.archiveFiles, limits) { path, reader ->
            if (allowed.any { it.containsMatchIn(path) }) return@forEachItem
            val ext = path.substringAfterLast('.', "").lowercase(Locale.ROOT)
            if (ext in rawExts) {
                issues += "$path (raw .$ext shader source)"
            } else if (ext == "wgsl" && policy.shaderSecurity.forbidWgslComments) {
                val text = String(reader(limits.maxZipEntryBytes.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()), Charsets.UTF_8)
                if (wgslCommentRegex.containsMatchIn(text)) {
                    issues += "$path (unstripped WGSL comments)"
                }
            }
        }
        metrics["shaders.sourceExposureCount"] = issues.size.toString()

        val passed = issues.isEmpty()
        return AuditFinding(
            checkId = "shaders.source.exposure",
            target = AuditTarget.ASSETS_AND_SHADERS,
            title = "Raw shader source files absent",
            status = if (passed) CheckStatus.PASS else CheckStatus.FAIL,
            severity = CheckSeverity.MEDIUM,
            weight = 10,
            summary = if (passed) {
                "No raw shader source files or forbidden shader comments found."
            } else {
                "Found ${issues.size} raw shader source file(s) or unstripped WGSL comment(s)."
            },
            evidence = issues.take(10),
            remediation = "Ship compiled/stripped shaders in release bundles and exclude raw .glsl/.hlsl/.asl sources.",
        )
    }

    private fun sniffModelMagic(header: ByteArray): String? = when {
        header.size >= 8 && glbMagic.indices.all { header[it] == glbMagic[it] } -> "glTF/GLB"
        header.size >= fbxMagic.size && fbxMagic.indices.all { header[it] == fbxMagic[it] } -> "FBX"
        else -> null
    }

    private fun forEachItem(
        directories: List<File>,
        archives: List<File>,
        limits: BinaryReadLimits,
        visitor: (path: String, readUpTo: (Int) -> ByteArray) -> Unit,
    ) {
        for (dir in directories.filter { it.isDirectory }) {
            dir.walkTopDown().filter { it.isFile }.sortedBy { it.invariantSeparatorsPath }.forEach { file ->
                val rel = file.relativeTo(dir).invariantSeparatorsPath
                visitor(rel) { maxBytes -> BoundedBinaryIo.readFilePrefix(file, maxBytes) }
            }
        }
        val maxCap = limits.maxZipEntryBytes.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
        for (archive in archives.filter { it.isFile }) {
            val budget = ZipReadBudget(limits)
            ZipFile(archive).use { zip ->
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    if (entry.isDirectory) continue
                    budget.recordEntry(entry.name)
                    visitor("${archive.name}!/${entry.name}") { maxBytes ->
                        zip.getInputStream(entry).use { input ->
                            val target = minOf(maxBytes, maxCap)
                            val buf = ByteArray(target)
                            var offset = 0
                            while (offset < target) {
                                val read = input.read(buf, offset, target - offset)
                                if (read <= 0) break
                                offset += read
                            }
                            if (offset == buf.size) buf else buf.copyOf(offset)
                        }
                    }
                }
            }
        }
    }
}

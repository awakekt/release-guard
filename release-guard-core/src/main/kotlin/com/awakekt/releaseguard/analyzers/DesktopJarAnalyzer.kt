/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.analyzers

import com.awakekt.releaseguard.io.BinaryReadLimits
import com.awakekt.releaseguard.io.BoundedBinaryIo
import com.awakekt.releaseguard.io.ZipReadBudget
import com.awakekt.releaseguard.model.AuditFinding
import com.awakekt.releaseguard.model.AuditTarget
import com.awakekt.releaseguard.model.CheckSeverity
import com.awakekt.releaseguard.model.CheckStatus
import com.awakekt.releaseguard.model.ReleaseGuardPolicy
import java.io.File
import java.util.Locale
import java.util.zip.ZipFile

/** Inputs for auditing Desktop JVM release JARs, native desktop libraries, launcher configs, and assets. */
public data class DesktopAuditInput(
    public val gameJarsDirectory: File,
    public val librariesDirectory: File? = null,
    public val mappingFile: File? = null,
    public val nativeLibsDirectory: File? = null,
    public val jpackageAppDirectory: File? = null,
    public val assetDirectory: File? = null,
)

/** Output from a single target analyzer: findings plus key-value telemetry metrics. */
public data class AnalyzerOutput(
    public val findings: List<AuditFinding>,
    public val metrics: Map<String, String> = emptyMap(),
)

/**
 * Audits obfuscated Desktop JVM release JARs, bundled native libraries (PE/ELF/Mach-O), `jpackage`
 * launcher configs, and packaged asset bundles.
 */
public object DesktopJarAnalyzer {
    private val safeSourceFileValues = setOf("SourceFile", "Unknown", "")
    private val jpackageDebugFlagRegex = Regex("""(?i)(?:-agentlib:jdwp|-Xrunjdwp|-Xdebug|(?:^|\s)-ea(?:\s|$))""")

    /** Audits [input] under [policy]. */
    public fun analyze(
        input: DesktopAuditInput,
        policy: ReleaseGuardPolicy,
        limits: BinaryReadLimits = BinaryReadLimits(),
    ): AnalyzerOutput {
        val gameJars = listJars(input.gameJarsDirectory)
        if (gameJars.isEmpty()) return missingJarsOutput(input.gameJarsDirectory)

        val libraryJars = input.librariesDirectory?.let(::listJars).orEmpty()
        val libraryMembers = collectLibraryMembers(gameJars, libraryJars, limits)
        val allClasses = gameJars.flatMap { jar -> ClassFileReader.readJar(jar, limits) }
        val ownJars = if (policy.desktop.ownJarNames.isEmpty()) {
            gameJars
        } else {
            gameJars.filter { it.name in policy.desktop.ownJarNames }.ifEmpty { gameJars }
        }
        val ownClasses = if (ownJars.size == gameJars.size) {
            allClasses
        } else {
            ownJars.flatMap { jar -> ClassFileReader.readJar(jar, limits) }
        }

        val metrics = linkedMapOf(
            "desktop.gameJarCount" to gameJars.size.toString(),
            "desktop.ownJarCount" to ownJars.size.toString(),
            "desktop.classCount" to allClasses.size.toString(),
        )
        val findings = buildList {
            add(checkReadability(ownClasses, libraryMembers, policy, metrics))
            add(checkProjectPackages(ownClasses, policy, metrics))
            add(
                ForbiddenClassInspector.check(
                    checkId = "desktop.obfuscation.forbidden_classes",
                    target = AuditTarget.DESKTOP_JVM,
                    compiledInternalNames = allClasses.map { it.internalName },
                    mappingFile = input.mappingFile,
                    forbiddenClasses = policy.desktop.forbiddenClasses,
                ),
            )
            add(checkSourceFileAttributes(ownClasses, policy, metrics))
            add(checkDebugTablesAndKotlinMetadata(ownClasses, policy, metrics))
            add(checkBytecodeVerification(gameJars, libraryJars, policy, limits, metrics))
            add(checkMappingHygiene(gameJars, input.mappingFile, policy))
            add(checkNativeLibraries(gameJars, input.nativeLibsDirectory, policy, limits, metrics))
            add(checkJpackageConfig(input.jpackageAppDirectory, policy))
            add(checkAssetEncryption(input.assetDirectory, policy))
            add(checkSecrets(gameJars, policy, limits))
        }
        return AnalyzerOutput(findings = findings, metrics = metrics)
    }

    private fun checkReadability(
        classes: List<ClassFileInfo>,
        libraryMembers: Set<String>,
        policy: ReleaseGuardPolicy,
        metrics: MutableMap<String, String>,
    ): AuditFinding {
        val ownNames = mutableListOf<String>()
        val allNames = mutableListOf<String>()
        for (info in classes) {
            val simple = info.internalName.substringAfterLast('/').substringAfterLast('$').ifEmpty { info.internalName }
            allNames += simple
            ownNames += simple
            for (member in info.members) {
                allNames += member
                if (member !in libraryMembers) ownNames += member
            }
        }
        val ownStats = IdentifierHeuristics.computeReadability(ownNames, policy.projectKeywords, policy.projectPackages)
        val allStats = IdentifierHeuristics.computeReadability(allNames, policy.projectKeywords, policy.projectPackages)
        metrics["desktop.ownReadability"] = String.format(Locale.ROOT, "%.4f", ownStats.score)
        metrics["desktop.allReadability"] = String.format(Locale.ROOT, "%.4f", allStats.score)

        val threshold = policy.desktop.maxOwnReadability
        val passed = ownStats.score <= threshold
        return AuditFinding(
            checkId = "desktop.obfuscation.readability",
            target = AuditTarget.DESKTOP_JVM,
            title = "Desktop JAR identifier obfuscation",
            status = if (passed) CheckStatus.PASS else CheckStatus.FAIL,
            severity = CheckSeverity.HIGH,
            weight = 25,
            summary = String.format(
                Locale.ROOT,
                "Own-code readability is %.3f (%d/%d recognisable; threshold %.3f).",
                ownStats.score,
                ownStats.recognisableCount,
                ownStats.totalCount,
                threshold,
            ),
            evidence = ownStats.examples,
            remediation = "Enable ProGuard/R8 obfuscation on game JARs with -repackageclasses and narrow keep rules.",
        )
    }

    private fun checkProjectPackages(
        classes: List<ClassFileInfo>,
        policy: ReleaseGuardPolicy,
        metrics: MutableMap<String, String>,
    ): AuditFinding {
        if (policy.projectPackages.isEmpty()) {
            return AuditFinding(
                checkId = "desktop.obfuscation.project_packages",
                target = AuditTarget.DESKTOP_JVM,
                title = "Desktop project package flattening",
                status = CheckStatus.SKIP,
                severity = CheckSeverity.MEDIUM,
                weight = 15,
                summary = "Skipped because projectPackages is empty.",
            )
        }
        val kept = classes.map { it.internalName }
            .filter { IdentifierHeuristics.matchesProjectPackage(it, policy.projectPackages) }
            .sorted()
        metrics["desktop.keptProjectClasses"] = kept.size.toString()
        val limit = policy.desktop.maxKeptProjectClasses
        val status = when {
            kept.size <= limit -> CheckStatus.PASS
            kept.size <= limit * 2 -> CheckStatus.WARN
            else -> CheckStatus.FAIL
        }
        return AuditFinding(
            checkId = "desktop.obfuscation.project_packages",
            target = AuditTarget.DESKTOP_JVM,
            title = "Desktop project package flattening",
            status = status,
            severity = CheckSeverity.MEDIUM,
            weight = 15,
            summary = "${kept.size} class(es) remain under configured project packages (limit $limit).",
            evidence = kept.take(10),
            remediation = "Use -repackageclasses '' and keep only required entrypoints (MainKt, JNA, JNI).",
        )
    }

    private fun checkSourceFileAttributes(
        classes: List<ClassFileInfo>,
        policy: ReleaseGuardPolicy,
        metrics: MutableMap<String, String>,
    ): AuditFinding {
        val leakedFiles = classes.mapNotNull { it.sourceFile }.filter { it !in safeSourceFileValues }.distinct().sorted()
        metrics["desktop.leakedSourceFileAttributes"] = leakedFiles.size.toString()
        if (!policy.desktop.forbidOriginalSourceFileAttribute) {
            return AuditFinding(
                checkId = "desktop.metadata.source_file",
                target = AuditTarget.DESKTOP_JVM,
                title = "SourceFile attribute scrubbing",
                status = CheckStatus.SKIP,
                severity = CheckSeverity.LOW,
                weight = 8,
                summary = "SourceFile attribute check disabled by policy.",
            )
        }
        val passed = leakedFiles.isEmpty()
        return AuditFinding(
            checkId = "desktop.metadata.source_file",
            target = AuditTarget.DESKTOP_JVM,
            title = "SourceFile attribute scrubbing",
            status = if (passed) CheckStatus.PASS else CheckStatus.WARN,
            severity = CheckSeverity.LOW,
            weight = 8,
            summary = if (passed) {
                "No original source file names remain in class SourceFile attributes."
            } else {
                "${leakedFiles.size} original source file name(s) remain in class SourceFile attributes."
            },
            evidence = leakedFiles.take(10),
            remediation = "Add '-renamesourcefileattribute SourceFile' to ProGuard/R8 rules.",
        )
    }

    private fun checkDebugTablesAndKotlinMetadata(
        classes: List<ClassFileInfo>,
        policy: ReleaseGuardPolicy,
        metrics: MutableMap<String, String>,
    ): AuditFinding {
        val kotlinMeta = classes.filter { it.hasKotlinMetadata }.map { it.internalName }
        val localVars = classes.filter { it.hasLocalVariableTable }.map { it.internalName }
        val methodParams = classes.filter { it.hasMethodParameters }.map { it.internalName }
        metrics["desktop.kotlinMetadataClasses"] = kotlinMeta.size.toString()
        metrics["desktop.localVariableTableClasses"] = localVars.size.toString()
        metrics["desktop.methodParametersClasses"] = methodParams.size.toString()

        if (!policy.desktop.forbidDebugTablesAndKotlinMetadata) {
            return AuditFinding(
                checkId = "desktop.metadata.debug_tables",
                target = AuditTarget.DESKTOP_JVM,
                title = "JVM debug tables and @kotlin.Metadata stripped",
                status = CheckStatus.SKIP,
                severity = CheckSeverity.MEDIUM,
                weight = 10,
                summary = "JVM debug table and @kotlin.Metadata check disabled by policy.",
            )
        }
        val issues = buildList {
            if (kotlinMeta.isNotEmpty()) add("@kotlin.Metadata present on ${kotlinMeta.size} class(es)")
            if (localVars.isNotEmpty()) add("LocalVariableTable present on ${localVars.size} class(es)")
            if (methodParams.isNotEmpty()) add("MethodParameters present on ${methodParams.size} class(es)")
        }
        val passed = issues.isEmpty()
        return AuditFinding(
            checkId = "desktop.metadata.debug_tables",
            target = AuditTarget.DESKTOP_JVM,
            title = "JVM debug tables and @kotlin.Metadata stripped",
            status = if (passed) CheckStatus.PASS else CheckStatus.WARN,
            severity = CheckSeverity.MEDIUM,
            weight = 10,
            summary = if (passed) {
                "No @kotlin.Metadata, LocalVariableTable, or MethodParameters debug tables remain."
            } else {
                "Metadata/debug tables survive in obfuscated classes: ${issues.joinToString("; ")}."
            },
            evidence = (
                kotlinMeta.take(4).map { "kotlin.Metadata:$it" } +
                    localVars.take(3).map { "LocalVariableTable:$it" } +
                    methodParams.take(3).map { "MethodParameters:$it" }
                ),
            remediation = "Avoid keeping LocalVariableTable/MethodParameters and strip kotlin.Metadata when kotlin-reflect is unused.",
        )
    }

    private fun checkBytecodeVerification(
        gameJars: List<File>,
        libraryJars: List<File>,
        policy: ReleaseGuardPolicy,
        limits: BinaryReadLimits,
        metrics: MutableMap<String, String>,
    ): AuditFinding {
        if (!policy.desktop.verifyBytecode) {
            return AuditFinding(
                checkId = "desktop.bytecode.verify",
                target = AuditTarget.DESKTOP_JVM,
                title = "JVM bytecode linkage verification",
                status = CheckStatus.SKIP,
                severity = CheckSeverity.CRITICAL,
                weight = 20,
                summary = "Bytecode linkage verification disabled by policy.",
            )
        }
        val result = BytecodeLinkVerifier.verify(gameJars, libraryJars, limits)
        metrics["desktop.bytecodeCheckedClasses"] = result.checkedClasses.toString()
        metrics["desktop.bytecodeRejectedClasses"] = result.rejectedClasses.size.toString()
        val passed = result.rejectedClasses.isEmpty()
        return AuditFinding(
            checkId = "desktop.bytecode.verify",
            target = AuditTarget.DESKTOP_JVM,
            title = "JVM bytecode linkage verification",
            status = if (passed) CheckStatus.PASS else CheckStatus.FAIL,
            severity = CheckSeverity.CRITICAL,
            weight = 20,
            summary = if (passed) {
                "Linked ${result.checkedClasses} class(es) with 0 JVM VerifyErrors."
            } else {
                "${result.rejectedClasses.size} of ${result.checkedClasses} class(es) failed JVM bytecode verification."
            },
            evidence = result.rejectedClasses.take(8).map { "${it.jarName}:${it.className} (${it.reason})" },
            remediation = "Add '-dontoptimize' to desktop ProGuard rules when stack-map frame rewrites fail verification.",
        )
    }

    private fun checkNativeLibraries(
        gameJars: List<File>,
        nativeLibsDir: File?,
        policy: ReleaseGuardPolicy,
        limits: BinaryReadLimits,
        metrics: MutableMap<String, String>,
    ): AuditFinding {
        val binaries = if (policy.desktop.inspectNativeLibraries) {
            collectDesktopNativeBinaries(gameJars, nativeLibsDir, limits)
        } else {
            emptyList()
        }
        metrics["desktop.nativeBinaryCount"] = binaries.size.toString()
        return when {
            !policy.desktop.inspectNativeLibraries -> AuditFinding(
                checkId = "desktop.native.hardening",
                target = AuditTarget.DESKTOP_JVM,
                title = "Desktop native library hardening (PE/ELF/Mach-O)",
                status = CheckStatus.SKIP,
                severity = CheckSeverity.MEDIUM,
                weight = 10,
                summary = "Desktop native library inspection disabled by policy.",
            )
            binaries.isEmpty() -> AuditFinding(
                checkId = "desktop.native.hardening",
                target = AuditTarget.DESKTOP_JVM,
                title = "Desktop native library hardening (PE/ELF/Mach-O)",
                status = CheckStatus.SKIP,
                severity = CheckSeverity.MEDIUM,
                weight = 10,
                summary = "No native .dll, .so, or .dylib libraries found to inspect.",
            )
            else -> {
                val issues = binaries.flatMap { (name, bytes) -> inspectSingleDesktopBinary(name, bytes, policy) }
                val passed = issues.isEmpty()
                AuditFinding(
                    checkId = "desktop.native.hardening",
                    target = AuditTarget.DESKTOP_JVM,
                    title = "Desktop native library hardening (PE/ELF/Mach-O)",
                    status = if (passed) CheckStatus.PASS else CheckStatus.FAIL,
                    severity = CheckSeverity.HIGH,
                    weight = 10,
                    summary = if (passed) {
                        "All ${binaries.size} desktop native library binary(s) passed hardening and path-scrub checks."
                    } else {
                        "Found ${issues.size} hardening or debug-path leak(s) across ${binaries.size} desktop native binary(s)."
                    },
                    evidence = issues.take(10),
                    remediation = "Build native libraries with ASLR/DEP (/DYNAMICBASE /NXCOMPAT), RELRO/NX/PIE, stripped symbols, and scrubbed PDB paths (/PDBALTPATH).",
                )
            }
        }
    }

    private fun checkJpackageConfig(jpackageDir: File?, policy: ReleaseGuardPolicy): AuditFinding {
        if (!policy.desktop.forbidJpackageDebugFlags || jpackageDir == null || !jpackageDir.isDirectory) {
            return AuditFinding(
                checkId = "desktop.jpackage.config",
                target = AuditTarget.DESKTOP_JVM,
                title = "Desktop launcher config (jpackage .cfg) hygiene",
                status = CheckStatus.SKIP,
                severity = CheckSeverity.HIGH,
                weight = 8,
                summary = "No jpackage app directory supplied or check disabled.",
            )
        }
        val cfgFiles = jpackageDir.walkTopDown().filter { it.isFile && it.extension.equals("cfg", ignoreCase = true) }.toList()
        val leaks = mutableListOf<String>()
        for (cfg in cfgFiles) {
            val content = BoundedBinaryIo.readTextBounded(cfg)
            jpackageDebugFlagRegex.findAll(content).forEach { hit ->
                leaks += "${cfg.name}:${hit.value.trim()}"
            }
        }
        val passed = leaks.isEmpty()
        return AuditFinding(
            checkId = "desktop.jpackage.config",
            target = AuditTarget.DESKTOP_JVM,
            title = "Desktop launcher config (jpackage .cfg) hygiene",
            status = if (passed) CheckStatus.PASS else CheckStatus.FAIL,
            severity = CheckSeverity.HIGH,
            weight = 8,
            summary = if (passed) {
                "Inspected ${cfgFiles.size} jpackage .cfg file(s) with no JDWP/debug JVM flags."
            } else {
                "Found ${leaks.size} debug JVM flag(s) baked into jpackage launcher config(s)."
            },
            evidence = leaks.take(10),
            remediation = "Remove -agentlib:jdwp, -Xdebug, and -ea from release jpackage JVM options.",
        )
    }
}

private fun missingJarsOutput(dir: File): AnalyzerOutput = AnalyzerOutput(
    findings = listOf(
        AuditFinding(
            checkId = "desktop.jars.present",
            target = AuditTarget.DESKTOP_JVM,
            title = "Desktop release JARs present",
            status = CheckStatus.FAIL,
            severity = CheckSeverity.CRITICAL,
            weight = 30,
            summary = "No JAR files found in ${dir.path}.",
            remediation = "Run the desktop ProGuard/obfuscation task before auditing.",
        ),
    ),
)

private fun listJars(directory: File): List<File> =
    if (directory.isDirectory) {
        directory.listFiles { file -> file.isFile && file.name.endsWith(".jar") }?.sortedBy { it.name }.orEmpty()
    } else {
        emptyList()
    }

private fun collectLibraryMembers(
    gameJars: List<File>,
    libraryJars: List<File>,
    limits: BinaryReadLimits,
): Set<String> {
    val gameNames = gameJars.mapTo(HashSet()) { it.name }
    val members = HashSet(IdentifierHeuristics.JDK_STANDARD_MEMBERS)
    for (jar in libraryJars) {
        if (jar.name in gameNames) continue
        for (info in ClassFileReader.readJar(jar, limits)) {
            members.addAll(info.members)
        }
    }
    return members
}

private fun checkMappingHygiene(
    gameJars: List<File>,
    mappingFile: File?,
    policy: ReleaseGuardPolicy,
): AuditFinding {
    val leakedMappingInsideJar = gameJars.filter { jar ->
        ZipFile(jar).use { zip ->
            zip.entries().asSequence().any { !it.isDirectory && it.name.endsWith("mapping.txt") }
        }
    }
    val validMapping = mappingFile?.takeIf { it.isFile && it.length() > 0L }
    return when {
        leakedMappingInsideJar.isNotEmpty() -> AuditFinding(
            checkId = "desktop.mapping.hygiene",
            target = AuditTarget.DESKTOP_JVM,
            title = "ProGuard mapping archive hygiene",
            status = CheckStatus.FAIL,
            severity = CheckSeverity.HIGH,
            weight = 5,
            summary = "Obfuscation mapping.txt was bundled inside shipped JAR(s).",
            evidence = leakedMappingInsideJar.map { it.name },
            remediation = "Keep mapping.txt outside the packaged distribution and store it privately for crash retracing.",
        )
        !policy.desktop.requireMappingFile -> AuditFinding(
            checkId = "desktop.mapping.hygiene",
            target = AuditTarget.DESKTOP_JVM,
            title = "ProGuard mapping archive hygiene",
            status = CheckStatus.PASS,
            severity = CheckSeverity.LOW,
            weight = 5,
            summary = if (validMapping != null) {
                "External mapping file present at ${validMapping.name}; no mapping bundled in JARs."
            } else {
                "No mapping.txt leaked inside shipped JARs."
            },
        )
        else -> AuditFinding(
            checkId = "desktop.mapping.hygiene",
            target = AuditTarget.DESKTOP_JVM,
            title = "ProGuard mapping archive hygiene",
            status = if (validMapping != null) CheckStatus.PASS else CheckStatus.WARN,
            severity = CheckSeverity.LOW,
            weight = 5,
            summary = if (validMapping != null) {
                "External ProGuard mapping file verified (${validMapping.length()} bytes)."
            } else {
                "Expected external ProGuard mapping file is missing or empty."
            },
            remediation = "Configure -printmapping to archive mapping.txt privately for crash stack-trace retracing.",
        )
    }
}

private fun collectDesktopNativeBinaries(
    gameJars: List<File>,
    nativeLibsDir: File?,
    limits: BinaryReadLimits,
): List<Pair<String, ByteArray>> {
    val results = mutableListOf<Pair<String, ByteArray>>()
    val nativeExts = setOf("dll", "exe", "so", "dylib")
    if (nativeLibsDir != null && nativeLibsDir.isDirectory) {
        nativeLibsDir.walkTopDown()
            .filter { it.isFile && it.extension.lowercase(Locale.ROOT) in nativeExts }
            .sortedBy { it.name }
            .forEach { file -> results += file.name to BoundedBinaryIo.readFileBounded(file, limits.maxSingleFileBytes) }
    }
    for (jar in gameJars) {
        val budget = ZipReadBudget(limits)
        ZipFile(jar).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                budget.recordEntry(entry.name)
                val ext = entry.name.substringAfterLast('.', "").lowercase(Locale.ROOT)
                if (!entry.isDirectory && ext in nativeExts) {
                    results += "${jar.name}!/${entry.name}" to budget.readEntryBytes(zip, entry)
                }
            }
        }
    }
    return results
}

private fun inspectSingleDesktopBinary(name: String, bytes: ByteArray, policy: ReleaseGuardPolicy): List<String> = when {
    PeBinaryInspector.isPe(bytes) -> inspectPeIssues(name, PeBinaryInspector.parse(bytes), policy)
    ElfBinaryInspector.isElf(bytes) -> inspectElfDesktopIssues(name, ElfBinaryInspector.parse(bytes))
    MachOInspector.isMachO(bytes) -> inspectMachODesktopIssues(name, MachOInspector.parse(bytes))
    else -> emptyList()
}

private fun inspectPeIssues(name: String, pe: PeInspectionResult, policy: ReleaseGuardPolicy): List<String> = buildList {
    if (policy.desktop.requirePeAslrAndDep && !pe.hasAslr) add("$name: missing PE ASLR (DYNAMIC_BASE)")
    if (policy.desktop.requirePeAslrAndDep && !pe.hasDepNx) add("$name: missing PE DEP (NX_COMPAT)")
    if (policy.desktop.forbidLeakedPdbPaths) pe.leakedPdbPaths.forEach { add("$name: leaked PDB path ($it)") }
}

private fun inspectElfDesktopIssues(name: String, elf: ElfInspectionResult): List<String> = buildList {
    if (!elf.hasNxStack) add("$name: executable stack (missing NX)")
    if (!elf.hasRelro) add("$name: missing RELRO")
    if (elf.hasDebugSections) add("$name: unstripped ELF debug sections (${elf.debugSectionNames.joinToString()})")
}

private fun inspectMachODesktopIssues(name: String, machO: MachOInspectionResult): List<String> = buildList {
    if (machO.hasDwarfSegment) add("$name: unstripped Mach-O __DWARF segment")
    if (machO.debugStabSymbolCount > 0) add("$name: ${machO.debugStabSymbolCount} STAB debug symbols")
}

private fun checkAssetEncryption(assetDir: File?, policy: ReleaseGuardPolicy): AuditFinding {
    val checks = if (policy.assetEncryption.enabled && assetDir != null && assetDir.isDirectory) {
        assetDir.walkTopDown()
            .filter { it.isFile && AssetEncryptionInspector.matchesBundleExtension(it.name, policy.assetEncryption) }
            .sortedBy { it.name }
            .map { file ->
                val header = file.inputStream().use { input ->
                    val buf = ByteArray(16)
                    val read = input.read(buf)
                    if (read > 0) buf.copyOf(read) else ByteArray(0)
                }
                AssetEncryptionInspector.inspectAwkbHeader(file.relativeTo(assetDir).invariantSeparatorsPath, header)
            }
            .toList()
    } else {
        emptyList()
    }
    return AssetEncryptionInspector.toFinding("desktop.assets.encryption", AuditTarget.DESKTOP_JVM, checks, policy.assetEncryption)
}

private fun checkSecrets(
    gameJars: List<File>,
    policy: ReleaseGuardPolicy,
    limits: BinaryReadLimits,
): AuditFinding {
    if (!policy.secrets.enabled) {
        return AuditFinding(
            checkId = "desktop.secrets.scan",
            target = AuditTarget.DESKTOP_JVM,
            title = "Desktop JAR secret scan",
            status = CheckStatus.SKIP,
            severity = CheckSeverity.CRITICAL,
            weight = 15,
            summary = "Secret scanning disabled by policy.",
        )
    }
    val matches = mutableListOf<SecretMatch>()
    val sensitiveFiles = mutableListOf<String>()
    for (jar in gameJars) {
        val budget = ZipReadBudget(limits)
        ZipFile(jar).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                budget.recordEntry(entry.name)
                if (entry.isDirectory) continue
                if (SecretScanner.isSensitivePackagedFile(entry.name)) {
                    sensitiveFiles += "${jar.name}!/${entry.name}"
                }
                if (entry.size <= MAX_SECRET_SCAN_ENTRY_BYTES) {
                    val bytes = budget.readEntryBytes(zip, entry, MAX_SECRET_SCAN_ENTRY_BYTES)
                    val texts = IdentifierHeuristics.extractPrintableStrings(bytes)
                    matches += SecretScanner.scanSecrets("${jar.name}!/${entry.name}", texts, policy.secrets)
                }
            }
        }
    }
    val passed = matches.isEmpty() && sensitiveFiles.isEmpty()
    return AuditFinding(
        checkId = "desktop.secrets.scan",
        target = AuditTarget.DESKTOP_JVM,
        title = "Desktop JAR secret & sensitive file scan",
        status = if (passed) CheckStatus.PASS else CheckStatus.FAIL,
        severity = CheckSeverity.CRITICAL,
        weight = 15,
        summary = if (passed) {
            "No private keys, high-entropy secrets, or sensitive key/env files found in desktop JARs."
        } else {
            "Found ${matches.size} secret match(es) and ${sensitiveFiles.size} sensitive file(s) in desktop JARs."
        },
        evidence = (
            matches.take(5).map { "${it.ruleName} @ ${it.location} (${it.redactedPreview})" } +
                sensitiveFiles.take(5).map { "sensitive-file:$it" }
            ),
        remediation = "Remove embedded private keys, tokens, and .env/.keystore/.pem files from desktop JARs.",
    )
}

private const val MAX_SECRET_SCAN_ENTRY_BYTES: Long = 8L * 1024L * 1024L

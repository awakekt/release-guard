/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.gradle

import com.awakekt.releaseguard.ReleaseGuardAuditor
import com.awakekt.releaseguard.ReleaseGuardRequest
import com.awakekt.releaseguard.analyzers.AndroidAuditInput
import com.awakekt.releaseguard.analyzers.AssetAuditInput
import com.awakekt.releaseguard.analyzers.DesktopAuditInput
import com.awakekt.releaseguard.analyzers.IosAuditInput
import com.awakekt.releaseguard.analyzers.SpirvShaderInspector
import com.awakekt.releaseguard.analyzers.SupplyChainAuditInput
import com.awakekt.releaseguard.analyzers.TlsAuditInput
import com.awakekt.releaseguard.analyzers.WebAuditInput
import com.awakekt.releaseguard.analyzers.WebBundleStripper
import com.awakekt.releaseguard.analyzers.WebStripOptions
import com.awakekt.releaseguard.io.ZipReadBudget
import com.awakekt.releaseguard.model.ReleaseGuardPolicy
import com.awakekt.releaseguard.report.HtmlReportRenderer
import com.awakekt.releaseguard.report.ReleaseGuardReportRenderer
import com.awakekt.releaseguard.report.SarifReportRenderer
import kotlinx.serialization.json.Json
import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.MapProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.CacheableTask
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.work.DisableCachingByDefault
import java.io.File
import java.util.Locale
import java.util.zip.ZipFile

/** Generates deterministic desktop ProGuard and Android R8 rule files from `releaseGuard.rules`. */
@CacheableTask
public abstract class GenerateReleaseGuardRulesTask : DefaultTask() {
    @get:Input
    @get:Optional
    public abstract val mainClass: Property<String>

    @get:Input
    public abstract val repackageClasses: Property<String>

    @get:Input
    public abstract val allowAccessModification: Property<Boolean>

    @get:Input
    public abstract val overloadAggressively: Property<Boolean>

    @get:Input
    public abstract val renameSourceFileAttribute: Property<String>

    @get:Input
    public abstract val stripKotlinIntrinsics: Property<Boolean>

    @get:Input
    public abstract val stripKotlinMetadata: Property<Boolean>

    @get:Input
    public abstract val stripAndroidLogs: Property<Boolean>

    @get:Input
    public abstract val keepKotlinxSerialization: Property<Boolean>

    @get:Input
    public abstract val keepEnums: Property<Boolean>

    @get:Input
    public abstract val keepJnaLibraries: Property<Boolean>

    @get:Input
    public abstract val keepComposeModifiers: Property<Boolean>

    @get:Input
    public abstract val desktopDontOptimize: Property<Boolean>

    @get:Input
    public abstract val extraRules: ListProperty<String>

    @get:Input
    public abstract val extraDesktopRules: ListProperty<String>

    @get:Input
    public abstract val extraAndroidRules: ListProperty<String>

    @get:OutputFile
    public abstract val desktopRulesFile: RegularFileProperty

    @get:OutputFile
    public abstract val androidRulesFile: RegularFileProperty

    @TaskAction
    public fun generate() {
        val config = ProGuardRuleConfig(
            mainClass = mainClass.orNull.orEmpty(),
            repackageClasses = repackageClasses.get(),
            allowAccessModification = allowAccessModification.get(),
            overloadAggressively = overloadAggressively.get(),
            renameSourceFileAttribute = renameSourceFileAttribute.get(),
            stripKotlinIntrinsics = stripKotlinIntrinsics.get(),
            stripKotlinMetadata = stripKotlinMetadata.get(),
            stripAndroidLogs = stripAndroidLogs.get(),
            keepKotlinxSerialization = keepKotlinxSerialization.get(),
            keepEnums = keepEnums.get(),
            keepJnaLibraries = keepJnaLibraries.get(),
            keepComposeModifiers = keepComposeModifiers.get(),
            desktopDontOptimize = desktopDontOptimize.get(),
            extraRules = extraRules.get(),
            extraDesktopRules = extraDesktopRules.get(),
            extraAndroidRules = extraAndroidRules.get(),
        )
        desktopRulesFile.get().asFile.apply {
            parentFile.mkdirs()
            writeText(ProGuardRuleGenerator.generateDesktopRules(config), Charsets.UTF_8)
        }
        androidRulesFile.get().asFile.apply {
            parentFile.mkdirs()
            writeText(ProGuardRuleGenerator.generateAndroidRules(config), Charsets.UTF_8)
        }
    }
}

/**
 * Extracts `META-INF/proguard` `.pro` consumer keep rules shipped inside external runtime dependency
 * JARs into a flat directory for desktop ProGuard tasks.
 */
@CacheableTask
public abstract class CollectLibraryKeepRulesTask : DefaultTask() {
    @get:Input
    public abstract val collectEnabled: Property<Boolean>

    @get:InputFiles
    @get:PathSensitive(PathSensitivity.NAME_ONLY)
    public abstract val dependencyJars: ConfigurableFileCollection

    @get:OutputDirectory
    public abstract val outputDir: DirectoryProperty

    @TaskAction
    public fun collect() {
        val out = outputDir.get().asFile
        if (out.exists()) out.deleteRecursively()
        out.mkdirs()
        if (!collectEnabled.get()) return

        val written = LinkedHashSet<String>()
        dependencyJars.files
            .filter { it.isFile && it.name.endsWith(".jar") }
            .sortedBy { it.name }
            .forEach { jar -> extractProguardEntries(jar, out, written) }
    }

    private fun extractProguardEntries(jar: File, out: File, written: MutableSet<String>) {
        val budget = ZipReadBudget()
        ZipFile(jar).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                budget.recordEntry(entry.name)
                val isPro = !entry.isDirectory &&
                    entry.name.startsWith("META-INF/proguard/") &&
                    entry.name.endsWith(".pro")
                if (isPro) {
                    val base = entry.name.substringAfterLast('/')
                    val targetName = if (written.add(base)) base else "${jar.nameWithoutExtension}-$base"
                    written.add(targetName)
                    out.resolve(targetName).writeBytes(budget.readEntryBytes(zip, entry))
                }
            }
        }
    }
}

/** Hardens a Kotlin/Wasm web bundle directly via [WebBundleStripper]. */
@CacheableTask
public abstract class HardenWebBundleTask : DefaultTask() {
    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.RELATIVE)
    public abstract val inputDir: DirectoryProperty

    @get:Input
    public abstract val stripWasmDebugSections: Property<Boolean>

    @get:Input
    public abstract val dropSourceMaps: Property<Boolean>

    @get:Input
    public abstract val generateSecurityHeaders: Property<Boolean>

    @get:Input
    @get:Optional
    public abstract val contentSecurityPolicyOverride: Property<String>

    @get:OutputDirectory
    public abstract val outputDir: DirectoryProperty

    @TaskAction
    public fun harden() {
        val report = WebBundleStripper.harden(
            inputDir = inputDir.get().asFile,
            outputDir = outputDir.get().asFile,
            options = WebStripOptions(
                stripWasmDebugSections = stripWasmDebugSections.get(),
                dropSourceMaps = dropSourceMaps.get(),
                generateSecurityHeaders = generateSecurityHeaders.get(),
                contentSecurityPolicyOverride = contentSecurityPolicyOverride.orNull?.takeIf { it.isNotBlank() },
            ),
        )
        logger.lifecycle(
            "Hardened web bundle: copied=${report.copiedFiles}, droppedMaps=${report.droppedSourceMaps.size}, " +
                "strippedWasmBytes=${report.strippedWasmBytesSaved}, headers=${report.wroteHeadersFile}",
        )
    }
}

/** Losslessly strips SPIR-V debug opcodes (`OpSource`, `OpName`, `OpLine`, `OpString`) in pure Kotlin. */
@CacheableTask
public abstract class StripSpirvShadersTask : DefaultTask() {
    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.RELATIVE)
    public abstract val inputDir: DirectoryProperty

    @get:OutputDirectory
    public abstract val outputDir: DirectoryProperty

    @TaskAction
    public fun strip() {
        val src = inputDir.get().asFile
        val dst = outputDir.get().asFile
        if (dst.exists()) dst.deleteRecursively()
        dst.mkdirs()
        var count = 0
        var savedBytes = 0L
        src.walkTopDown().filter { it.isFile && it.extension.equals("spv", ignoreCase = true) }.forEach { file ->
            val raw = file.readBytes()
            val stripped = SpirvShaderInspector.stripDebugOpcodes(raw)
            val target = dst.resolve(file.relativeTo(src))
            target.parentFile?.mkdirs()
            target.writeBytes(stripped)
            count++
            savedBytes += (raw.size - stripped.size).coerceAtLeast(0)
        }
        logger.lifecycle("Stripped $count SPIR-V shader(s) into ${dst.path} (saved $savedBytes bytes).")
    }
}

/**
 * Audits all enabled targets via [ReleaseGuardAuditor], writes JSON, Markdown, and SARIF 2.1.0
 * reports, compares against an optional baseline scorecard, and enforces configured release gates.
 */
@DisableCachingByDefault(because = "Audits release artifacts on disk and optional live TLS endpoints")
public abstract class VerifyReleaseGuardTask : DefaultTask() {
    init {
        outputs.upToDateWhen { false }
    }

    @get:Input
    public abstract val serializedPolicyJson: Property<String>

    @get:Input
    public abstract val desktopEnabled: Property<Boolean>

    @get:Input
    @get:Optional
    public abstract val desktopGameJarsPath: Property<String>

    @get:Input
    @get:Optional
    public abstract val desktopLibrariesPath: Property<String>

    @get:Input
    @get:Optional
    public abstract val desktopMappingPath: Property<String>

    @get:Input
    @get:Optional
    public abstract val desktopNativeLibsPath: Property<String>

    @get:Input
    @get:Optional
    public abstract val desktopJpackagePath: Property<String>

    @get:Input
    @get:Optional
    public abstract val desktopAssetsPath: Property<String>

    @get:Input
    public abstract val webEnabled: Property<Boolean>

    @get:Input
    @get:Optional
    public abstract val webSitePath: Property<String>

    @get:Input
    public abstract val androidEnabled: Property<Boolean>

    @get:Input
    @get:Optional
    public abstract val androidArtifactPath: Property<String>

    @get:Input
    @get:Optional
    public abstract val androidMappingPath: Property<String>

    @get:Input
    public abstract val iosEnabled: Property<Boolean>

    @get:Input
    @get:Optional
    public abstract val iosArtifactPath: Property<String>

    @get:Input
    @get:Optional
    public abstract val iosInfoPlistPath: Property<String>

    @get:Input
    public abstract val tlsEnabled: Property<Boolean>

    @get:Input
    @get:Optional
    public abstract val tlsSpkiPins: Property<String>

    @get:Input
    public abstract val tlsProbeHosts: ListProperty<String>

    @get:Input
    public abstract val supplyChainEnabled: Property<Boolean>

    @get:Input
    public abstract val resolvedDependencies: ListProperty<String>

    @get:Input
    public abstract val assetsEnabled: Property<Boolean>

    @get:Input
    public abstract val shadersEnabled: Property<Boolean>

    @get:Input
    public abstract val assetDirectoryPaths: ListProperty<String>

    @get:Input
    public abstract val shaderDirectoryPaths: ListProperty<String>

    @get:Input
    public abstract val assetArchivePaths: ListProperty<String>

    @get:Input
    public abstract val customCheckClasses: ListProperty<String>

    @get:Input
    public abstract val loadServiceProviderChecks: Property<Boolean>

    @get:Input
    public abstract val customParameters: MapProperty<String, String>

    @get:Input
    @get:Optional
    public abstract val baselinePath: Property<String>

    @get:Input
    public abstract val consoleFormat: Property<String>

    @get:OutputFile
    public abstract val jsonReportFile: RegularFileProperty

    @get:OutputFile
    public abstract val markdownReportFile: RegularFileProperty

    @get:OutputFile
    public abstract val sarifReportFile: RegularFileProperty

    @get:OutputFile
    public abstract val htmlReportFile: RegularFileProperty

    @TaskAction
    public fun verify() {
        val json = Json { ignoreUnknownKeys = true }
        val policy = json.decodeFromString(ReleaseGuardPolicy.serializer(), serializedPolicyJson.get())
        val request = buildRequest(policy)
        val scorecard = ReleaseGuardAuditor.audit(request)

        writeReport(jsonReportFile.get().asFile, ReleaseGuardReportRenderer.renderJson(scorecard))
        writeReport(markdownReportFile.get().asFile, ReleaseGuardReportRenderer.renderMarkdown(scorecard))
        writeReport(sarifReportFile.get().asFile, SarifReportRenderer.renderSarif(scorecard))
        writeReport(htmlReportFile.get().asFile, HtmlReportRenderer.renderHtml(scorecard))

        val rendered = when (consoleFormat.get().lowercase(Locale.ROOT)) {
            "json" -> ReleaseGuardReportRenderer.renderJson(scorecard)
            "markdown", "md" -> ReleaseGuardReportRenderer.renderMarkdown(scorecard)
            "sarif" -> SarifReportRenderer.renderSarif(scorecard)
            "html" -> HtmlReportRenderer.renderHtml(scorecard)
            else -> ReleaseGuardReportRenderer.renderConsole(scorecard)
        }
        logger.lifecycle(rendered.trimEnd())
        if (!scorecard.passedGate) {
            throw GradleException(
                "Release Guard verification failed (score=${scorecard.overallScore}/${policy.minScore}). " +
                    "Open HTML dashboard: ${htmlReportFile.get().asFile.absolutePath} " +
                    "(Markdown: ${markdownReportFile.get().asFile.absolutePath}).",
            )
        }
    }

    private fun buildRequest(policy: ReleaseGuardPolicy): ReleaseGuardRequest {
        val baseline = baselinePath.orNull?.let(::File)?.takeIf { it.isFile }?.let { file ->
            ReleaseGuardReportRenderer.parseJson(file.readText(Charsets.UTF_8))
        }
        val request = ReleaseGuardRequest(
            policy = policy,
            desktop = buildDesktopInput(),
            android = buildAndroidInput(),
            web = if (webEnabled.get()) {
                WebAuditInput(File(requirePath(webSitePath, "releaseGuard.web.enabled is true but strippedOutputDir is not set.")))
            } else {
                null
            },
            ios = buildIosInput(),
            tls = if (tlsEnabled.get()) TlsAuditInput(tlsSpkiPins.orNull.orEmpty(), tlsProbeHosts.get()) else null,
            supplyChain = if (supplyChainEnabled.get()) SupplyChainAuditInput(resolvedDependencies.get()) else null,
            assets = buildAssetsInput(policy),
            baseline = baseline,
            customCheckClassNames = customCheckClasses.get(),
            loadServiceProviderChecks = loadServiceProviderChecks.get(),
            customParameters = customParameters.get(),
        )
        val hasTarget =
            listOf(request.desktop, request.android, request.web, request.ios, request.tls, request.supplyChain, request.assets)
                .any { it != null } || request.customCheckClassNames.isNotEmpty()
        if (!hasTarget) {
            throw GradleException(
                "Enable at least one target in releaseGuard { desktop / android / web / ios / assets / shaders / tls / supplyChain / customChecks }.",
            )
        }
        return request
    }

    private fun buildDesktopInput(): DesktopAuditInput? = if (desktopEnabled.get()) {
        val jars = requirePath(desktopGameJarsPath, "releaseGuard.desktop.enabled is true but gameJarsDir is not set.")
        DesktopAuditInput(
            gameJarsDirectory = File(jars),
            librariesDirectory = desktopLibrariesPath.orNull?.let(::File),
            mappingFile = desktopMappingPath.orNull?.let(::File),
            nativeLibsDirectory = desktopNativeLibsPath.orNull?.let(::File),
            jpackageAppDirectory = desktopJpackagePath.orNull?.let(::File),
            assetDirectory = desktopAssetsPath.orNull?.let(::File),
        )
    } else {
        null
    }

    private fun buildAndroidInput(): AndroidAuditInput? = if (androidEnabled.get()) {
        AndroidAuditInput(
            File(requirePath(androidArtifactPath, "releaseGuard.android.enabled is true but artifactFile is not set.")),
            androidMappingPath.orNull?.let(::File),
        )
    } else {
        null
    }

    private fun buildIosInput(): IosAuditInput? = if (iosEnabled.get()) {
        IosAuditInput(
            File(requirePath(iosArtifactPath, "releaseGuard.ios.enabled is true but artifactPath is not set.")),
            iosInfoPlistPath.orNull?.let(::File),
        )
    } else {
        null
    }

    private fun buildAssetsInput(policy: ReleaseGuardPolicy): AssetAuditInput? {
        if (!assetsEnabled.get() && !shadersEnabled.get() && !policy.assetEncryption.enabled) return null
        val assetDirs = assetDirectoryPaths.get().map(::File)
        val shaderDirs = shaderDirectoryPaths.get().map(::File)
        val archives = assetArchivePaths.get().map(::File)
        return if (assetDirs.isNotEmpty() || shaderDirs.isNotEmpty() || archives.isNotEmpty()) {
            AssetAuditInput(assetDirectories = assetDirs, shaderDirectories = shaderDirs, archiveFiles = archives)
        } else {
            null
        }
    }

    private fun requirePath(prop: Property<String>, message: String): String =
        prop.orNull ?: throw GradleException(message)

    private fun writeReport(file: File, content: String) {
        file.parentFile?.mkdirs()
        file.writeText(content, Charsets.UTF_8)
    }
}

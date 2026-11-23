/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.gradle

import com.android.build.api.variant.ApplicationAndroidComponentsExtension
import com.awakekt.releaseguard.model.AndroidAuditPolicy
import com.awakekt.releaseguard.model.AssetEncryptionPolicy
import com.awakekt.releaseguard.model.BaselinePolicy
import com.awakekt.releaseguard.model.CheckSeverity
import com.awakekt.releaseguard.model.DesktopAuditPolicy
import com.awakekt.releaseguard.model.IosAuditPolicy
import com.awakekt.releaseguard.model.ReleaseGuardPolicy
import com.awakekt.releaseguard.model.SecretScanPolicy
import com.awakekt.releaseguard.model.SupplyChainPolicy
import com.awakekt.releaseguard.model.TlsAuditPolicy
import com.awakekt.releaseguard.model.WebAuditMode
import com.awakekt.releaseguard.model.WebAuditPolicy
import kotlinx.serialization.json.Json
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.artifacts.component.ModuleComponentIdentifier
import org.gradle.api.provider.Provider
import org.gradle.api.tasks.TaskProvider
import org.jetbrains.kotlin.gradle.targets.js.ir.KotlinJsIrLink
import org.jetbrains.kotlin.gradle.targets.wasm.binaryen.BinaryenExec
import java.util.Locale

/**
 * Gradle plugin (`com.awakekt.release-guard`) providing build-time KMP hardening, ProGuard/R8 rule
 * generation, web bundle stripping, Android release packaging hygiene, and weighted CI scorecards.
 */
public class ReleaseGuardPlugin : Plugin<Project> {
    override fun apply(project: Project) {
        project.pluginManager.apply("base")
        val ext = project.extensions.create("releaseGuard", ReleaseGuardExtension::class.java)
        applyConventions(project, ext)

        val generateRules = registerGenerateRulesTask(project, ext)
        registerCollectKeepRulesTask(project, ext)
        registerHardenWebTask(project, ext)
        registerVerifyTask(project, ext)

        // Isolate optional KMP and AGP plugin references into dedicated helper objects so pure-JVM
        // projects never load Kotlin/Android plugin classes.
        project.plugins.withId("org.jetbrains.kotlin.multiplatform") {
            KotlinWasmHardeningHook.wire(project, ext)
        }
        project.plugins.withId("com.android.application") {
            AndroidReleaseHardeningHook.wire(project, ext, generateRules)
        }
    }

    private fun applyConventions(project: Project, ext: ReleaseGuardExtension) {
        ext.projectPackages.convention(emptyList())
        ext.projectKeywords.convention(emptyList())
        ext.minScore.convention(80)
        ext.failOnSeverity.convention("HIGH")
        ext.disabledChecks.convention(emptySet())
        ext.severityOverrides.convention(emptyMap())
        ext.weightOverrides.convention(emptyMap())
        ext.allowedLibraryPathPatterns.convention(ReleaseGuardPolicy.DEFAULT_ALLOWED_LIBRARY_PATHS)

        applyRulesConventions(ext.rules)
        applyDesktopConventions(ext.desktop)
        applyWebConventions(project, ext.web)
        applyAndroidConventions(ext.android)
        applyIosTlsAndMiscConventions(project, ext)
    }

    private fun applyRulesConventions(rules: ReleaseGuardRulesSpec) {
        rules.repackageClasses.convention("")
        rules.allowAccessModification.convention(true)
        rules.overloadAggressively.convention(true)
        rules.renameSourceFileAttribute.convention("SourceFile")
        rules.stripKotlinIntrinsics.convention(true)
        rules.stripKotlinMetadata.convention(false)
        rules.stripAndroidLogs.convention(true)
        rules.keepKotlinxSerialization.convention(true)
        rules.keepEnums.convention(true)
        rules.keepJnaLibraries.convention(true)
        rules.keepComposeModifiers.convention(true)
        rules.desktopDontOptimize.convention(true)
        rules.extraRules.convention(emptyList())
        rules.extraDesktopRules.convention(emptyList())
        rules.extraAndroidRules.convention(emptyList())
    }

    private fun applyDesktopConventions(desktop: DesktopGuardSpec) {
        desktop.enabled.convention(false)
        desktop.maxReadability.convention(0.02)
        desktop.maxKeptProjectClasses.convention(10)
        desktop.verifyBytecode.convention(true)
        desktop.forbidOriginalSourceFileAttribute.convention(true)
        desktop.forbidDebugTablesAndKotlinMetadata.convention(true)
        desktop.requireMappingFile.convention(false)
        desktop.collectLibraryKeepRules.convention(true)
        desktop.inspectNativeLibraries.convention(true)
        desktop.requirePeAslrAndDep.convention(true)
        desktop.forbidLeakedPdbPaths.convention(true)
        desktop.forbidJpackageDebugFlags.convention(true)
    }

    private fun applyWebConventions(project: Project, web: WebGuardSpec) {
        web.enabled.convention(false)
        web.stripKclassFqn.convention(true)
        web.profilingNamesProperty.convention("releaseGuard.wasm.names")
        web.strippedOutputDir.convention(project.layout.buildDirectory.dir("release-guard/web-hardened"))
        web.stripWasmDebugSections.convention(true)
        web.dropSourceMaps.convention(true)
        web.generateSecurityHeaders.convention(true)
        web.mode.convention("production")
        web.maxReadability.convention(0.25)
        web.forbidProjectSourcePaths.convention(true)
        web.requireSecurityHeaders.convention(true)
        web.gradeCspQuality.convention(true)
        web.allowWasmUnsafeEvalInCsp.convention(true)
        web.requireSubresourceIntegrity.convention(true)
        web.sriAllowlistHosts.convention(emptySet())
        web.forbidInsecureWebEndpoints.convention(true)
        web.forbidDebuggerStatements.convention(true)
        web.forbidSensitiveDistFiles.convention(true)
    }

    private fun applyAndroidConventions(android: AndroidGuardSpec) {
        android.enabled.convention(false)
        android.autoConfigureReleaseHardening.convention(true)
        android.maxReadability.convention(0.05)
        android.maxKeptProjectClasses.convention(20)
        android.forbidKotlinMetadata.convention(true)
        android.forbidDebuggable.convention(true)
        android.forbidAllowBackup.convention(true)
        android.forbidCleartextTraffic.convention(true)
        android.forbidTestOnly.convention(true)
        android.forbidExportedComponentsWithoutPermission.convention(true)
        android.allowedExportedComponents.convention(emptySet())
        android.forbidWeakNetworkSecurityConfig.convention(true)
        android.forbidDebugSigningCert.convention(true)
        android.requireV2OrV3Signing.convention(true)
        android.expectedSigningDigestsSha256.convention(emptySet())
        android.inspectNativeElfLibraries.convention(true)
        android.requireElfHardening.convention(true)
        android.requireElf16KbAlignment.convention(true)
        android.forbiddenArtifactPatterns.convention(AndroidAuditPolicy.DEFAULT_FORBIDDEN_ARTIFACTS)
        android.forbidSensitiveBundledFiles.convention(true)
        android.requireMappingFile.convention(false)
    }

    private fun applyIosTlsAndMiscConventions(project: Project, ext: ReleaseGuardExtension) {
        ext.ios.enabled.convention(false)
        ext.ios.forbidDwarfSections.convention(true)
        ext.ios.maxUnstrippedProjectSymbols.convention(0)
        ext.ios.forbidArbitraryLoads.convention(true)
        ext.ios.forbidAtsHttpExceptions.convention(true)
        ext.ios.forbidDebugProvisioningProfile.convention(true)
        ext.ios.requireMachOPie.convention(true)
        ext.ios.requireCodeSignatureForIpa.convention(true)
        ext.ios.forbidLeakedBuildPaths.convention(true)
        ext.ios.requirePrivacyManifest.convention(false)

        ext.tls.enabled.convention(false)
        ext.tls.requirePins.convention(false)
        ext.tls.minPinsPerHost.convention(2)
        ext.tls.probeLiveHosts.convention(false)
        ext.tls.probeHosts.convention(emptyList())

        ext.secrets.enabled.convention(true)
        ext.secrets.enableHighEntropyScan.convention(true)
        ext.secrets.minEntropyThreshold.convention(4.5)
        ext.secrets.forbidLocalhostEndpointsInRelease.convention(false)
        ext.secrets.extraPatterns.convention(emptyMap())
        ext.secrets.allowlistRegexes.convention(emptyList())

        ext.assetEncryption.enabled.convention(false)
        ext.assetEncryption.bundleExtensions.convention(setOf("awkb"))

        ext.supplyChain.enabled.convention(false)
        ext.supplyChain.forbidSnapshotDependencies.convention(true)

        ext.reports.jsonReport.convention(project.layout.buildDirectory.file("reports/release-guard/scorecard.json"))
        ext.reports.markdownReport.convention(project.layout.buildDirectory.file("reports/release-guard/scorecard.md"))
        ext.reports.sarifReport.convention(project.layout.buildDirectory.file("reports/release-guard/scorecard.sarif"))
        ext.reports.htmlReport.convention(project.layout.buildDirectory.file("reports/release-guard/scorecard.html"))
        ext.reports.failOnRegression.convention(false)
        ext.reports.maxAllowedScoreDrop.convention(0)
        ext.reports.consoleFormat.convention("console")
    }

    private fun registerGenerateRulesTask(
        project: Project,
        ext: ReleaseGuardExtension,
    ): TaskProvider<GenerateReleaseGuardRulesTask> {
        val rulesDir = project.layout.buildDirectory.dir("generated/release-guard/rules")
        return project.tasks.register("generateReleaseGuardRules", GenerateReleaseGuardRulesTask::class.java) { task ->
            task.group = "release guard"
            task.description = "Generate curated desktop ProGuard and Android R8 hardening rules."
            task.mainClass.set(ext.rules.mainClass)
            task.repackageClasses.set(ext.rules.repackageClasses)
            task.allowAccessModification.set(ext.rules.allowAccessModification)
            task.overloadAggressively.set(ext.rules.overloadAggressively)
            task.renameSourceFileAttribute.set(ext.rules.renameSourceFileAttribute)
            task.stripKotlinIntrinsics.set(ext.rules.stripKotlinIntrinsics)
            task.stripKotlinMetadata.set(ext.rules.stripKotlinMetadata)
            task.stripAndroidLogs.set(ext.rules.stripAndroidLogs)
            task.keepKotlinxSerialization.set(ext.rules.keepKotlinxSerialization)
            task.keepEnums.set(ext.rules.keepEnums)
            task.keepJnaLibraries.set(ext.rules.keepJnaLibraries)
            task.keepComposeModifiers.set(ext.rules.keepComposeModifiers)
            task.desktopDontOptimize.set(ext.rules.desktopDontOptimize)
            task.extraRules.set(ext.rules.extraRules)
            task.extraDesktopRules.set(ext.rules.extraDesktopRules)
            task.extraAndroidRules.set(ext.rules.extraAndroidRules)
            task.desktopRulesFile.set(rulesDir.map { it.file("desktop-proguard-rules.pro") })
            task.androidRulesFile.set(rulesDir.map { it.file("android-proguard-rules.pro") })
        }
    }

    private fun registerCollectKeepRulesTask(project: Project, ext: ReleaseGuardExtension) {
        val collectTask = project.tasks.register("collectLibraryKeepRules", CollectLibraryKeepRulesTask::class.java) { task ->
            task.group = "release guard"
            task.description = "Extract META-INF/proguard .pro consumer keep rules from external runtime dependencies."
            task.collectEnabled.set(ext.desktop.collectLibraryKeepRules)
            task.outputDir.set(project.layout.buildDirectory.dir("generated/release-guard/library-keep-rules"))
        }
        project.configurations.matching { it.name == "runtimeClasspath" }.configureEach { cfg ->
            val externalJars = cfg.incoming.artifactView { view ->
                view.componentFilter { it is ModuleComponentIdentifier }
            }.files
            collectTask.configure { it.dependencyJars.from(externalJars) }
        }
    }

    private fun registerHardenWebTask(project: Project, ext: ReleaseGuardExtension) {
        project.tasks.register("hardenWebBundle", HardenWebBundleTask::class.java) { task ->
            task.group = "release guard"
            task.description = "Strip WASM debug/name sections, drop source maps, and emit security _headers."
            task.inputDir.set(ext.web.inputDir)
            task.stripWasmDebugSections.set(ext.web.stripWasmDebugSections)
            task.dropSourceMaps.set(ext.web.dropSourceMaps)
            task.generateSecurityHeaders.set(ext.web.generateSecurityHeaders)
            task.contentSecurityPolicyOverride.set(ext.web.contentSecurityPolicyOverride)
            task.outputDir.set(ext.web.strippedOutputDir)
        }
    }

    private fun registerVerifyTask(project: Project, ext: ReleaseGuardExtension) {
        val verifyTask = project.tasks.register("verifyReleaseGuard", VerifyReleaseGuardTask::class.java) { task ->
            task.group = "verification"
            task.description = "Audit enabled KMP release targets, score hygiene (0..100), export JSON/Markdown/SARIF, and enforce CI gates."
            task.serializedPolicyJson.set(buildPolicyJsonProvider(project, ext))

            task.desktopEnabled.set(ext.desktop.enabled)
            task.desktopGameJarsPath.set(ext.desktop.gameJarsDir.map { it.asFile.absolutePath })
            task.desktopLibrariesPath.set(ext.desktop.librariesDir.map { it.asFile.absolutePath })
            task.desktopMappingPath.set(ext.desktop.mappingFile.map { it.asFile.absolutePath })
            task.desktopNativeLibsPath.set(ext.desktop.nativeLibsDir.map { it.asFile.absolutePath })
            task.desktopJpackagePath.set(ext.desktop.jpackageAppDir.map { it.asFile.absolutePath })
            task.desktopAssetsPath.set(ext.desktop.assetDir.map { it.asFile.absolutePath })

            task.webEnabled.set(ext.web.enabled)
            task.webSitePath.set(ext.web.strippedOutputDir.map { it.asFile.absolutePath })

            task.androidEnabled.set(ext.android.enabled)
            task.androidArtifactPath.set(ext.android.artifactFile.map { it.asFile.absolutePath })
            task.androidMappingPath.set(ext.android.mappingFile.map { it.asFile.absolutePath })

            task.iosEnabled.set(ext.ios.enabled)
            task.iosArtifactPath.set(ext.ios.artifactPath)
            task.iosInfoPlistPath.set(ext.ios.infoPlistFile.map { it.asFile.absolutePath })

            task.tlsEnabled.set(ext.tls.enabled)
            task.tlsSpkiPins.set(ext.tls.spkiPins)
            task.tlsProbeHosts.set(ext.tls.probeHosts)

            task.supplyChainEnabled.set(ext.supplyChain.enabled)
            task.resolvedDependencies.convention(emptyList())

            task.baselinePath.set(ext.reports.baselineFile.map { it.asFile.absolutePath })
            task.consoleFormat.set(ext.reports.consoleFormat)
            task.jsonReportFile.set(ext.reports.jsonReport)
            task.markdownReportFile.set(ext.reports.markdownReport)
            task.sarifReportFile.set(ext.reports.sarifReport)
            task.htmlReportFile.set(ext.reports.htmlReport)
        }

        // Capture resolved external coordinates lazily for supply-chain -SNAPSHOT gating without breaking configuration cache.
        project.configurations.matching { it.name == "runtimeClasspath" || it.name == "releaseRuntimeClasspath" }.configureEach { cfg ->
            val coordsProvider = cfg.incoming.resolutionResult.rootComponent.map { root ->
                val seen = LinkedHashSet<String>()
                fun walk(comp: org.gradle.api.artifacts.result.ResolvedComponentResult) {
                    val id = comp.id
                    if (id is ModuleComponentIdentifier) {
                        seen += "${id.group}:${id.module}:${id.version}"
                    }
                    comp.dependencies
                        .filterIsInstance<org.gradle.api.artifacts.result.ResolvedDependencyResult>()
                        .forEach { dep ->
                            if (seen.add(dep.selected.id.displayName)) {
                                walk(dep.selected)
                            }
                        }
                }
                walk(root)
                seen.filter { ':' in it }.sorted()
            }
            verifyTask.configure { it.resolvedDependencies.addAll(coordsProvider) }
        }
    }
}

private val policyJsonFormat: Json = Json { encodeDefaults = true }

private fun buildPolicyJsonProvider(project: Project, ext: ReleaseGuardExtension): Provider<String> =
    project.providers.provider {
        val sevRaw = ext.failOnSeverity.get().uppercase(Locale.ROOT)
        val policy = ReleaseGuardPolicy(
            projectPackages = ext.projectPackages.get(),
            projectKeywords = ext.projectKeywords.get(),
            minScore = ext.minScore.get(),
            failOnSeverity = if (sevRaw == "NONE") null else CheckSeverity.valueOf(sevRaw),
            allowedLibraryPathPatterns = ext.allowedLibraryPathPatterns.get(),
            disabledChecks = ext.disabledChecks.get(),
            severityOverrides = ext.severityOverrides.get().mapValues { (_, v) -> CheckSeverity.valueOf(v.uppercase(Locale.ROOT)) },
            weightOverrides = ext.weightOverrides.get(),
            desktop = buildDesktopPolicy(ext.desktop),
            android = buildAndroidPolicy(ext.android),
            web = buildWebPolicy(ext.web),
            ios = buildIosPolicy(ext.ios),
            tls = TlsAuditPolicy(
                requirePins = ext.tls.requirePins.get(),
                minPinsPerHost = ext.tls.minPinsPerHost.get(),
                probeLiveHosts = ext.tls.probeLiveHosts.get(),
                probeHosts = ext.tls.probeHosts.get(),
            ),
            secrets = SecretScanPolicy(
                enabled = ext.secrets.enabled.get(),
                enableHighEntropyScan = ext.secrets.enableHighEntropyScan.get(),
                minEntropyThreshold = ext.secrets.minEntropyThreshold.get(),
                forbidLocalhostEndpointsInRelease = ext.secrets.forbidLocalhostEndpointsInRelease.get(),
                extraPatterns = ext.secrets.extraPatterns.get(),
                allowlistRegexes = ext.secrets.allowlistRegexes.get(),
            ),
            assetEncryption = AssetEncryptionPolicy(
                enabled = ext.assetEncryption.enabled.get(),
                bundleExtensions = ext.assetEncryption.bundleExtensions.get(),
            ),
            baseline = BaselinePolicy(
                failOnRegression = ext.reports.failOnRegression.get(),
                maxAllowedScoreDrop = ext.reports.maxAllowedScoreDrop.get(),
            ),
            supplyChain = SupplyChainPolicy(
                forbidSnapshotDependencies = ext.supplyChain.forbidSnapshotDependencies.get(),
            ),
        )
        policyJsonFormat.encodeToString(ReleaseGuardPolicy.serializer(), policy)
    }

private fun buildDesktopPolicy(desktop: DesktopGuardSpec): DesktopAuditPolicy = DesktopAuditPolicy(
    maxOwnReadability = desktop.maxReadability.get(),
    maxKeptProjectClasses = desktop.maxKeptProjectClasses.get(),
    verifyBytecode = desktop.verifyBytecode.get(),
    forbidOriginalSourceFileAttribute = desktop.forbidOriginalSourceFileAttribute.get(),
    forbidDebugTablesAndKotlinMetadata = desktop.forbidDebugTablesAndKotlinMetadata.get(),
    requireMappingFile = desktop.requireMappingFile.get(),
    inspectNativeLibraries = desktop.inspectNativeLibraries.get(),
    requirePeAslrAndDep = desktop.requirePeAslrAndDep.get(),
    forbidLeakedPdbPaths = desktop.forbidLeakedPdbPaths.get(),
    forbidJpackageDebugFlags = desktop.forbidJpackageDebugFlags.get(),
)

private fun buildAndroidPolicy(android: AndroidGuardSpec): AndroidAuditPolicy = AndroidAuditPolicy(
    maxOwnReadability = android.maxReadability.get(),
    maxKeptProjectClasses = android.maxKeptProjectClasses.get(),
    forbidKotlinMetadata = android.forbidKotlinMetadata.get(),
    forbidDebuggable = android.forbidDebuggable.get(),
    forbidAllowBackup = android.forbidAllowBackup.get(),
    forbidCleartextTraffic = android.forbidCleartextTraffic.get(),
    forbidTestOnly = android.forbidTestOnly.get(),
    minTargetSdkVersion = android.minTargetSdkVersion.orNull,
    forbidExportedComponentsWithoutPermission = android.forbidExportedComponentsWithoutPermission.get(),
    allowedExportedComponents = android.allowedExportedComponents.get(),
    forbidWeakNetworkSecurityConfig = android.forbidWeakNetworkSecurityConfig.get(),
    forbidDebugSigningCert = android.forbidDebugSigningCert.get(),
    requireV2OrV3Signing = android.requireV2OrV3Signing.get(),
    expectedSigningDigestsSha256 = android.expectedSigningDigestsSha256.get(),
    inspectNativeElfLibraries = android.inspectNativeElfLibraries.get(),
    requireElfHardening = android.requireElfHardening.get(),
    requireElf16KbAlignment = android.requireElf16KbAlignment.get(),
    forbiddenArtifactPatterns = android.forbiddenArtifactPatterns.get(),
    forbidSensitiveBundledFiles = android.forbidSensitiveBundledFiles.get(),
    requireMappingFile = android.requireMappingFile.get(),
)

private fun buildWebPolicy(web: WebGuardSpec): WebAuditPolicy = WebAuditPolicy(
    mode = WebAuditMode.valueOf(web.mode.get().uppercase(Locale.ROOT)),
    maxReadability = web.maxReadability.get(),
    forbidSourceMaps = web.dropSourceMaps.get(),
    forbidDebugSections = web.stripWasmDebugSections.get(),
    forbidProjectSourcePaths = web.forbidProjectSourcePaths.get(),
    maxQualifiedProjectClasses = web.maxQualifiedProjectClasses.orNull,
    requireSecurityHeaders = web.requireSecurityHeaders.get(),
    gradeCspQuality = web.gradeCspQuality.get(),
    allowWasmUnsafeEvalInCsp = web.allowWasmUnsafeEvalInCsp.get(),
    requireSubresourceIntegrity = web.requireSubresourceIntegrity.get(),
    sriAllowlistHosts = web.sriAllowlistHosts.get(),
    forbidInsecureWebEndpoints = web.forbidInsecureWebEndpoints.get(),
    forbidDebuggerStatements = web.forbidDebuggerStatements.get(),
    forbidSensitiveDistFiles = web.forbidSensitiveDistFiles.get(),
    maxWasmExports = web.maxWasmExports.orNull,
)

private fun buildIosPolicy(ios: IosGuardSpec): IosAuditPolicy = IosAuditPolicy(
    forbidDwarfSections = ios.forbidDwarfSections.get(),
    maxUnstrippedProjectSymbols = ios.maxUnstrippedProjectSymbols.get(),
    forbidArbitraryLoads = ios.forbidArbitraryLoads.get(),
    forbidAtsHttpExceptions = ios.forbidAtsHttpExceptions.get(),
    forbidDebugProvisioningProfile = ios.forbidDebugProvisioningProfile.get(),
    requireMachOPie = ios.requireMachOPie.get(),
    requireCodeSignatureForIpa = ios.requireCodeSignatureForIpa.get(),
    forbidLeakedBuildPaths = ios.forbidLeakedBuildPaths.get(),
    requirePrivacyManifest = ios.requirePrivacyManifest.get(),
)

private object KotlinWasmHardeningHook {
    fun wire(project: Project, ext: ReleaseGuardExtension) {
        project.tasks.withType(KotlinJsIrLink::class.java)
            .matching { "Production" in it.name }
            .configureEach { task ->
                task.compilerOptions.freeCompilerArgs.addAll(
                    ext.web.stripKclassFqn.map { strip ->
                        if (strip) listOf("-Xwasm-kclass-fqn=false") else emptyList()
                    },
                )
            }
        project.tasks.withType(BinaryenExec::class.java).configureEach { task ->
            val propName = ext.web.profilingNamesProperty.get()
            if (project.providers.gradleProperty(propName).orNull == "true") {
                task.binaryenArguments.add("-g")
            }
        }
    }
}

private object AndroidReleaseHardeningHook {
    fun wire(
        project: Project,
        ext: ReleaseGuardExtension,
        generateRules: TaskProvider<GenerateReleaseGuardRulesTask>,
    ) {
        project.extensions.configure(ApplicationAndroidComponentsExtension::class.java) { components ->
            components.finalizeDsl { androidExt ->
                if (!ext.android.autoConfigureReleaseHardening.get()) return@finalizeDsl
                androidExt.packaging {
                    resources {
                        excludes += listOf(
                            "/META-INF/version-control-info.textproto",
                            "/DebugProbesKt.bin",
                            "/kotlin-tooling-metadata.json",
                        )
                    }
                }
                androidExt.buildTypes.named("release") { releaseType ->
                    releaseType.vcsInfo.include = false
                    releaseType.proguardFile(generateRules.flatMap { it.androidRulesFile })
                }
            }
            components.onVariants { variant ->
                if (variant.buildType == "release" && ext.android.autoConfigureReleaseHardening.get()) {
                    variant.packaging.jniLibs.excludes.add("**/libVkLayer_khronos_validation.so")
                }
            }
        }
        project.tasks.matching { it.name.contains("Release") && (it.name.startsWith("minify") || it.name.startsWith("merge")) }
            .configureEach { it.dependsOn(generateRules) }
    }
}

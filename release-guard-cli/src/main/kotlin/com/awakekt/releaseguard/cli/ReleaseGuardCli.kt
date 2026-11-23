/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.cli

import com.awakekt.releaseguard.ReleaseGuardAuditor
import com.awakekt.releaseguard.ReleaseGuardRequest
import com.awakekt.releaseguard.analyzers.AndroidAuditInput
import com.awakekt.releaseguard.analyzers.AssetAuditInput
import com.awakekt.releaseguard.analyzers.DesktopAuditInput
import com.awakekt.releaseguard.analyzers.IosAuditInput
import com.awakekt.releaseguard.analyzers.SpirvShaderInspector
import com.awakekt.releaseguard.analyzers.TlsAuditInput
import com.awakekt.releaseguard.analyzers.TlsPinAnalyzer
import com.awakekt.releaseguard.analyzers.WebAuditInput
import com.awakekt.releaseguard.analyzers.WebBundleStripper
import com.awakekt.releaseguard.analyzers.WebStripOptions
import com.awakekt.releaseguard.model.CheckSeverity
import com.awakekt.releaseguard.model.ReleaseGuardPolicies
import com.awakekt.releaseguard.model.ReleaseGuardPolicy
import com.awakekt.releaseguard.model.WebAuditMode
import com.awakekt.releaseguard.report.HtmlReportRenderer
import com.awakekt.releaseguard.report.ReleaseGuardReportRenderer
import com.awakekt.releaseguard.report.SarifReportRenderer
import kotlinx.serialization.json.Json
import java.io.File
import java.io.PrintStream
import java.util.Locale
import kotlin.system.exitProcess

/**
 * Standalone Release Guard CLI for auditing KMP release binaries, stripping web bundles,
 * printing live TLS SPKI pins, comparing against baselines, and exporting JSON/Markdown/SARIF reports.
 */
public object ReleaseGuardCli {
    private val json = Json {
        prettyPrint = true
        encodeDefaults = true
        ignoreUnknownKeys = true
    }

    /** Executes the CLI with [args] and returns a POSIX exit code (`0` pass, `1` gate fail, `2` usage error). */
    public fun execute(
        args: Array<String>,
        out: PrintStream = System.out,
        err: PrintStream = System.err,
    ): Int {
        if (args.isEmpty() || args[0] in setOf("--help", "-h", "help")) {
            out.println(USAGE_TEXT)
            return 0
        }
        return try {
            when (args[0]) {
                "audit" -> runAudit(args.drop(1), out, err)
                "strip-web" -> runStripWeb(args.drop(1), out)
                "strip-spirv" -> runStripSpirv(args.drop(1), out)
                "print-tls-pins" -> runPrintTlsPins(args.drop(1), out)
                "init-policy" -> runInitPolicy(args.drop(1), out)
                else -> {
                    err.println("Unknown command '${args[0]}'. Run with --help for usage.")
                    2
                }
            }
        } catch (error: IllegalArgumentException) {
            err.println("error: ${error.message}")
            2
        }
    }

    private fun runAudit(args: List<String>, out: PrintStream, err: PrintStream): Int {
        val parsed = parseAuditArgs(args)
        val policy = resolveAuditPolicy(parsed)
        val request = buildAuditRequest(parsed, policy)
        val scorecard = ReleaseGuardAuditor.audit(request)

        parsed.jsonOut?.let { file ->
            file.parentFile?.mkdirs()
            file.writeText(ReleaseGuardReportRenderer.renderJson(scorecard), Charsets.UTF_8)
        }
        parsed.markdownOut?.let { file ->
            file.parentFile?.mkdirs()
            file.writeText(ReleaseGuardReportRenderer.renderMarkdown(scorecard), Charsets.UTF_8)
        }
        parsed.sarifOut?.let { file ->
            file.parentFile?.mkdirs()
            file.writeText(SarifReportRenderer.renderSarif(scorecard), Charsets.UTF_8)
        }
        parsed.htmlOut?.let { file ->
            file.parentFile?.mkdirs()
            file.writeText(HtmlReportRenderer.renderHtml(scorecard), Charsets.UTF_8)
        }
        val rendered = when (parsed.format) {
            "json" -> ReleaseGuardReportRenderer.renderJson(scorecard)
            "markdown", "md" -> ReleaseGuardReportRenderer.renderMarkdown(scorecard)
            "sarif" -> SarifReportRenderer.renderSarif(scorecard)
            "html" -> HtmlReportRenderer.renderHtml(scorecard)
            else -> ReleaseGuardReportRenderer.renderConsole(scorecard)
        }
        out.print(rendered)
        if (!scorecard.passedGate) {
            err.println("Release Guard gate failed (score=${scorecard.overallScore}/${policy.minScore}).")
            return 1
        }
        return 0
    }

    private fun resolveAuditPolicy(parsed: ParsedAuditArgs): ReleaseGuardPolicy {
        val base = parsed.policyFile?.let { file ->
            require(file.isFile) { "Policy JSON file does not exist: ${file.path}" }
            json.decodeFromString(ReleaseGuardPolicy.serializer(), file.readText(Charsets.UTF_8))
        } ?: when (parsed.preset) {
            "strict" -> ReleaseGuardPolicies.strictRelease()
            "dev", "development" -> ReleaseGuardPolicies.developmentAudit()
            else -> ReleaseGuardPolicies.balancedRelease()
        }
        return applyCliPolicyOverrides(base, parsed)
    }

    private fun buildAuditRequest(parsed: ParsedAuditArgs, policy: ReleaseGuardPolicy): ReleaseGuardRequest {
        val baseline = parsed.baselineFile?.let { file ->
            require(file.isFile) { "Baseline scorecard JSON does not exist: ${file.path}" }
            ReleaseGuardReportRenderer.parseJson(file.readText(Charsets.UTF_8))
        }
        val assetsInput = if (parsed.assetDirs.isNotEmpty() || parsed.shaderDirs.isNotEmpty()) {
            AssetAuditInput(assetDirectories = parsed.assetDirs, shaderDirectories = parsed.shaderDirs)
        } else {
            null
        }
        val request = ReleaseGuardRequest(
            policy = policy,
            desktop = parsed.desktopJars?.let {
                DesktopAuditInput(
                    gameJarsDirectory = it,
                    librariesDirectory = parsed.desktopLibs,
                    mappingFile = parsed.desktopMapping,
                    nativeLibsDirectory = parsed.desktopNativeLibs,
                    jpackageAppDirectory = parsed.desktopJpackageDir,
                    assetDirectory = parsed.desktopAssets,
                )
            },
            android = parsed.androidArtifact?.let { AndroidAuditInput(it, parsed.androidMapping) },
            web = parsed.webDir?.let { WebAuditInput(it) },
            ios = parsed.iosArtifact?.let { IosAuditInput(it, parsed.iosPlist) },
            tls = parsed.tlsPins?.let { TlsAuditInput(it, parsed.tlsProbeHosts) },
            assets = assetsInput,
            baseline = baseline,
            customCheckClassNames = parsed.customCheckClasses,
            customParameters = parsed.customParams,
        )
        val hasAnyTarget =
            listOf(request.desktop, request.android, request.web, request.ios, request.tls, request.assets).any { it != null } ||
                request.customCheckClassNames.isNotEmpty()
        require(hasAnyTarget) {
            "Pass at least one target (--desktop-jars, --android-apk, --android-aab, --web-dir, --ios-artifact, --asset-dir, --shader-dir, --tls-pins, or --custom-check-class)."
        }
        return request
    }

    private fun runStripSpirv(args: List<String>, out: PrintStream): Int {
        var input: File? = null
        var output: File? = null
        var i = 0
        while (i < args.size) {
            when (args[i]) {
                "--input" -> { input = File(requireArgValue(args, i)); i += 2 }
                "--output" -> { output = File(requireArgValue(args, i)); i += 2 }
                else -> throw IllegalArgumentException("Unknown strip-spirv option '${args[i]}'.")
            }
        }
        val inDir = requireNotNull(input) { "strip-spirv requires --input <dir>." }
        val outDir = requireNotNull(output) { "strip-spirv requires --output <dir>." }
        require(inDir.isDirectory) { "Input directory does not exist: ${inDir.path}" }
        var count = 0
        var savedBytes = 0L
        inDir.walkTopDown().filter { it.isFile && it.extension.equals("spv", ignoreCase = true) }.forEach { file ->
            val raw = file.readBytes()
            val stripped = SpirvShaderInspector.stripDebugOpcodes(raw)
            val target = outDir.resolve(file.relativeTo(inDir))
            target.parentFile?.mkdirs()
            target.writeBytes(stripped)
            count++
            savedBytes += (raw.size - stripped.size).coerceAtLeast(0)
        }
        out.println("Stripped $count SPIR-V shader(s) into ${outDir.path} (saved $savedBytes bytes).")
        return 0
    }

    private fun runStripWeb(args: List<String>, out: PrintStream): Int {
        var input: File? = null
        var output: File? = null
        var generateHeaders = true
        var stripWasm = true
        var cspOverride: String? = null
        var i = 0
        while (i < args.size) {
            when (args[i]) {
                "--input" -> { input = File(requireArgValue(args, i)); i += 2 }
                "--output" -> { output = File(requireArgValue(args, i)); i += 2 }
                "--no-headers" -> { generateHeaders = false; i += 1 }
                "--no-strip-wasm" -> { stripWasm = false; i += 1 }
                "--csp" -> { cspOverride = requireArgValue(args, i); i += 2 }
                else -> throw IllegalArgumentException("Unknown strip-web option '${args[i]}'.")
            }
        }
        val inDir = requireNotNull(input) { "strip-web requires --input <dir>." }
        val outDir = requireNotNull(output) { "strip-web requires --output <dir>." }
        val report = WebBundleStripper.harden(
            inputDir = inDir,
            outputDir = outDir,
            options = WebStripOptions(
                stripWasmDebugSections = stripWasm,
                generateSecurityHeaders = generateHeaders,
                contentSecurityPolicyOverride = cspOverride,
            ),
        )
        out.println(
            "Hardened web bundle into ${outDir.path}: copied=${report.copiedFiles}, " +
                "droppedMaps=${report.droppedSourceMaps.size}, droppedSensitive=${report.droppedSensitiveFiles.size}, " +
                "strippedWasmBytes=${report.strippedWasmBytesSaved}, headers=${report.wroteHeadersFile}",
        )
        return 0
    }

    private fun runPrintTlsPins(args: List<String>, out: PrintStream): Int {
        require(args.isNotEmpty()) { "print-tls-pins requires at least one hostname." }
        out.println(TlsPinAnalyzer.fetchLivePinSpec(args))
        return 0
    }

    private fun runInitPolicy(args: List<String>, out: PrintStream): Int {
        var output: File? = null
        var preset = "balanced"
        val packages = mutableListOf<String>()
        var i = 0
        while (i < args.size) {
            when (args[i]) {
                "--output" -> { output = File(requireArgValue(args, i)); i += 2 }
                "--preset" -> { preset = requireArgValue(args, i).lowercase(Locale.ROOT); i += 2 }
                "--project-package" -> { packages += requireArgValue(args, i); i += 2 }
                else -> throw IllegalArgumentException("Unknown init-policy option '${args[i]}'.")
            }
        }
        val policy = when (preset) {
            "strict" -> ReleaseGuardPolicies.strictRelease(projectPackages = packages)
            "dev", "development" -> ReleaseGuardPolicies.developmentAudit(projectPackages = packages)
            else -> ReleaseGuardPolicies.balancedRelease(projectPackages = packages)
        }
        val encoded = json.encodeToString(ReleaseGuardPolicy.serializer(), policy) + "\n"
        if (output != null) {
            output.parentFile?.mkdirs()
            output.writeText(encoded, Charsets.UTF_8)
            out.println("Wrote starter Release Guard policy to ${output.path}")
        } else {
            out.print(encoded)
        }
        return 0
    }

    internal data class ParsedAuditArgs(
        val policyFile: File? = null,
        val preset: String = "balanced",
        val projectPackages: List<String> = emptyList(),
        val projectKeywords: List<String> = emptyList(),
        val minScore: Int? = null,
        val failOnSeveritySet: Boolean = false,
        val failOnSeverity: CheckSeverity? = null,
        val webMode: WebAuditMode? = null,
        val desktopJars: File? = null,
        val desktopLibs: File? = null,
        val desktopMapping: File? = null,
        val desktopNativeLibs: File? = null,
        val desktopJpackageDir: File? = null,
        val desktopAssets: File? = null,
        val androidArtifact: File? = null,
        val androidMapping: File? = null,
        val webDir: File? = null,
        val iosArtifact: File? = null,
        val iosPlist: File? = null,
        val tlsPins: String? = null,
        val tlsProbeHosts: List<String> = emptyList(),
        val probeLiveTls: Boolean = false,
        val baselineFile: File? = null,
        val failOnRegression: Boolean = false,
        val requireEncryptedAssets: Boolean = false,
        val format: String = "console",
        val jsonOut: File? = null,
        val markdownOut: File? = null,
        val sarifOut: File? = null,
        val htmlOut: File? = null,
        val forbiddenClasses: List<String> = emptyList(),
        val ownJarNames: Set<String> = emptySet(),
        val assetDirs: List<File> = emptyList(),
        val shaderDirs: List<File> = emptyList(),
        val customCheckClasses: List<String> = emptyList(),
        val customParams: Map<String, String> = emptyMap(),
    )

    @Suppress("CyclomaticComplexMethod", "LongMethod")
    private fun parseAuditArgs(args: List<String>): ParsedAuditArgs {
        var state = ParsedAuditArgs()
        val packages = mutableListOf<String>()
        val keywords = mutableListOf<String>()
        val probeHosts = mutableListOf<String>()
        val forbiddenClasses = mutableListOf<String>()
        val ownJarNames = linkedSetOf<String>()
        val assetDirs = mutableListOf<File>()
        val shaderDirs = mutableListOf<File>()
        val customCheckClasses = mutableListOf<String>()
        val customParams = linkedMapOf<String, String>()
        var i = 0
        while (i < args.size) {
            when (val flag = args[i]) {
                "--config" -> { state = state.copy(policyFile = File(requireArgValue(args, i))); i += 2 }
                "--preset" -> { state = state.copy(preset = requireArgValue(args, i).lowercase(Locale.ROOT)); i += 2 }
                "--project-package" -> { packages += requireArgValue(args, i); i += 2 }
                "--project-keyword" -> { keywords += requireArgValue(args, i); i += 2 }
                "--min-score" -> { state = state.copy(minScore = requireArgValue(args, i).toInt()); i += 2 }
                "--fail-on-severity" -> {
                    val raw = requireArgValue(args, i).uppercase(Locale.ROOT)
                    state = state.copy(
                        failOnSeveritySet = true,
                        failOnSeverity = if (raw == "NONE") null else CheckSeverity.valueOf(raw),
                    )
                    i += 2
                }
                "--web-mode" -> {
                    state = state.copy(webMode = WebAuditMode.valueOf(requireArgValue(args, i).uppercase(Locale.ROOT)))
                    i += 2
                }
                "--desktop-jars" -> { state = state.copy(desktopJars = File(requireArgValue(args, i))); i += 2 }
                "--desktop-libs" -> { state = state.copy(desktopLibs = File(requireArgValue(args, i))); i += 2 }
                "--desktop-mapping" -> { state = state.copy(desktopMapping = File(requireArgValue(args, i))); i += 2 }
                "--desktop-native-libs" -> { state = state.copy(desktopNativeLibs = File(requireArgValue(args, i))); i += 2 }
                "--desktop-jpackage-dir" -> { state = state.copy(desktopJpackageDir = File(requireArgValue(args, i))); i += 2 }
                "--desktop-assets" -> { state = state.copy(desktopAssets = File(requireArgValue(args, i))); i += 2 }
                "--own-jar" -> { ownJarNames += requireArgValue(args, i); i += 2 }
                "--forbid-class" -> { forbiddenClasses += requireArgValue(args, i); i += 2 }
                "--asset-dir" -> { assetDirs += File(requireArgValue(args, i)); i += 2 }
                "--shader-dir" -> { shaderDirs += File(requireArgValue(args, i)); i += 2 }
                "--custom-check-class" -> { customCheckClasses += requireArgValue(args, i); i += 2 }
                "--custom-param" -> {
                    val entry = requireArgValue(args, i)
                    val eq = entry.indexOf('=')
                    require(eq > 0) { "--custom-param expects key=value, got '$entry'." }
                    customParams[entry.substring(0, eq)] = entry.substring(eq + 1)
                    i += 2
                }
                "--android-apk", "--android-aab", "--android-artifact" -> {
                    state = state.copy(androidArtifact = File(requireArgValue(args, i)))
                    i += 2
                }
                "--android-mapping" -> { state = state.copy(androidMapping = File(requireArgValue(args, i))); i += 2 }
                "--web-dir" -> { state = state.copy(webDir = File(requireArgValue(args, i))); i += 2 }
                "--ios-framework", "--ios-artifact" -> { state = state.copy(iosArtifact = File(requireArgValue(args, i))); i += 2 }
                "--ios-plist" -> { state = state.copy(iosPlist = File(requireArgValue(args, i))); i += 2 }
                "--tls-pins" -> { state = state.copy(tlsPins = requireArgValue(args, i)); i += 2 }
                "--tls-probe-host" -> { probeHosts += requireArgValue(args, i); i += 2 }
                "--tls-probe-live" -> { state = state.copy(probeLiveTls = true); i += 1 }
                "--baseline" -> { state = state.copy(baselineFile = File(requireArgValue(args, i))); i += 2 }
                "--fail-on-regression" -> { state = state.copy(failOnRegression = true); i += 1 }
                "--require-encrypted-assets" -> { state = state.copy(requireEncryptedAssets = true); i += 1 }
                "--format" -> { state = state.copy(format = requireArgValue(args, i).lowercase(Locale.ROOT)); i += 2 }
                "--json-out" -> { state = state.copy(jsonOut = File(requireArgValue(args, i))); i += 2 }
                "--markdown-out" -> { state = state.copy(markdownOut = File(requireArgValue(args, i))); i += 2 }
                "--sarif-out" -> { state = state.copy(sarifOut = File(requireArgValue(args, i))); i += 2 }
                "--html-out" -> { state = state.copy(htmlOut = File(requireArgValue(args, i))); i += 2 }
                else -> throw IllegalArgumentException("Unknown audit option '$flag'.")
            }
        }
        return state.copy(
            projectPackages = packages,
            projectKeywords = keywords,
            tlsProbeHosts = probeHosts,
            forbiddenClasses = forbiddenClasses,
            ownJarNames = ownJarNames,
            assetDirs = assetDirs,
            shaderDirs = shaderDirs,
            customCheckClasses = customCheckClasses,
            customParams = customParams,
        )
    }

    private fun requireArgValue(args: List<String>, flagIndex: Int): String {
        require(flagIndex + 1 < args.size) { "Missing value after '${args[flagIndex]}'." }
        return args[flagIndex + 1]
    }

    private const val USAGE_TEXT: String = """
Release Guard - KMP Release Hardening & Hygiene Auditor CLI

Usage:
  audit [options]
    --config <policy.json>           Load a ReleaseGuardPolicy JSON file
    --preset <strict|balanced|dev>   Policy preset when --config is omitted
    --project-package <pkg>          Repeatable project package prefix
    --project-keyword <kw>           Repeatable project keyword to flag in readability checks
    --min-score <0..100>             Minimum overall release hygiene score to pass gate
    --fail-on-severity <level>       CRITICAL|HIGH|MEDIUM|LOW|INFO|NONE
    --desktop-jars <dir>             Directory of obfuscated desktop game JARs
    --desktop-libs <dir>             Directory of desktop runtime library JARs
    --desktop-mapping <file>         External ProGuard mapping.txt path
    --desktop-native-libs <dir>      Directory of desktop native .dll/.so/.dylib libraries
    --desktop-jpackage-dir <dir>     jpackage app directory containing *.cfg launcher configs
    --desktop-assets <dir>           Directory of packaged content bundles (.awkb)
    --own-jar <jar-name>             Repeatable own-game JAR filename to scope desktop readability checks
    --forbid-class <fqcn>            Repeatable forbidden class FQCN checked in bytecode & mapping.txt
    --asset-dir <dir>                Repeatable directory audited for raw 3D models & encrypted containers
    --shader-dir <dir>               Repeatable directory audited for SPIR-V debug info & raw shaders
    --custom-check-class <fqcn>      Repeatable ReleaseGuardCheck / ReleaseGuardCheckProvider class
    --custom-param <key=value>       Repeatable custom key=value parameter passed to callbacks
    --android-apk <file>             Android release APK path
    --android-aab <file>             Android App Bundle (.aab) path
    --android-mapping <file>         External R8 mapping.txt path
    --web-dir <dir>                  Web (Kotlin/Wasm + JS) distribution directory
    --web-mode <production|preview>
    --ios-artifact <path>            iOS .framework, .xcframework, .ipa, or Mach-O binary
    --ios-plist <file>               Optional Info.plist override (XML or binary bplist00)
    --tls-pins <spec>                TLS SPKI pin spec ('host=sha256/<b64>,...')
    --tls-probe-live                 Verify pins against live TLS handshakes
    --tls-probe-host <host>          Repeatable host to probe against wildcard pin rules
    --baseline <scorecard.json>      Compare against a previous JSON scorecard for regressions
    --fail-on-regression             Fail gate if score drops or new failures appear vs baseline
    --require-encrypted-assets       Enforce encrypted content bundle headers (.awkb v2 flag)
    --format <console|json|markdown|sarif|html>
    --json-out <file>                Write machine-readable JSON scorecard
    --markdown-out <file>            Write Markdown scorecard summary
    --sarif-out <file>               Write SARIF 2.1.0 JSON for GitHub Code Scanning
    --html-out <file>                Write interactive HTML dashboard with plain-English explanations

  strip-web --input <dir> --output <dir> [--no-headers] [--no-strip-wasm] [--csp <policy>]
  strip-spirv --input <dir> --output <dir>
  print-tls-pins <host> [<host>...]
  init-policy [--preset <strict|balanced|dev>] [--project-package <pkg>] [--output <file>]
"""
}

private fun applyCliPolicyOverrides(
    base: ReleaseGuardPolicy,
    parsed: ReleaseGuardCli.ParsedAuditArgs,
): ReleaseGuardPolicy {
    var policy = applyCoreOverrides(base, parsed)
    if (parsed.webMode != null) policy = policy.copy(web = policy.web.copy(mode = parsed.webMode))
    if (parsed.probeLiveTls) policy = policy.copy(tls = policy.tls.copy(probeLiveHosts = true))
    if (parsed.requireEncryptedAssets) policy = policy.copy(assetEncryption = policy.assetEncryption.copy(enabled = true))
    if (parsed.forbiddenClasses.isNotEmpty()) {
        policy = policy.copy(
            desktop = policy.desktop.copy(forbiddenClasses = parsed.forbiddenClasses),
            android = policy.android.copy(forbiddenClasses = parsed.forbiddenClasses),
        )
    }
    if (parsed.ownJarNames.isNotEmpty()) policy = policy.copy(desktop = policy.desktop.copy(ownJarNames = parsed.ownJarNames))
    if (parsed.assetDirs.isNotEmpty()) policy = policy.copy(assetSecurity = policy.assetSecurity.copy(enabled = true))
    if (parsed.shaderDirs.isNotEmpty()) policy = policy.copy(shaderSecurity = policy.shaderSecurity.copy(enabled = true))
    return policy
}

private fun applyCoreOverrides(
    base: ReleaseGuardPolicy,
    parsed: ReleaseGuardCli.ParsedAuditArgs,
): ReleaseGuardPolicy {
    var policy = base
    if (parsed.projectPackages.isNotEmpty()) policy = policy.copy(projectPackages = parsed.projectPackages)
    if (parsed.projectKeywords.isNotEmpty()) policy = policy.copy(projectKeywords = parsed.projectKeywords)
    if (parsed.minScore != null) policy = policy.copy(minScore = parsed.minScore)
    if (parsed.failOnSeveritySet) policy = policy.copy(failOnSeverity = parsed.failOnSeverity)
    if (parsed.failOnRegression) policy = policy.copy(baseline = policy.baseline.copy(failOnRegression = true))
    return policy
}

/** CLI process entrypoint. */
public fun main(args: Array<String>) {
    exitProcess(ReleaseGuardCli.execute(args))
}

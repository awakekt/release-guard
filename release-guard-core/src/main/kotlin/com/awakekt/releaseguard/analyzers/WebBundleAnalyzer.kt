/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.analyzers

import com.awakekt.releaseguard.io.BinaryReadLimits
import com.awakekt.releaseguard.io.BoundedBinaryIo
import com.awakekt.releaseguard.model.AuditFinding
import com.awakekt.releaseguard.model.AuditTarget
import com.awakekt.releaseguard.model.CheckSeverity
import com.awakekt.releaseguard.model.CheckStatus
import com.awakekt.releaseguard.model.ReleaseGuardPolicy
import com.awakekt.releaseguard.model.WebAuditMode
import java.io.File
import java.util.Locale

/** Inputs for auditing a compiled Web (Kotlin/Wasm + JS) distribution directory. */
public data class WebAuditInput(
    public val siteDirectory: File,
)

/**
 * Audits Kotlin/Wasm and JS web bundles for source-map leaks (JS & CSS), WASM debug sections &
 * export surface, identifier readability, leaked `.kt` paths, FQN counts, `_headers` presence and
 * CSP directive quality, Subresource Integrity (SRI), insecure `ws://`/`http://` endpoints,
 * `debugger;` residue, sensitive dist files, and embedded secrets.
 */
public object WebBundleAnalyzer {
    private val bundleExtensions = setOf("wasm", "js", "mjs")
    private val textExtensions = setOf("js", "mjs", "html", "css", "json", "txt", "svg", "wasm")
    private val externalScriptRegex = Regex("""<script\b[^>]*\bsrc\s*=\s*["'](https?://[^"']+)["'][^>]*>""", RegexOption.IGNORE_CASE)
    private val externalLinkRegex = Regex("""<link\b[^>]*\bhref\s*=\s*["'](https?://[^"']+)["'][^>]*>""", RegexOption.IGNORE_CASE)
    private val debuggerStmtRegex = Regex("""\bdebugger\s*;""")

    /** Audits [input] under [policy]. */
    public fun analyze(
        input: WebAuditInput,
        policy: ReleaseGuardPolicy,
        limits: BinaryReadLimits = BinaryReadLimits(),
    ): AnalyzerOutput {
        val site = input.siteDirectory
        if (!site.isDirectory) return missingWebDirOutput(site)

        val allFiles = site.walkTopDown().filter { it.isFile }.sortedBy { it.relativeTo(site).invariantSeparatorsPath }.toList()
        val bundleFiles = site.listFiles()?.filter { it.isFile && it.extension in bundleExtensions }?.sortedBy { it.name }.orEmpty()
        val wasmFiles = bundleFiles.filter { it.extension == "wasm" }
        val metrics = linkedMapOf(
            "web.bundleFileCount" to bundleFiles.size.toString(),
            "web.wasmTotalBytes" to wasmFiles.sumOf { it.length() }.toString(),
        )

        val bundleStringsByFile = bundleFiles.associateWith { file ->
            IdentifierHeuristics.extractPrintableStrings(BoundedBinaryIo.readFileBounded(file, limits.maxSingleFileBytes))
        }
        val allBundleStrings = bundleStringsByFile.values.flatten()

        val findings = listOf(
            checkSourceMaps(site, allFiles, policy, limits),
            checkWasmDebugSections(wasmFiles, policy, limits, metrics),
            checkWasmExports(wasmFiles, policy, limits, metrics),
            checkReadability(allBundleStrings, policy, metrics),
            checkSourcePaths(allBundleStrings, policy, metrics),
            checkQualifiedClassNames(wasmFiles, bundleStringsByFile, policy, metrics),
            checkSecurityHeadersAndCspQuality(site, policy),
            checkSubresourceIntegrity(site, allFiles, policy, limits),
            checkInsecureEndpointsAndDebugger(bundleFiles, bundleStringsByFile, policy, limits),
            checkSensitiveDistFiles(site, allFiles, policy),
            checkWebSecrets(bundleStringsByFile, policy),
        )
        return AnalyzerOutput(findings = findings, metrics = metrics)
    }

    private fun checkSourceMaps(
        site: File,
        allFiles: List<File>,
        policy: ReleaseGuardPolicy,
        limits: BinaryReadLimits,
    ): AuditFinding {
        if (!policy.web.forbidSourceMaps) {
            return AuditFinding(
                checkId = "web.sourcemaps.absent",
                target = AuditTarget.WEB_WASM,
                title = "Web source maps excluded",
                status = CheckStatus.SKIP,
                severity = CheckSeverity.HIGH,
                weight = 15,
                summary = "Source map check disabled by policy.",
            )
        }
        val leaks = mutableListOf<String>()
        for (file in allFiles) {
            val rel = file.relativeTo(site).invariantSeparatorsPath
            if (file.extension == "map") {
                leaks += "map:$rel"
            } else if (file.extension in textExtensions && file.length() <= limits.maxSingleFileBytes) {
                val bytes = BoundedBinaryIo.readFileBounded(file, limits.maxSingleFileBytes)
                if (containsAscii(bytes, "sourceMappingURL")) {
                    leaks += "sourceMappingURL:$rel"
                }
            }
        }
        val passed = leaks.isEmpty()
        return AuditFinding(
            checkId = "web.sourcemaps.absent",
            target = AuditTarget.WEB_WASM,
            title = "Web source maps excluded",
            status = if (passed) CheckStatus.PASS else CheckStatus.FAIL,
            severity = CheckSeverity.HIGH,
            weight = 15,
            summary = if (passed) {
                "No .map files or JS/CSS sourceMappingURL references found in web bundle."
            } else {
                "Found ${leaks.size} source map file(s) or sourceMappingURL reference(s)."
            },
            evidence = leaks.take(10),
            remediation = "Run WebBundleStripper / hardenWebBundle to drop *.map files and strip JS/CSS sourceMappingURL comments.",
        )
    }

    private fun checkWasmDebugSections(
        wasmFiles: List<File>,
        policy: ReleaseGuardPolicy,
        limits: BinaryReadLimits,
        metrics: MutableMap<String, String>,
    ): AuditFinding {
        if (wasmFiles.isEmpty()) {
            return AuditFinding(
                checkId = "web.wasm.debug_sections",
                target = AuditTarget.WEB_WASM,
                title = "WASM debug and name sections stripped",
                status = CheckStatus.FAIL,
                severity = CheckSeverity.HIGH,
                weight = 15,
                summary = "No top-level .wasm module found in web bundle directory.",
                remediation = "Point the audit at the wasmJs productionExecutable or hardened site output.",
            )
        }
        val debugLeaks = mutableListOf<String>()
        for (wasm in wasmFiles) {
            val sections = WasmBinaryInspector.readSections(BoundedBinaryIo.readFileBounded(wasm, limits.maxSingleFileBytes))
            sections.filter(WasmBinaryInspector::isDebugSection).forEach { sec ->
                debugLeaks += "${wasm.name}:\"${sec.name}\" (${sec.sizeBytes} B)"
            }
        }
        metrics["web.wasmDebugSectionCount"] = debugLeaks.size.toString()

        val enforce = policy.web.mode == WebAuditMode.PRODUCTION && policy.web.forbidDebugSections
        val status = when {
            debugLeaks.isEmpty() -> CheckStatus.PASS
            enforce -> CheckStatus.FAIL
            else -> CheckStatus.WARN
        }
        return AuditFinding(
            checkId = "web.wasm.debug_sections",
            target = AuditTarget.WEB_WASM,
            title = "WASM debug and name sections stripped",
            status = status,
            severity = CheckSeverity.HIGH,
            weight = 15,
            summary = if (debugLeaks.isEmpty()) {
                "All ${wasmFiles.size} WASM module(s) are free of name, producers, and debug custom sections."
            } else {
                "Found ${debugLeaks.size} WASM debug/name custom section(s) (mode=${policy.web.mode})."
            },
            evidence = debugLeaks.take(10),
            remediation = "Build production WASM without -g and strip custom debug/name/producers sections with hardenWebBundle.",
        )
    }

    private fun checkWasmExports(
        wasmFiles: List<File>,
        policy: ReleaseGuardPolicy,
        limits: BinaryReadLimits,
        metrics: MutableMap<String, String>,
    ): AuditFinding {
        val exports = wasmFiles.flatMap { wasm ->
            WasmBinaryInspector.readExports(BoundedBinaryIo.readFileBounded(wasm, limits.maxSingleFileBytes))
        }
        metrics["web.wasmExportCount"] = exports.size.toString()
        val limit = policy.web.maxWasmExports ?: return AuditFinding(
            checkId = "web.wasm.exports",
            target = AuditTarget.WEB_WASM,
            title = "WASM exported symbol surface",
            status = CheckStatus.PASS,
            severity = CheckSeverity.LOW,
            weight = 5,
            summary = "Observed ${exports.size} WASM export(s) across ${wasmFiles.size} module(s).",
        )
        val passed = exports.size <= limit
        return AuditFinding(
            checkId = "web.wasm.exports",
            target = AuditTarget.WEB_WASM,
            title = "WASM exported symbol surface",
            status = if (passed) CheckStatus.PASS else CheckStatus.WARN,
            severity = CheckSeverity.LOW,
            weight = 5,
            summary = "Observed ${exports.size} WASM export(s) (limit $limit).",
            evidence = exports.take(10),
            remediation = "Limit @JsExport declarations in production Kotlin/Wasm builds to required entrypoints.",
        )
    }

    private fun checkSecurityHeadersAndCspQuality(site: File, policy: ReleaseGuardPolicy): AuditFinding {
        val headersFile = site.resolve("_headers")
        return when {
            !policy.web.requireSecurityHeaders -> AuditFinding(
                checkId = "web.headers.security",
                target = AuditTarget.WEB_WASM,
                title = "Web security headers & CSP quality (_headers)",
                status = CheckStatus.SKIP,
                severity = CheckSeverity.MEDIUM,
                weight = 12,
                summary = "Security headers check disabled by policy.",
            )
            !headersFile.isFile -> AuditFinding(
                checkId = "web.headers.security",
                target = AuditTarget.WEB_WASM,
                title = "Web security headers & CSP quality (_headers)",
                status = CheckStatus.WARN,
                severity = CheckSeverity.MEDIUM,
                weight = 12,
                summary = "No _headers file found in web bundle directory.",
                remediation = "Generate _headers with hardened CSP, HSTS, X-Content-Type-Options, X-Frame-Options, and Referrer-Policy.",
            )
            else -> evaluateHeadersContent(BoundedBinaryIo.readTextBounded(headersFile), policy)
        }
    }

    private fun checkSubresourceIntegrity(
        site: File,
        allFiles: List<File>,
        policy: ReleaseGuardPolicy,
        limits: BinaryReadLimits,
    ): AuditFinding {
        if (!policy.web.requireSubresourceIntegrity) {
            return AuditFinding(
                checkId = "web.html.sri",
                target = AuditTarget.WEB_WASM,
                title = "External script/stylesheet Subresource Integrity (SRI)",
                status = CheckStatus.SKIP,
                severity = CheckSeverity.MEDIUM,
                weight = 8,
                summary = "Subresource Integrity (SRI) check disabled by policy.",
            )
        }
        val allowlist = policy.web.sriAllowlistHosts.map { it.lowercase(Locale.ROOT) }.toSet()
        val blocking = mutableListOf<String>()
        val dynamicFontWarnings = mutableListOf<String>()
        for (html in allFiles.filter { it.extension.equals("html", ignoreCase = true) }) {
            val content = BoundedBinaryIo.readTextBounded(html, limits.maxSingleFileBytes)
            val rel = html.relativeTo(site).invariantSeparatorsPath
            collectMissingSri(rel, content, externalScriptRegex, requireStylesheet = false, allowlist, blocking, dynamicFontWarnings)
            collectMissingSri(rel, content, externalLinkRegex, requireStylesheet = true, allowlist, blocking, dynamicFontWarnings)
        }
        val status = when {
            blocking.isNotEmpty() -> CheckStatus.FAIL
            dynamicFontWarnings.isNotEmpty() -> CheckStatus.WARN
            else -> CheckStatus.PASS
        }
        val summary = when (status) {
            CheckStatus.PASS -> "All external HTML script/stylesheet tags include Subresource Integrity (or are allowlisted/local)."
            CheckStatus.WARN -> "Found ${dynamicFontWarnings.size} dynamic external font stylesheet(s) without SRI (consider self-hosting or allowlisting)."
            else -> "Found ${blocking.size} external script/stylesheet tag(s) without integrity=\"sha...\"."
        }
        return AuditFinding(
            checkId = "web.html.sri",
            target = AuditTarget.WEB_WASM,
            title = "External script/stylesheet Subresource Integrity (SRI)",
            status = status,
            severity = CheckSeverity.MEDIUM,
            weight = 8,
            summary = summary,
            evidence = (blocking + dynamicFontWarnings).take(10),
            remediation = "Self-host static assets/fonts, add integrity=\"sha384-...\" and crossorigin=\"anonymous\", or add dynamic font CDNs to sriAllowlistHosts.",
        )
    }

    private fun checkInsecureEndpointsAndDebugger(
        bundleFiles: List<File>,
        bundleStringsByFile: Map<File, List<String>>,
        policy: ReleaseGuardPolicy,
        limits: BinaryReadLimits,
    ): AuditFinding {
        val issues = mutableListOf<String>()
        if (policy.web.forbidInsecureWebEndpoints) {
            for ((file, texts) in bundleStringsByFile) {
                SecretScanner.extractInsecureEndpoints(texts).forEach { url ->
                    issues += "${file.name}:$url"
                }
            }
        }
        if (policy.web.forbidDebuggerStatements) {
            for (file in bundleFiles.filter { it.extension == "js" || it.extension == "mjs" }) {
                val text = BoundedBinaryIo.readTextBounded(file, limits.maxSingleFileBytes)
                if (debuggerStmtRegex.containsMatchIn(text)) {
                    issues += "${file.name}:debugger;"
                }
            }
        }
        val passed = issues.isEmpty()
        return AuditFinding(
            checkId = "web.runtime.insecure_endpoints",
            target = AuditTarget.WEB_WASM,
            title = "Web cleartext endpoints (http/ws) & debugger residue",
            status = if (passed) CheckStatus.PASS else CheckStatus.FAIL,
            severity = CheckSeverity.HIGH,
            weight = 10,
            summary = if (passed) {
                "No cleartext http:// or ws:// endpoints or debugger; statements found in web bundle."
            } else {
                "Found ${issues.size} cleartext endpoint(s) or debugger; statement(s) in web bundle."
            },
            evidence = issues.take(10),
            remediation = "Switch all production endpoints to https:// and wss:// and strip debugger statements.",
        )
    }
}

private fun missingWebDirOutput(site: File): AnalyzerOutput = AnalyzerOutput(
    findings = listOf(
        AuditFinding(
            checkId = "web.bundle.present",
            target = AuditTarget.WEB_WASM,
            title = "Web bundle directory present",
            status = CheckStatus.FAIL,
            severity = CheckSeverity.CRITICAL,
            weight = 25,
            summary = "Web bundle directory does not exist: ${site.path}.",
            remediation = "Build wasmJsBrowserDistribution (and hardenWebBundle) before auditing.",
        ),
    ),
)

private fun checkReadability(
    allBundleStrings: List<String>,
    policy: ReleaseGuardPolicy,
    metrics: MutableMap<String, String>,
): AuditFinding {
    val identifiers = IdentifierHeuristics.extractIdentifiers(allBundleStrings)
    val stats = IdentifierHeuristics.computeReadability(
        names = identifiers,
        projectKeywords = policy.projectKeywords,
        projectPackages = policy.projectPackages,
        includeCommonPackageRoots = true,
    )
    metrics["web.readability"] = String.format(Locale.ROOT, "%.4f", stats.score)
    metrics["web.distinctIdentifiers"] = stats.totalCount.toString()

    val threshold = policy.web.maxReadability
    val enforce = policy.web.mode == WebAuditMode.PRODUCTION
    val status = when {
        stats.score <= threshold -> CheckStatus.PASS
        enforce -> CheckStatus.FAIL
        else -> CheckStatus.WARN
    }
    return AuditFinding(
        checkId = "web.obfuscation.readability",
        target = AuditTarget.WEB_WASM,
        title = "Web bundle identifier readability",
        status = status,
        severity = CheckSeverity.HIGH,
        weight = 20,
        summary = String.format(
            Locale.ROOT,
            "Web bundle readability is %.3f (%d/%d recognisable; threshold %.3f, mode=%s).",
            stats.score,
            stats.recognisableCount,
            stats.totalCount,
            threshold,
            policy.web.mode,
        ),
        evidence = stats.examples,
        remediation = "Enable production Binaryen optimization, webpack minification, -Xwasm-kclass-fqn=false, and WASM section stripping.",
    )
}

private fun checkSourcePaths(
    allBundleStrings: List<String>,
    policy: ReleaseGuardPolicy,
    metrics: MutableMap<String, String>,
): AuditFinding {
    val paths = IdentifierHeuristics.extractSourcePaths(allBundleStrings, policy.allowedLibraryPathPatterns)
    metrics["web.projectSourcePaths"] = paths.projectPaths.size.toString()
    metrics["web.librarySourcePaths"] = paths.libraryPaths.size.toString()

    if (!policy.web.forbidProjectSourcePaths) {
        return AuditFinding(
            checkId = "web.metadata.source_paths",
            target = AuditTarget.WEB_WASM,
            title = "No project .kt source paths in web bundle",
            status = CheckStatus.SKIP,
            severity = CheckSeverity.HIGH,
            weight = 12,
            summary = "Project source-path check disabled by policy.",
        )
    }
    val passed = paths.projectPaths.isEmpty()
    return AuditFinding(
        checkId = "web.metadata.source_paths",
        target = AuditTarget.WEB_WASM,
        title = "No project .kt source paths in web bundle",
        status = if (passed) CheckStatus.PASS else CheckStatus.FAIL,
        severity = CheckSeverity.HIGH,
        weight = 12,
        summary = if (passed) {
            "0 project .kt source paths leaked (${paths.libraryPaths.size} allowlisted library path(s))."
        } else {
            "${paths.projectPaths.size} project .kt build path(s) leaked in web bundle."
        },
        evidence = paths.projectPaths.take(10),
        remediation = "Avoid callable/property references (`::privateFn`, `by lazy`) on file-private declarations in wasmJs code.",
    )
}

private fun checkQualifiedClassNames(
    wasmFiles: List<File>,
    bundleStringsByFile: Map<File, List<String>>,
    policy: ReleaseGuardPolicy,
    metrics: MutableMap<String, String>,
): AuditFinding {
    val wasmStrings = wasmFiles.flatMap { bundleStringsByFile[it].orEmpty() }
    val allClasses = IdentifierHeuristics.extractQualifiedClassNames(wasmStrings)
    val projectClasses = allClasses.filter { IdentifierHeuristics.matchesProjectPackage(it, policy.projectPackages) }
    metrics["web.qualifiedClassNamesTotal"] = allClasses.size.toString()
    metrics["web.qualifiedClassNamesProject"] = projectClasses.size.toString()

    val limit = policy.web.maxQualifiedProjectClasses
    val status = when {
        limit == null || projectClasses.size <= limit -> CheckStatus.PASS
        else -> CheckStatus.WARN
    }
    return AuditFinding(
        checkId = "web.metadata.fqn_classes",
        target = AuditTarget.WEB_WASM,
        title = "WASM qualified class name exposure",
        status = status,
        severity = CheckSeverity.LOW,
        weight = 5,
        summary = if (limit == null) {
            "Found ${allClasses.size} qualified class name(s) in WASM (${projectClasses.size} in project packages)."
        } else {
            "Found ${projectClasses.size} project qualified class name(s) in WASM (limit $limit; ${allClasses.size} total)."
        },
        evidence = projectClasses.take(8).ifEmpty { allClasses.take(4) },
        remediation = "Pass -Xwasm-kclass-fqn=false to production KotlinJsIrLink tasks.",
    )
}

private fun evaluateHeadersContent(content: String, policy: ReleaseGuardPolicy): AuditFinding {
    val missing = buildList {
        if (!content.contains("Content-Security-Policy:", ignoreCase = true)) add("Content-Security-Policy")
        if (!content.contains("X-Content-Type-Options: nosniff", ignoreCase = true)) add("X-Content-Type-Options: nosniff")
        if (!content.contains("X-Frame-Options:", ignoreCase = true) && !content.contains("frame-ancestors", ignoreCase = true)) {
            add("X-Frame-Options / frame-ancestors")
        }
        if (!content.contains("Referrer-Policy:", ignoreCase = true)) add("Referrer-Policy")
    }
    val cspWeaknesses = if (policy.web.gradeCspQuality) {
        inspectCspDirectives(content, policy.web.allowWasmUnsafeEvalInCsp)
    } else {
        emptyList()
    }
    val status = when {
        missing.isNotEmpty() -> CheckStatus.FAIL
        cspWeaknesses.any { it.startsWith("HIGH:") } -> CheckStatus.FAIL
        cspWeaknesses.isNotEmpty() -> CheckStatus.WARN
        else -> CheckStatus.PASS
    }
    return AuditFinding(
        checkId = "web.headers.security",
        target = AuditTarget.WEB_WASM,
        title = "Web security headers & CSP quality (_headers)",
        status = status,
        severity = CheckSeverity.MEDIUM,
        weight = 12,
        summary = when (status) {
            CheckStatus.PASS -> "Verified hardened CSP, X-Content-Type-Options, clickjacking protection, and Referrer-Policy in _headers."
            CheckStatus.WARN -> "Security headers present, with CSP/hardening improvement suggestion(s): ${cspWeaknesses.joinToString()}."
            else -> "Missing header(s) or weak CSP directive(s): ${(missing + cspWeaknesses).joinToString()}."
        },
        evidence = (missing + cspWeaknesses).take(10),
        remediation = "Use WebBundleStripper / hardenWebBundle to emit strict CSP (object-src 'none', frame-ancestors 'none', no script-src 'unsafe-inline' or '*').",
    )
}

private fun inspectCspDirectives(headersContent: String, allowWasmUnsafeEval: Boolean): List<String> {
    val cspLine = headersContent.lineSequence()
        .map(String::trim)
        .firstOrNull { it.startsWith("Content-Security-Policy:", ignoreCase = true) }
        ?.substringAfter(':')
        ?.trim()
        ?: return emptyList()
    val directives = cspLine.split(';')
        .map(String::trim)
        .filter(String::isNotEmpty)
        .associate { part ->
            val key = part.substringBefore(' ').lowercase(Locale.ROOT)
            val value = part.substringAfter(' ', "")
            key to value
        }
    val scriptSrc = directives["script-src"].orEmpty()
    val connectSrc = directives["connect-src"].orEmpty()
    return buildList {
        if ("'unsafe-inline'" in scriptSrc) add("HIGH:script-src allows 'unsafe-inline'")
        if (Regex("""(^|\s)\*(\s|$)""").containsMatchIn(scriptSrc)) add("HIGH:script-src allows wildcard '*'")
        if (Regex("""(^|\s)\*(\s|$)""").containsMatchIn(connectSrc)) add("WARN:connect-src allows wildcard '*'")
        if (!allowWasmUnsafeEval && "'unsafe-eval'" in scriptSrc) add("WARN:script-src allows 'unsafe-eval'")
        if (directives["object-src"]?.trim() != "'none'") add("WARN:missing object-src 'none'")
        if (!directives.containsKey("frame-ancestors")) add("WARN:missing frame-ancestors directive")
    }
}

private val dynamicFontHosts: Set<String> = setOf("fonts.googleapis.com", "use.typekit.net")

private fun collectMissingSri(
    relPath: String,
    html: String,
    regex: Regex,
    requireStylesheet: Boolean,
    allowlistHosts: Set<String>,
    blockingOut: MutableList<String>,
    warningOut: MutableList<String>,
) {
    for (match in regex.findAll(html)) {
        val tag = match.value
        val url = match.groupValues[1]
        val host = url.substringAfter("://", "").substringBefore('/').substringBefore(':').lowercase(Locale.ROOT)
        val isStylesheet = !requireStylesheet || tag.contains("stylesheet", ignoreCase = true)
        val hasSri = Regex("""\bintegrity\s*=\s*["']sha(?:256|384|512)-[^"']+["']""", RegexOption.IGNORE_CASE).containsMatchIn(tag)
        if (isStylesheet && !hasSri && host !in allowlistHosts) {
            if (requireStylesheet && host in dynamicFontHosts) {
                warningOut += "$relPath -> $url"
            } else {
                blockingOut += "$relPath -> $url"
            }
        }
    }
}

private fun checkSensitiveDistFiles(site: File, allFiles: List<File>, policy: ReleaseGuardPolicy): AuditFinding {
    if (!policy.web.forbidSensitiveDistFiles) {
        return AuditFinding(
            checkId = "web.packaging.sensitive_files",
            target = AuditTarget.WEB_WASM,
            title = "No sensitive files in web dist",
            status = CheckStatus.SKIP,
            severity = CheckSeverity.CRITICAL,
            weight = 10,
            summary = "Sensitive web dist file check disabled by policy.",
        )
    }
    val hits = allFiles.map { it.relativeTo(site).invariantSeparatorsPath }
        .filter(SecretScanner::isSensitivePackagedFile)
    val passed = hits.isEmpty()
    return AuditFinding(
        checkId = "web.packaging.sensitive_files",
        target = AuditTarget.WEB_WASM,
        title = "No sensitive files in web dist",
        status = if (passed) CheckStatus.PASS else CheckStatus.FAIL,
        severity = CheckSeverity.CRITICAL,
        weight = 10,
        summary = if (passed) {
            "No .env, .git, key, or database files found in web dist."
        } else {
            "Found ${hits.size} sensitive file(s) inside web distribution directory."
        },
        evidence = hits.take(10),
        remediation = "Remove .env, .git, key, and database files from static web hosting outputs.",
    )
}

private fun checkWebSecrets(
    bundleStringsByFile: Map<File, List<String>>,
    policy: ReleaseGuardPolicy,
): AuditFinding {
    if (!policy.secrets.enabled) {
        return AuditFinding(
            checkId = "web.secrets.scan",
            target = AuditTarget.WEB_WASM,
            title = "Web bundle secret scan",
            status = CheckStatus.SKIP,
            severity = CheckSeverity.CRITICAL,
            weight = 10,
            summary = "Secret scanning disabled by policy.",
        )
    }
    val matches = bundleStringsByFile.flatMap { (file, texts) ->
        SecretScanner.scanSecrets(file.name, texts, policy.secrets)
    }
    val passed = matches.isEmpty()
    return AuditFinding(
        checkId = "web.secrets.scan",
        target = AuditTarget.WEB_WASM,
        title = "Web bundle secret scan",
        status = if (passed) CheckStatus.PASS else CheckStatus.FAIL,
        severity = CheckSeverity.CRITICAL,
        weight = 10,
        summary = if (passed) {
            "No high-confidence private keys or secret tokens found in web bundle."
        } else {
            "Found ${matches.size} high-confidence secret or forbidden endpoint match(es) in web bundle."
        },
        evidence = matches.take(8).map { "${it.ruleName} @ ${it.location} (${it.redactedPreview})" },
        remediation = "Never embed private keys or server credentials in browser-delivered bundles.",
    )
}

private fun containsAscii(bytes: ByteArray, needle: String): Boolean {
    val target = needle.toByteArray(Charsets.US_ASCII)
    return target.isNotEmpty() && bytes.size >= target.size &&
        (0..(bytes.size - target.size)).any { start ->
            target.indices.all { j -> bytes[start + j] == target[j] }
        }
}

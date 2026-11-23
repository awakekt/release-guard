/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.analyzers

import com.awakekt.releaseguard.io.BoundedBinaryIo
import java.io.File
import java.security.MessageDigest
import java.util.Base64

/** Options controlling [WebBundleStripper.harden]. */
public data class WebStripOptions(
    public val stripWasmDebugSections: Boolean = true,
    public val dropSourceMaps: Boolean = true,
    public val dropSensitiveFiles: Boolean = true,
    public val excludedFiles: Set<String> = DEFAULT_EXCLUDED_LOCAL_INDEXES,
    public val generateSecurityHeaders: Boolean = true,
    public val contentSecurityPolicyOverride: String? = null,
) {
    public companion object {
        /** Development-only project index files omitted from static deployments by default. */
        public val DEFAULT_EXCLUDED_LOCAL_INDEXES: Set<String> = setOf("project.index.json", "editor.index.json", ".DS_Store")
    }
}

/** Summary report produced by [WebBundleStripper.harden]. */
public data class WebStripReport(
    public val copiedFiles: Int,
    public val droppedSourceMaps: List<String>,
    public val cleanedSourceMapReferences: List<String>,
    public val droppedSensitiveFiles: List<String> = emptyList(),
    public val strippedWasmBytesSaved: Long,
    public val removedWasmSections: List<String>,
    public val wroteHeadersFile: Boolean,
)

/**
 * Hardens a compiled Kotlin/Wasm + JS web distribution directory for static hosting:
 * drops `*.map` and sensitive files, removes JS and CSS `sourceMappingURL` directives, strips WASM
 * debug/name custom sections, computes SHA-256 CSP hashes for inline scripts, and emits `_headers`.
 */
public object WebBundleStripper {
    private val jsSourceMapCommentRegex = Regex("""\r?\n?//[#@]\s*sourceMappingURL=[^\r\n]*""")
    private val cssSourceMapCommentRegex = Regex("""\r?\n?/\*[#@]\s*sourceMappingURL=.*?\*/""", RegexOption.DOT_MATCHES_ALL)
    private val inlineScriptRegex = Regex(
        """<script(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script>""",
        setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL),
    )
    private val hashedAssetRegex = Regex("""[0-9a-f]{16,}\.(?:wasm|js|mjs)""")
    private val textExtensions = setOf("js", "mjs", "html", "css")
    private val stableAssetExtensions = setOf("js", "mjs", "css")

    private class StripAccumulator {
        var copiedFiles: Int = 0
        val droppedMaps: MutableList<String> = mutableListOf()
        val cleanedRefs: MutableList<String> = mutableListOf()
        val droppedSensitive: MutableList<String> = mutableListOf()
        var bytesSaved: Long = 0L
        val removedSections: MutableList<String> = mutableListOf()
    }

    /** Copies and hardens [inputDir] into [outputDir] according to [options]. */
    public fun harden(
        inputDir: File,
        outputDir: File,
        options: WebStripOptions = WebStripOptions(),
    ): WebStripReport {
        require(inputDir.isDirectory) { "Web input directory does not exist: ${inputDir.path}" }
        if (outputDir.exists()) outputDir.deleteRecursively()
        outputDir.mkdirs()

        val acc = StripAccumulator()
        inputDir.walkTopDown()
            .filter { it.isFile }
            .sortedBy { it.relativeTo(inputDir).invariantSeparatorsPath }
            .forEach { source -> processFile(source, inputDir, outputDir, options, acc) }

        val wroteHeaders = if (options.generateSecurityHeaders) {
            writeHeadersFile(outputDir, options.contentSecurityPolicyOverride)
            true
        } else {
            false
        }

        return WebStripReport(
            copiedFiles = acc.copiedFiles,
            droppedSourceMaps = acc.droppedMaps,
            cleanedSourceMapReferences = acc.cleanedRefs,
            droppedSensitiveFiles = acc.droppedSensitive,
            strippedWasmBytesSaved = acc.bytesSaved,
            removedWasmSections = acc.removedSections,
            wroteHeadersFile = wroteHeaders,
        )
    }

    private fun processFile(
        source: File,
        inputDir: File,
        outputDir: File,
        options: WebStripOptions,
        acc: StripAccumulator,
    ) {
        val relative = source.relativeTo(inputDir).invariantSeparatorsPath
        val skip = shouldSkipFile(source, relative, options, acc)
        if (skip) return

        val dest = outputDir.resolve(relative)
        dest.parentFile.mkdirs()
        when {
            source.extension == "wasm" && options.stripWasmDebugSections -> {
                val original = BoundedBinaryIo.readFileBounded(source)
                val result = WasmBinaryInspector.stripDebugSections(original)
                dest.writeBytes(result.strippedBytes)
                acc.bytesSaved += (original.size - result.strippedBytes.size).toLong()
                result.removedSections.forEach { sec -> acc.removedSections += "$relative:${sec.name}" }
            }
            options.dropSourceMaps && source.extension in textExtensions -> {
                val originalText = BoundedBinaryIo.readTextBounded(source)
                val cleaned = cssSourceMapCommentRegex.replace(jsSourceMapCommentRegex.replace(originalText, ""), "")
                if (cleaned != originalText) acc.cleanedRefs += relative
                dest.writeText(cleaned, Charsets.UTF_8)
            }
            else -> source.copyTo(dest, overwrite = true)
        }
        acc.copiedFiles += 1
    }

    private fun shouldSkipFile(
        source: File,
        relative: String,
        options: WebStripOptions,
        acc: StripAccumulator,
    ): Boolean = when {
        options.dropSourceMaps && source.extension == "map" -> {
            acc.droppedMaps += relative
            true
        }
        options.dropSensitiveFiles && SecretScanner.isSensitivePackagedFile(relative) -> {
            acc.droppedSensitive += relative
            true
        }
        relative in options.excludedFiles -> true
        else -> false
    }

    private fun writeHeadersFile(outputDir: File, cspOverride: String?) {
        val indexHtml = outputDir.resolve("index.html").takeIf { it.isFile }?.let(BoundedBinaryIo::readTextBounded).orEmpty()
        val scriptHashes = computeInlineScriptHashes(indexHtml)
        val topLevelFiles = outputDir.listFiles()?.filter { it.isFile }?.map { it.name }?.sorted().orEmpty()
        val hashed = topLevelFiles.filter { hashedAssetRegex.matches(it) }
        val stable = topLevelFiles.filter { it.substringAfterLast('.', "") in stableAssetExtensions && !hashedAssetRegex.matches(it) }
        val headersContent = buildHeadersFile(
            hashedFiles = hashed,
            stableFiles = stable,
            scriptHashes = scriptHashes,
            cspOverride = cspOverride,
        )
        outputDir.resolve("_headers").writeText(headersContent, Charsets.UTF_8)
    }

    /** Computes `'sha256-...'` CSP source tokens for inline `<script>` tags inside [html]. */
    public fun computeInlineScriptHashes(html: String): List<String> {
        val digest = MessageDigest.getInstance("SHA-256")
        val tokens = linkedSetOf<String>()
        for (match in inlineScriptRegex.findAll(html)) {
            val body = match.groupValues[1]
            val hash = Base64.getEncoder().encodeToString(digest.digest(body.toByteArray(Charsets.UTF_8)))
            tokens += "'sha256-$hash'"
        }
        return tokens.toList()
    }

    /** Generates a hardened default `Content-Security-Policy` suitable for Kotlin/Wasm apps. */
    public fun defaultContentSecurityPolicy(scriptHashes: List<String> = emptyList()): String {
        val extra = if (scriptHashes.isEmpty()) "" else " " + scriptHashes.joinToString(" ")
        return "default-src 'self'; " +
            "script-src 'self' 'wasm-unsafe-eval'$extra; " +
            "worker-src 'self' blob:; " +
            "style-src 'self' 'unsafe-inline'; " +
            "font-src 'self' data:; " +
            "img-src 'self' blob: data: https:; " +
            "media-src 'self' blob: data:; " +
            "connect-src 'self' https: wss:; " +
            "object-src 'none'; " +
            "base-uri 'self'; " +
            "frame-ancestors 'none'"
    }

    private fun buildHeadersFile(
        hashedFiles: List<String>,
        stableFiles: List<String>,
        scriptHashes: List<String>,
        cspOverride: String?,
    ): String = buildString {
        val csp = cspOverride?.takeIf { it.isNotBlank() } ?: defaultContentSecurityPolicy(scriptHashes)
        appendLine("# Generated by Release Guard WebBundleStripper.")
        appendLine("/*")
        appendLine("  Strict-Transport-Security: max-age=31536000; includeSubDomains")
        appendLine("  X-Content-Type-Options: nosniff")
        appendLine("  X-Frame-Options: DENY")
        appendLine("  Referrer-Policy: no-referrer")
        appendLine("  Cross-Origin-Opener-Policy: same-origin")
        appendLine("/")
        appendLine("  Cache-Control: no-cache")
        appendLine("  Content-Security-Policy: $csp")
        appendLine("/index.html")
        appendLine("  Cache-Control: no-cache")
        appendLine("  Content-Security-Policy: $csp")
        for (name in stableFiles) {
            appendLine("/$name")
            appendLine("  Cache-Control: no-cache")
        }
        for (name in hashedFiles) {
            appendLine("/$name")
            appendLine("  Cache-Control: public, max-age=31536000, immutable")
        }
    }
}

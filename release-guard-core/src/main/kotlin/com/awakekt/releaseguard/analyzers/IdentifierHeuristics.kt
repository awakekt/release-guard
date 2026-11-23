/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.analyzers

import java.util.Locale

/** Aggregated readability measurements across a collection of symbol or string identifiers. */
public data class ReadabilityStats(
    public val score: Double,
    public val recognisableCount: Int,
    public val totalCount: Int,
    public val examples: List<String>,
)

/** Partitioned Kotlin source paths discovered inside a compiled bundle. */
public data class SourcePathStats(
    public val projectPaths: List<String>,
    public val libraryPaths: List<String>,
)

/**
 * Shared static string, identifier, readability, `.kt` source-path, and FQN class heuristics used
 * across target analyzers.
 */
public object IdentifierHeuristics {
    private const val MIN_PRINTABLE = 0x20
    private const val MAX_PRINTABLE = 0x7E
    private const val MIN_RUN_LENGTH = 4
    private const val MIN_IDENTIFIER_LENGTH = 4

    private val identifierRegex = Regex("""[A-Za-z_][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*""")
    private val upperCamelRegex = Regex("""[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]*)+""")
    private val lowerCamelRegex = Regex("""[a-z][a-z0-9]+(?:[A-Z][a-z0-9]+)+""")
    private val fileClassRegex = Regex("""[A-Z][A-Za-z0-9]*Kt""")
    private val commonRootPackageRegex = Regex("""(?:^|\.)(?:kotlinx?|com|org|io|androidx|java)\.""")
    private val sourcePathRegex = Regex("""(?:[A-Za-z]:)?[/\\](?:[\w.@+-]+[/\\])+[\w.@+-]+\.kt\b""")
    private val qualifiedClassRegex = Regex(
        """\b(?:com|org|io|net|dev|kotlin|kotlinx|androidx|java|javax)(?:\.[a-z][a-z0-9_]*)*\.[A-Z][A-Za-z0-9_]*""",
    )

    /** Standard JDK members every JVM/Kotlin class may override without revealing app logic. */
    public val JDK_STANDARD_MEMBERS: Set<String> = setOf(
        "hashCode",
        "equals",
        "toString",
        "clone",
        "finalize",
        "getClass",
        "valueOf",
        "values",
        "compareTo",
        "name",
        "ordinal",
        "getDeclaringClass",
        "describeConstable",
        "annotationType",
        "close",
        "run",
        "call",
    )

    /** Extracts ASCII and UTF-16LE runs of 4 or more printable characters from [bytes]. */
    public fun extractPrintableStrings(bytes: ByteArray): List<String> {
        val results = mutableListOf<String>()
        extractAsciiRuns(bytes, results)
        extractUtf16LeRuns(bytes, results)
        return results
    }

    /** Returns `true` when [internalOrDottedName] sits under one of [projectPackages]. */
    public fun matchesProjectPackage(internalOrDottedName: String, projectPackages: List<String>): Boolean {
        if (projectPackages.isEmpty()) return false
        val dotted = internalOrDottedName.replace('/', '.')
        return projectPackages.any { pkg ->
            val normalized = pkg.trim().trimEnd('.')
            normalized.isNotEmpty() && (dotted == normalized || dotted.startsWith("$normalized."))
        }
    }

    /** Returns `true` if [name] reads like a meaningful non-obfuscated class, member, or package identifier. */
    public fun isRecognisableIdentifier(
        name: String,
        projectKeywords: List<String> = emptyList(),
        projectPackages: List<String> = emptyList(),
        includeCommonPackageRoots: Boolean = false,
    ): Boolean {
        if (name.length < MIN_IDENTIFIER_LENGTH && !matchesKeywords(name, projectKeywords)) return false
        val last = name.substringAfterLast('.')
        return matchesKeywords(name, projectKeywords) ||
            matchesProjectPackage(name, projectPackages) ||
            (includeCommonPackageRoots && commonRootPackageRegex.containsMatchIn(name)) ||
            ('.' in name && upperCamelRegex.matches(last)) ||
            upperCamelRegex.matches(name) ||
            fileClassRegex.matches(name) ||
            lowerCamelRegex.matches(name)
    }

    /** Computes the readability fraction and representative examples across [names]. */
    public fun computeReadability(
        names: Collection<String>,
        projectKeywords: List<String> = emptyList(),
        projectPackages: List<String> = emptyList(),
        includeCommonPackageRoots: Boolean = false,
    ): ReadabilityStats {
        if (names.isEmpty()) return ReadabilityStats(0.0, 0, 0, emptyList())
        val recognisable = names.filter {
            isRecognisableIdentifier(it, projectKeywords, projectPackages, includeCommonPackageRoots)
        }
        val projectHits = recognisable.filter {
            matchesKeywords(it, projectKeywords) || matchesProjectPackage(it, projectPackages)
        }.distinct().sorted()
        val projectSet = projectHits.toSet()
        val otherHits = recognisable.filterNot { it in projectSet }.distinct().sorted()
        val examples = (projectHits.take(6) + otherHits.take(6)).take(12)
        val ratio = recognisable.size.toDouble() / names.size.toDouble()
        return ReadabilityStats(
            score = ratio,
            recognisableCount = recognisable.size,
            totalCount = names.size,
            examples = examples,
        )
    }

    /** Extracts distinct identifier-like tokens of at least 4 characters from [texts]. */
    public fun extractIdentifiers(texts: Iterable<String>): Set<String> {
        val identifiers = linkedSetOf<String>()
        for (text in texts) {
            for (match in identifierRegex.findAll(text)) {
                val token = match.value
                if (token.length >= MIN_IDENTIFIER_LENGTH) identifiers += token
            }
        }
        return identifiers
    }

    /** Extracts distinct absolute `.kt` build paths and separates project paths from allowlisted library paths. */
    public fun extractSourcePaths(
        texts: Iterable<String>,
        allowedLibraryPathPatterns: List<String>,
    ): SourcePathStats {
        val libraryRegexes = allowedLibraryPathPatterns.map(::Regex)
        val allPaths = linkedSetOf<String>()
        for (text in texts) {
            sourcePathRegex.findAll(text).forEach { allPaths += it.value }
        }
        val projectPaths = mutableListOf<String>()
        val libraryPaths = mutableListOf<String>()
        for (path in allPaths.sorted()) {
            if (libraryRegexes.any { it.containsMatchIn(path) }) libraryPaths += path else projectPaths += path
        }
        return SourcePathStats(projectPaths = projectPaths, libraryPaths = libraryPaths)
    }

    /** Extracts distinct fully-qualified class names such as `com.example.game.Player` from [texts]. */
    public fun extractQualifiedClassNames(texts: Iterable<String>): List<String> {
        val classes = linkedSetOf<String>()
        for (text in texts) {
            qualifiedClassRegex.findAll(text).forEach { classes += it.value }
        }
        return classes.sorted()
    }

    private fun matchesKeywords(name: String, keywords: List<String>): Boolean {
        if (keywords.isEmpty()) return false
        val lower = name.lowercase(Locale.ROOT)
        return keywords.any { kw ->
            val trimmed = kw.trim().lowercase(Locale.ROOT)
            trimmed.isNotEmpty() && trimmed in lower
        }
    }

    private fun extractAsciiRuns(bytes: ByteArray, out: MutableList<String>) {
        var start = -1
        for (index in bytes.indices) {
            val value = bytes[index].toInt() and 0xFF
            if (value in MIN_PRINTABLE..MAX_PRINTABLE) {
                if (start < 0) start = index
            } else if (start >= 0) {
                if (index - start >= MIN_RUN_LENGTH) out += String(bytes, start, index - start, Charsets.US_ASCII)
                start = -1
            }
        }
        if (start >= 0 && bytes.size - start >= MIN_RUN_LENGTH) {
            out += String(bytes, start, bytes.size - start, Charsets.US_ASCII)
        }
    }

    private fun extractUtf16LeRuns(bytes: ByteArray, out: MutableList<String>) {
        var i = 0
        val current = StringBuilder()
        while (i + 1 < bytes.size) {
            val lo = bytes[i].toInt() and 0xFF
            val hi = bytes[i + 1].toInt() and 0xFF
            if (hi == 0 && lo in MIN_PRINTABLE..MAX_PRINTABLE) {
                current.append(lo.toChar())
                i += 2
            } else {
                if (current.length >= MIN_RUN_LENGTH) out += current.toString()
                current.setLength(0)
                i += 1
            }
        }
        if (current.length >= MIN_RUN_LENGTH) out += current.toString()
    }
}

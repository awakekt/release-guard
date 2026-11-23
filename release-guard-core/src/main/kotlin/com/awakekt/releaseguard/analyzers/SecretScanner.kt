/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.analyzers

import com.awakekt.releaseguard.model.SecretScanPolicy
import java.util.Locale
import kotlin.math.ln

/** One redacted high-confidence secret, high-entropy token, or forbidden dev-endpoint match. */
public data class SecretMatch(
    public val ruleName: String,
    public val location: String,
    public val redactedPreview: String,
)

/**
 * High-confidence secret pattern scanner, Shannon entropy token detector, cleartext endpoint
 * finder, sensitive packaged-file classifier, and workstation path leak detector.
 */
public object SecretScanner {
    private val localBuildPathRegex = Regex(
        """(?:/Users/[A-Za-z0-9._-]+/|/home/[A-Za-z0-9._-]+/|[A-Za-z]:\\Users\\[A-Za-z0-9._-]+\\)[^\s"'<>]{3,}""",
    )

    private val defaultSecretPatterns: Map<String, Regex> = linkedMapOf(
        "pem_private_key" to Regex("""-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"""),
        "aws_access_key_id" to Regex("""\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"""),
        "github_token" to Regex("""\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b"""),
        "stripe_live_secret" to Regex("""\bsk_live_[A-Za-z0-9]{16,}\b"""),
        "slack_token" to Regex("""\bxox[baprs]-[A-Za-z0-9-]{16,}\b"""),
        "gcp_api_key" to Regex("""\bAIza[0-9A-Za-z_-]{35}\b"""),
    )

    private val secretAssignmentRegex = Regex(
        """(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret|signing[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9+/=_-]{24,})["']?""",
    )

    private val localhostEndpointRegex = Regex(
        """\b(?:http|ws)://(?:localhost|127\.0\.0\.1)(?::\d+)?(?:/[^\s"'<>]*)?""",
        RegexOption.IGNORE_CASE,
    )

    private val insecureEndpointRegex = Regex(
        """\b(?:http|ws)://([A-Za-z0-9.-]+(?::\d+)?(?:/[^\s"'<>]*)?)""",
        RegexOption.IGNORE_CASE,
    )

    private val allowedInsecureHosts: Set<String> = setOf(
        "schemas.android.com",
        "www.w3.org",
        "w3.org",
        "ns.adobe.com",
        "xml.org",
        "purl.org",
        "www.apache.org",
        "apache.org",
        "example.com",
        "example.org",
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
    )

    private val sensitiveFileNames: Set<String> = setOf(
        ".env",
        ".env.local",
        ".env.production",
        ".env.development",
        "local.properties",
        "id_rsa",
        "id_ed25519",
    )

    private val sensitiveFileExtensions: Set<String> = setOf(
        "jks",
        "keystore",
        "p12",
        "pfx",
        "pem",
        "key",
        "sqlite",
        "sqlite3",
        "db",
    )

    /** Extracts workstation build paths (`/Users/<name>/...`, `/home/<name>/...`, `C:\Users\...`) outside allowlists. */
    public fun extractLocalBuildPaths(
        texts: Iterable<String>,
        allowedLibraryPathPatterns: List<String>,
    ): List<String> {
        val libraryRegexes = allowedLibraryPathPatterns.map(::Regex)
        val hits = linkedSetOf<String>()
        for (text in texts) {
            localBuildPathRegex.findAll(text).forEach { match ->
                if (libraryRegexes.none { it.containsMatchIn(match.value) }) hits += match.value
            }
        }
        return hits.sorted()
    }

    /** Extracts non-standard cleartext `http://` and `ws://` endpoints from [texts]. */
    public fun extractInsecureEndpoints(texts: Iterable<String>): List<String> {
        val hits = linkedSetOf<String>()
        for (text in texts) {
            for (match in insecureEndpointRegex.findAll(text)) {
                val host = match.groupValues[1].substringBefore('/').substringBefore(':').lowercase(Locale.ROOT)
                if (host.isNotEmpty() && '.' in host && host !in allowedInsecureHosts) hits += match.value
            }
        }
        return hits.sorted()
    }

    /** Returns `true` when [relativePath] looks like a sensitive key, credential, `.env`, `.git`, or DB file. */
    public fun isSensitivePackagedFile(relativePath: String): Boolean {
        val segments = relativePath.replace('\\', '/').split('/')
        val fileName = segments.lastOrNull().orEmpty().lowercase(Locale.ROOT)
        val ext = fileName.substringAfterLast('.', "")
        val hasGitSegment = segments.any { it.equals(".git", ignoreCase = true) }
        return hasGitSegment || fileName in sensitiveFileNames || fileName.startsWith(".env.") || ext in sensitiveFileExtensions
    }

    /** Computes Shannon entropy (bits per character) of [value]. */
    public fun shannonEntropy(value: String): Double {
        if (value.isEmpty()) return 0.0
        val freq = HashMap<Char, Int>()
        for (ch in value) freq[ch] = (freq[ch] ?: 0) + 1
        val len = value.length.toDouble()
        var entropy = 0.0
        for (count in freq.values) {
            val p = count.toDouble() / len
            entropy -= p * (ln(p) / ln(2.0))
        }
        return entropy
    }

    /** Scans [texts] at [location] for high-confidence leaked private keys, high-entropy credentials, or dev endpoints. */
    public fun scanSecrets(
        location: String,
        texts: Iterable<String>,
        policy: SecretScanPolicy,
    ): List<SecretMatch> {
        if (!policy.enabled) return emptyList()
        val allowlist = policy.allowlistRegexes.map(::Regex)
        val patterns = buildMap {
            putAll(defaultSecretPatterns)
            if (policy.forbidLocalhostEndpointsInRelease) put("localhost_endpoint", localhostEndpointRegex)
            policy.extraPatterns.forEach { (name, expr) -> put(name, Regex(expr)) }
        }
        val matches = mutableListOf<SecretMatch>()
        val seen = linkedSetOf<String>()
        for (text in texts) {
            scanRegexPatterns(location, text, patterns, allowlist, seen, matches)
            if (policy.enableHighEntropyScan) {
                scanHighEntropyAssignments(location, text, policy.minEntropyThreshold, allowlist, seen, matches)
            }
        }
        return matches
    }

    private fun scanRegexPatterns(
        location: String,
        text: String,
        patterns: Map<String, Regex>,
        allowlist: List<Regex>,
        seen: MutableSet<String>,
        matches: MutableList<SecretMatch>,
    ) {
        for ((ruleName, regex) in patterns) {
            for (hit in regex.findAll(text)) {
                val raw = hit.value
                if (allowlist.any { it.containsMatchIn(raw) }) continue
                val preview = redactSecret(raw)
                if (seen.add("$ruleName:$location:$preview")) matches += SecretMatch(ruleName, location, preview)
            }
        }
    }

    private fun scanHighEntropyAssignments(
        location: String,
        text: String,
        minEntropy: Double,
        allowlist: List<Regex>,
        seen: MutableSet<String>,
        matches: MutableList<SecretMatch>,
    ) {
        for (hit in secretAssignmentRegex.findAll(text)) {
            val candidate = hit.groupValues[1]
            val looksPlaceholder = candidate.all { it == candidate[0] } ||
                candidate.contains("placeholder", ignoreCase = true) ||
                candidate.contains("example", ignoreCase = true)
            if (!looksPlaceholder && shannonEntropy(candidate) >= minEntropy && allowlist.none { it.containsMatchIn(candidate) }) {
                val preview = redactSecret(candidate)
                if (seen.add("high_entropy_secret:$location:$preview")) {
                    matches += SecretMatch("high_entropy_secret", location, preview)
                }
            }
        }
    }
}

private fun redactSecret(value: String): String =
    if (value.length <= 12) value.take(4) + "***" else value.take(6) + "..." + value.takeLast(4)

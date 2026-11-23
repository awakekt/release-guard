/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.analyzers

import com.awakekt.releaseguard.model.AuditFinding
import com.awakekt.releaseguard.model.AuditTarget
import com.awakekt.releaseguard.model.CheckSeverity
import com.awakekt.releaseguard.model.CheckStatus
import com.awakekt.releaseguard.model.ReleaseGuardPolicy
import java.io.IOException
import java.net.InetAddress
import java.net.URI
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Locale
import javax.naming.InvalidNameException
import javax.naming.ldap.LdapName
import javax.net.ssl.HttpsURLConnection
import javax.security.auth.x500.X500Principal

/** Inputs for validating TLS SPKI pin specifications. */
public data class TlsAuditInput(
    public val spkiPinsSpec: String,
    public val probeHosts: List<String> = emptyList(),
)

/**
 * Parses, validates, generates, and optionally live-probes TLS Subject Public Key Info (SPKI) SHA-256
 * pin rules (`host=sha256/<base64>,...;...`).
 */
public object TlsPinAnalyzer {
    private const val SHA256_PREFIX = "sha256/"
    private const val TIMEOUT_MS = 8_000

    /** Validates [input] against [policy] and emits syntax, rotation-safety, and optional live probe findings. */
    public fun analyze(input: TlsAuditInput, policy: ReleaseGuardPolicy): AnalyzerOutput {
        val raw = input.spkiPinsSpec.trim()
        if (raw.isEmpty()) return unconfiguredOutput(policy)
        val parsed = runCatching { parsePinSpec(raw) }
        return parsed.fold(
            onFailure = { error -> invalidSyntaxOutput(error.message ?: "Invalid TLS SPKI pin specification.") },
            onSuccess = { pinMap ->
                val findings = mutableListOf(
                    AuditFinding(
                        checkId = "tls.spki.syntax",
                        target = AuditTarget.TRANSPORT_TLS,
                        title = "TLS SPKI pin syntax validity",
                        status = CheckStatus.PASS,
                        severity = CheckSeverity.HIGH,
                        weight = 10,
                        summary = "Parsed ${pinMap.size} valid TLS SPKI pin rule(s).",
                    ),
                    checkBackupPins(pinMap, policy),
                )
                if (policy.tls.probeLiveHosts) {
                    val hosts = (input.probeHosts + policy.tls.probeHosts).map(::normalizeHostArg).distinct()
                    findings += probeLiveEndpoints(pinMap, hosts)
                }
                AnalyzerOutput(findings = findings, metrics = mapOf("tls.pinnedHostRules" to pinMap.size.toString()))
            },
        )
    }

    /** Parses and strictly validates a `host=sha256/<base64>,...` pin spec string. */
    public fun parsePinSpec(spec: String): Map<String, Set<String>> {
        val parsed = LinkedHashMap<String, MutableSet<String>>()
        val decoder = Base64.getDecoder()
        for (rawEntry in spec.split(';', '\n')) {
            val entry = rawEntry.trim()
            if (entry.isEmpty()) continue
            val eq = entry.indexOf('=')
            require(eq > 0 && eq < entry.lastIndex) {
                "Invalid TLS pin entry '$entry'; expected 'host=sha256/<base64>,...'."
            }
            val pattern = normalizePattern(entry.substring(0, eq))
            val hostPins = parsed.getOrPut(pattern) { LinkedHashSet() }
            val rawPins = entry.substring(eq + 1).split(',').map(String::trim).filter(String::isNotEmpty)
            require(rawPins.isNotEmpty()) { "No SPKI pins supplied for TLS host '$pattern'." }
            for (pin in rawPins) {
                require(pin.startsWith(SHA256_PREFIX) && pin.length > SHA256_PREFIX.length) {
                    "Invalid TLS pin '$pin' for '$pattern'; expected 'sha256/<base64>'."
                }
                val decoded = try {
                    decoder.decode(pin.removePrefix(SHA256_PREFIX))
                } catch (error: IllegalArgumentException) {
                    throw IllegalArgumentException("Invalid Base64 in TLS pin '$pin' for '$pattern'.", error)
                }
                require(decoded.size == 32) {
                    "Invalid TLS pin '$pin' for '$pattern'; decoded ${decoded.size} bytes instead of 32."
                }
                hostPins += pin
            }
        }
        return parsed
    }

    /** Connects to each live [hosts] endpoint and returns a rotation-safe SPKI pin spec (CA pins first, then leaf). */
    public fun fetchLivePinSpec(hosts: List<String>): String {
        require(hosts.isNotEmpty()) { "Pass at least one hostname to fetch TLS SPKI pins." }
        return hosts.joinToString(";") { rawHost ->
            val host = normalizeHostArg(rawHost)
            val chain = fetchCertificateChain(host)
            val ordered = LinkedHashSet<String>()
            for (idx in 1 until chain.size) {
                ordered += spkiSha256Pin(chain[idx])
            }
            ordered += spkiSha256Pin(chain[0])
            "$host=${ordered.joinToString(",")}"
        }
    }

    /** Computes the `sha256/<base64>` SPKI pin of [certificate]. */
    public fun spkiSha256Pin(certificate: X509Certificate): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(certificate.publicKey.encoded)
        return SHA256_PREFIX + Base64.getEncoder().encodeToString(digest)
    }

    /** Matches a pin host [pattern] (exact, `*.domain`, or `**.domain`) against [host]. */
    public fun matchesPattern(pattern: String, host: String): Boolean {
        val p = pattern.lowercase(Locale.ROOT)
        val h = host.lowercase(Locale.ROOT)
        return when {
            p.startsWith("**.") -> {
                val suffix = p.substring(3)
                val prefixLen = h.length - suffix.length
                h.endsWith(suffix) && (prefixLen == 0 || (prefixLen > 0 && h[prefixLen - 1] == '.'))
            }
            p.startsWith("*.") -> {
                val suffix = p.substring(1)
                val prefixLen = h.length - suffix.length
                prefixLen > 0 && h.endsWith(suffix) && h.lastIndexOf('.', prefixLen - 1) == -1
            }
            else -> h == p
        }
    }

    private fun probeLiveEndpoints(pins: Map<String, Set<String>>, explicitProbeHosts: List<String>): AuditFinding {
        val targets = LinkedHashSet<String>()
        for (pattern in pins.keys) {
            if (!pattern.startsWith("*") && !isLocalHost(pattern)) targets += pattern
        }
        for (candidate in explicitProbeHosts) {
            if (matchingPinsForIdentities(pins, listOf(candidate)).isNotEmpty()) targets += candidate
        }
        if (targets.isEmpty()) {
            return AuditFinding(
                checkId = "tls.spki.live_match",
                target = AuditTarget.TRANSPORT_TLS,
                title = "Live TLS SPKI pin verification",
                status = CheckStatus.SKIP,
                severity = CheckSeverity.HIGH,
                weight = 15,
                summary = "No concrete live hostnames matched the configured pin rules.",
            )
        }
        val mismatches = mutableListOf<String>()
        var verified = 0
        for (host in targets) {
            val resolved = runCatching { InetAddress.getAllByName(host) }.isSuccess
            if (!resolved) continue
            try {
                val chain = fetchCertificateChain(host)
                val identities = extractLeafIdentities(chain[0])
                val expected = matchingPinsForIdentities(pins, identities).ifEmpty {
                    matchingPinsForIdentities(pins, listOf(host))
                }
                val presented = chain.map(::spkiSha256Pin)
                if (presented.none { it in expected }) {
                    mismatches += "$host: presented=$presented expected=$expected"
                } else {
                    verified += 1
                }
            } catch (error: IOException) {
                mismatches += "$host: TLS handshake error (${error.message})"
            }
        }
        val passed = mismatches.isEmpty()
        return AuditFinding(
            checkId = "tls.spki.live_match",
            target = AuditTarget.TRANSPORT_TLS,
            title = "Live TLS SPKI pin verification",
            status = if (passed) CheckStatus.PASS else CheckStatus.FAIL,
            severity = CheckSeverity.HIGH,
            weight = 15,
            summary = if (passed) {
                "Verified live TLS SPKI pins for $verified endpoint(s)."
            } else {
                "${mismatches.size} live TLS endpoint(s) failed SPKI pin matching."
            },
            evidence = mismatches.take(5),
            remediation = "Refresh SPKI pins with 'print-tls-pins' before cutting a release.",
        )
    }

    private fun fetchCertificateChain(host: String): List<X509Certificate> {
        val connection = URI.create("https://$host").toURL().openConnection() as HttpsURLConnection
        connection.connectTimeout = TIMEOUT_MS
        connection.readTimeout = TIMEOUT_MS
        try {
            connection.connect()
            val certs = connection.serverCertificates.filterIsInstance<X509Certificate>()
            require(certs.isNotEmpty()) { "Server returned no X.509 certificates for '$host'." }
            return certs
        } finally {
            connection.disconnect()
        }
    }

    private fun extractLeafIdentities(leaf: X509Certificate): List<String> {
        val ids = LinkedHashSet<String>()
        leaf.subjectAlternativeNames.orEmpty().forEach { entry ->
            if (entry.size >= 2) {
                val type = entry[0] as? Int
                val value = entry[1] as? String
                if ((type == 2 || type == 7) && !value.isNullOrBlank()) {
                    ids += value.trim()
                }
            }
        }
        if (ids.isEmpty()) {
            try {
                val dn = LdapName(leaf.subjectX500Principal.getName(X500Principal.RFC2253))
                dn.rdns.filter { it.type.equals("CN", ignoreCase = true) }.forEach { rdn ->
                    val cn = rdn.value?.toString()?.trim()
                    if (!cn.isNullOrEmpty()) ids += cn
                }
            } catch (_: InvalidNameException) {
                // Fallback handled by caller.
            }
        }
        return ids.toList()
    }
}

private fun unconfiguredOutput(policy: ReleaseGuardPolicy): AnalyzerOutput = AnalyzerOutput(
    findings = listOf(
        AuditFinding(
            checkId = "tls.spki.configured",
            target = AuditTarget.TRANSPORT_TLS,
            title = "TLS SPKI pinning configured",
            status = if (policy.tls.requirePins) CheckStatus.FAIL else CheckStatus.WARN,
            severity = if (policy.tls.requirePins) CheckSeverity.HIGH else CheckSeverity.MEDIUM,
            weight = 20,
            summary = "No TLS SPKI pins configured; clients rely on OS CA trust store only.",
            remediation = "Configure at least 2 rotation-safe SPKI pins per production endpoint (intermediate CA + backup CA).",
        ),
    ),
    metrics = mapOf("tls.pinnedHostRules" to "0"),
)

private fun invalidSyntaxOutput(message: String): AnalyzerOutput = AnalyzerOutput(
    findings = listOf(
        AuditFinding(
            checkId = "tls.spki.syntax",
            target = AuditTarget.TRANSPORT_TLS,
            title = "TLS SPKI pin syntax validity",
            status = CheckStatus.FAIL,
            severity = CheckSeverity.CRITICAL,
            weight = 20,
            summary = message,
            remediation = "Use 'host=sha256/<32-byte-base64>,sha256/<backup>' entries separated by ';' or newlines.",
        ),
    ),
)

private fun checkBackupPins(parsed: Map<String, Set<String>>, policy: ReleaseGuardPolicy): AuditFinding {
    val minPins = policy.tls.minPinsPerHost.coerceAtLeast(1)
    val underPinned = parsed.filterValues { it.size < minPins }.keys.sorted()
    return AuditFinding(
        checkId = "tls.spki.rotation_backup",
        target = AuditTarget.TRANSPORT_TLS,
        title = "TLS SPKI backup pin rotation safety",
        status = if (underPinned.isEmpty()) CheckStatus.PASS else CheckStatus.WARN,
        severity = CheckSeverity.MEDIUM,
        weight = 10,
        summary = if (underPinned.isEmpty()) {
            "Every pinned host pattern has at least $minPins SPKI pins for safe certificate rotation."
        } else {
            "${underPinned.size} host pattern(s) have fewer than $minPins SPKI pins."
        },
        evidence = underPinned,
        remediation = "Configure at least $minPins pins per host (primary intermediate CA + backup CA/key) to avoid rotation lockout.",
    )
}

private fun normalizePattern(raw: String): String {
    val pattern = raw.trim().lowercase(Locale.ROOT)
    require(pattern.isNotEmpty() && pattern.none(Char::isWhitespace)) { "Invalid TLS host pattern '$raw'." }
    val valid = when {
        pattern.startsWith("**.") -> pattern.length > 3 && pattern.indexOf('*', 2) == -1
        pattern.startsWith("*.") -> pattern.length > 2 && pattern.indexOf('*', 1) == -1
        else -> '*' !in pattern
    }
    require(valid) { "Unsupported TLS wildcard pattern '$raw'." }
    return pattern
}

private fun normalizeHostArg(raw: String): String {
    var host = raw.trim().lowercase(Locale.ROOT)
        .removePrefix("https://")
        .removePrefix("http://")
        .removePrefix("wss://")
        .removePrefix("ws://")
    host = host.substringBefore('/').substringBefore(':')
    require(host.isNotEmpty()) { "Empty host argument '$raw'." }
    return host
}

private fun isLocalHost(host: String): Boolean = host == "localhost" || host == "127.0.0.1" || host == "::1"

private fun matchingPinsForIdentities(pins: Map<String, Set<String>>, identities: Collection<String>): Set<String> {
    val cleanIds = identities.map { it.trim().lowercase(Locale.ROOT) }.filter(String::isNotEmpty)
    val expected = LinkedHashSet<String>()
    for ((pattern, hostPins) in pins) {
        val matched = cleanIds.any { id ->
            TlsPinAnalyzer.matchesPattern(pattern, id) ||
                (id.startsWith("*.") && id.count { it == '.' } >= 2 && TlsPinAnalyzer.matchesPattern(id, pattern))
        }
        if (matched) expected.addAll(hostPins)
    }
    return expected
}

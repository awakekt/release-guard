/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.analyzers

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Locale

/** Insecure directives discovered in an Android `network_security_config.xml` resource. */
public data class NetworkSecurityConfigSummary(
    public val trustsUserCertificates: Boolean = false,
    public val hasDebugOverrides: Boolean = false,
    public val permitsCleartextTraffic: Boolean = false,
    public val issues: List<String> = emptyList(),
)

/**
 * Pure-Kotlin inspector for Android `res/xml/network_security_config.xml` resources in plain XML,
 * compiled AXML (`.apk`), or Protobuf XML (`.aab`) form.
 */
public object NetworkSecurityConfigInspector {
    private const val RES_XML_TYPE = 0x0003
    private val userCertRegex = Regex("""<certificates\b[^>]*\bsrc\s*=\s*"user"""", RegexOption.IGNORE_CASE)
    private val debugOverridesRegex = Regex("""<debug-overrides\b""", RegexOption.IGNORE_CASE)
    private val cleartextRegex = Regex("""\bcleartextTrafficPermitted\s*=\s*"true"""", RegexOption.IGNORE_CASE)

    /** Returns `true` when [bytes] represents an Android `network-security-config` XML resource (plain or compiled AXML). */
    internal fun isNetworkSecurityConfig(bytes: ByteArray): Boolean {
        val isAxml = bytes.size >= 8 &&
            (ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getShort(0).toInt() and 0xFFFF) == RES_XML_TYPE
        return if (isAxml) {
            BinaryXmlManifestInspector.extractStringsFromBinaryXml(bytes)
                .any { it.equals("network-security-config", ignoreCase = true) }
        } else {
            String(bytes, Charsets.UTF_8).contains("<network-security-config", ignoreCase = true)
        }
    }

    /** Inspects raw bytes of a `network_security_config.xml` file. */
    public fun parse(bytes: ByteArray): NetworkSecurityConfigSummary {
        val isAxml = bytes.size >= 8 &&
            (ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getShort(0).toInt() and 0xFFFF) == RES_XML_TYPE
        return when {
            isAxml -> inspectBinaryStrings(BinaryXmlManifestInspector.extractStringsFromBinaryXml(bytes))
            String(bytes, Charsets.UTF_8).contains("<network-security-config", ignoreCase = true) ->
                inspectPlainXml(String(bytes, Charsets.UTF_8))
            else -> inspectBinaryStrings(IdentifierHeuristics.extractPrintableStrings(bytes))
        }
    }

    private fun inspectPlainXml(xml: String): NetworkSecurityConfigSummary {
        val trustsUser = userCertRegex.containsMatchIn(xml)
        val hasDebug = debugOverridesRegex.containsMatchIn(xml)
        val permitsCleartext = cleartextRegex.containsMatchIn(xml)
        return buildSummary(trustsUser, hasDebug, permitsCleartext)
    }

    private fun inspectBinaryStrings(tokens: List<String>): NetworkSecurityConfigSummary {
        val lower = tokens.map { it.lowercase(Locale.ROOT) }
        val hasCertElement = lower.any { it == "certificates" }
        val trustsUser = hasCertElement && lower.any { it == "user" }
        val hasDebug = lower.any { it == "debug-overrides" }
        // In compiled AXML/protobuf, boolean attribute values aren't plain "true" strings unless present;
        // detect explicit cleartextTrafficPermitted="true" or cleartext domains.
        val permitsCleartext = lower.any { "cleartexttrafficpermitted=\"true\"" in it }
        return buildSummary(trustsUser, hasDebug, permitsCleartext)
    }

    private fun buildSummary(
        trustsUser: Boolean,
        hasDebug: Boolean,
        permitsCleartext: Boolean,
    ): NetworkSecurityConfigSummary {
        val issues = buildList {
            if (trustsUser) add("trusts user-installed CA certificates (<certificates src=\"user\"/>)")
            if (hasDebug) add("contains <debug-overrides> block")
            if (permitsCleartext) add("enables cleartextTrafficPermitted=\"true\"")
        }
        return NetworkSecurityConfigSummary(
            trustsUserCertificates = trustsUser,
            hasDebugOverrides = hasDebug,
            permitsCleartextTraffic = permitsCleartext,
            issues = issues,
        )
    }
}

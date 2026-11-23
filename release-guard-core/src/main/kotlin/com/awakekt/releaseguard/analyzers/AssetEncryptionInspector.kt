/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.analyzers

import com.awakekt.releaseguard.model.AssetEncryptionPolicy
import com.awakekt.releaseguard.model.AuditFinding
import com.awakekt.releaseguard.model.AuditTarget
import com.awakekt.releaseguard.model.CheckSeverity
import com.awakekt.releaseguard.model.CheckStatus
import com.awakekt.releaseguard.model.ContainerHeaderRule
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Locale
import kotlin.math.ln

/** Inspection result for a single content bundle header. */
public data class BundleHeaderCheck(
    public val path: String,
    public val isEncrypted: Boolean,
    public val detail: String,
)

/**
 * Inspects packaged content bundle headers (such as Awake `.awkb` v2 bundles where header version >= 2
 * and flags bit 0 indicates per-member AES-256-GCM encryption) to ensure plaintext bundles do not ship
 * when asset encryption is required.
 */
public object AssetEncryptionInspector {
    private val awkbMagic = "AWKB".toByteArray(Charsets.US_ASCII)
    private const val AWKB_FLAG_ENCRYPTED = 0x0001

    /** Returns `true` when [path] ends with one of [policy]'s configured [AssetEncryptionPolicy.bundleExtensions]. */
    public fun matchesBundleExtension(path: String, policy: AssetEncryptionPolicy): Boolean {
        val ext = path.substringAfterLast('.', "").lowercase(Locale.ROOT)
        return ext.isNotEmpty() && policy.bundleExtensions.any { it.lowercase(Locale.ROOT) == ext }
    }

    /** Returns `true` when [path] matches either default `.awkb` bundle extensions or any custom container rule. */
    public fun matchesAnyContainer(path: String, policy: AssetEncryptionPolicy): Boolean {
        if (matchesBundleExtension(path, policy)) return true
        val ext = path.substringAfterLast('.', "").lowercase(Locale.ROOT)
        return ext.isNotEmpty() &&
            policy.customContainerRules.any { it.extension.lowercase(Locale.ROOT).removePrefix(".") == ext }
    }

    /** Inspects a container at [path] using a matching [ContainerHeaderRule] or `.awkb` v2 header rules + optional entropy floor. */
    public fun inspectContainer(
        path: String,
        sampleBytes: ByteArray,
        policy: AssetEncryptionPolicy,
    ): BundleHeaderCheck {
        val ext = path.substringAfterLast('.', "").lowercase(Locale.ROOT)
        val customRule = policy.customContainerRules.firstOrNull {
            it.extension.lowercase(Locale.ROOT).removePrefix(".") == ext
        }
        val base = if (customRule != null) {
            inspectCustomRule(path, sampleBytes, customRule)
        } else {
            inspectAwkbHeader(path, sampleBytes)
        }
        val minEntropy = policy.minContainerEntropy
        if (!base.isEncrypted || minEntropy == null || sampleBytes.size < 256) return base
        val payload = sampleBytes.copyOfRange(minOf(64, sampleBytes.size), sampleBytes.size)
        val entropy = computeByteEntropy(payload)
        return if (entropy < minEntropy) {
            base.copy(
                isEncrypted = false,
                detail = "${base.detail}; low payload entropy ${String.format(Locale.ROOT, "%.2f", entropy)} < $minEntropy",
            )
        } else {
            base
        }
    }

    /** Inspects a container header against a generic declarative [rule]. */
    public fun inspectCustomRule(path: String, bytes: ByteArray, rule: ContainerHeaderRule): BundleHeaderCheck {
        val expectedMagic = rule.expectedMagicAscii.toByteArray(Charsets.US_ASCII)
        return when {
            bytes.size < rule.minHeaderBytes || bytes.size < expectedMagic.size ->
                BundleHeaderCheck(path, false, "truncated header (${bytes.size} bytes)")
            !expectedMagic.indices.all { idx -> bytes[idx] == expectedMagic[idx] } ->
                BundleHeaderCheck(path, false, "unexpected magic (expected '${rule.expectedMagicAscii}')")
            else -> {
                val order = if (rule.littleEndian) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN
                val buf = ByteBuffer.wrap(bytes).order(order)
                val versionOk = rule.versionOffset?.let { off ->
                    bytes.size >= off + 2 && (buf.getShort(off).toInt() and 0xFFFF) >= rule.minVersion
                } ?: true
                val flagsOk = rule.flagsOffset?.let { off ->
                    bytes.size >= off + 2 && ((buf.getShort(off).toInt() and 0xFFFF) and rule.requiredFlagsMask) == rule.requiredFlagsMask
                } ?: true
                val ok = versionOk && flagsOk
                BundleHeaderCheck(path, ok, "${rule.extension} magic='${rule.expectedMagicAscii}' ok=$ok")
            }
        }
    }

    /** Computes Shannon entropy in bits per byte (`0.0..8.0`) over [bytes]. */
    public fun computeByteEntropy(bytes: ByteArray): Double {
        if (bytes.isEmpty()) return 0.0
        val counts = IntArray(256)
        for (b in bytes) counts[b.toInt() and 0xFF]++
        val total = bytes.size.toDouble()
        var entropy = 0.0
        for (c in counts) {
            if (c > 0) {
                val p = c / total
                entropy -= p * (ln(p) / ln(2.0))
            }
        }
        return entropy
    }

    /** Inspects the first header bytes of a `.awkb` content bundle at [path]. */
    public fun inspectAwkbHeader(path: String, headerBytes: ByteArray): BundleHeaderCheck = when {
        headerBytes.size < 8 -> BundleHeaderCheck(path, false, "truncated header (${headerBytes.size} bytes)")
        !awkbMagic.indices.all { idx -> headerBytes[idx] == awkbMagic[idx] } ->
            BundleHeaderCheck(path, false, "unrecognized bundle magic")
        else -> {
            val buf = ByteBuffer.wrap(headerBytes).order(ByteOrder.LITTLE_ENDIAN)
            val version = buf.getShort(4).toInt() and 0xFFFF
            val flags = buf.getShort(6).toInt() and 0xFFFF
            val encrypted = version >= 2 && (flags and AWKB_FLAG_ENCRYPTED) != 0
            BundleHeaderCheck(path = path, isEncrypted = encrypted, detail = "awkb v$version flags=0x${flags.toString(16)}")
        }
    }

    /** Builds a scored [AuditFinding] summarizing [checks] for [target]. */
    public fun toFinding(
        checkId: String,
        target: AuditTarget,
        checks: List<BundleHeaderCheck>,
        policy: AssetEncryptionPolicy,
    ): AuditFinding = when {
        !policy.enabled -> AuditFinding(
            checkId = checkId,
            target = target,
            title = "Packaged asset bundle encryption",
            status = CheckStatus.SKIP,
            severity = CheckSeverity.MEDIUM,
            weight = 10,
            summary = "Asset bundle encryption check disabled by policy.",
        )
        checks.isEmpty() -> AuditFinding(
            checkId = checkId,
            target = target,
            title = "Packaged asset bundle encryption",
            status = CheckStatus.SKIP,
            severity = CheckSeverity.MEDIUM,
            weight = 10,
            summary = "No packaged content bundles (${policy.bundleExtensions.joinToString()}) discovered.",
        )
        else -> {
            val plaintext = checks.filterNot { it.isEncrypted }
            val passed = plaintext.isEmpty()
            AuditFinding(
                checkId = checkId,
                target = target,
                title = "Packaged asset bundle encryption",
                status = if (passed) CheckStatus.PASS else CheckStatus.FAIL,
                severity = CheckSeverity.HIGH,
                weight = 10,
                summary = if (passed) {
                    "All ${checks.size} packaged content bundle(s) carry encrypted v2 headers."
                } else {
                    "${plaintext.size} of ${checks.size} packaged content bundle(s) are unencrypted."
                },
                evidence = plaintext.take(10).map { "${it.path} (${it.detail})" },
                remediation = "Encrypt release content bundles with a bundle encryption key before packaging.",
            )
        }
    }
}

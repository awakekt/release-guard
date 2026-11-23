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
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Locale

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

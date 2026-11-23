/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.analyzers

import com.awakekt.releaseguard.io.BinaryReadLimits
import com.awakekt.releaseguard.io.ZipReadBudget
import java.io.ByteArrayInputStream
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Locale
import java.util.zip.ZipFile

/** One X.509 signing certificate discovered in an APK or AAB. */
public data class ApkCertificateInfo(
    public val subjectDn: String,
    public val issuerDn: String,
    public val sha256Hex: String,
    public val isAndroidDebugCert: Boolean,
)

/** Summary of v1 (JAR) and v2/v3 (APK Signing Block) signatures inside an APK or AAB. */
public data class ApkSigningSummary(
    public val hasV1Signature: Boolean,
    public val hasV2OrV3Signature: Boolean,
    public val certificates: List<ApkCertificateInfo>,
) {
    /** `true` if at least one signing scheme is present. */
    public val isSigned: Boolean
        get() = hasV1Signature || hasV2OrV3Signature || certificates.isNotEmpty()
}

/**
 * Pure-Kotlin inspector for Android APK/AAB signing certificates (v1 `META-INF` `.RSA`/`.DSA`/`.EC`
 * entries and v2/v3 APK Signing Blocks).
 */
public object ApkCertificateInspector {
    private val v1CertRegex = Regex("""^META-INF/[^/]+\.(?:RSA|DSA|EC)$""", RegexOption.IGNORE_CASE)
    private val apkSigBlockMagic = "APK Sig Block 42".toByteArray(Charsets.US_ASCII)
    private const val EOCD_SIGNATURE = 0x06054B50
    private const val APK_SIGNATURE_SCHEME_V2_ID = 0x7109871A
    private const val APK_SIGNATURE_SCHEME_V3_ID = 0xF05368C0.toInt()
    private const val MAX_SIG_BLOCK_BYTES: Long = 16L * 1024L * 1024L
    private const val MAX_CERT_ENTRY_BYTES: Long = 4L * 1024L * 1024L

    /** Inspects v1 and v2/v3 signing metadata in [archiveFile]. */
    public fun inspect(
        archiveFile: File,
        limits: BinaryReadLimits = BinaryReadLimits(),
    ): ApkSigningSummary {
        val v1Certs = readV1Certificates(archiveFile, limits)
        val v2Result = readV2OrV3SigningBlock(archiveFile)
        val combined = (v1Certs + v2Result.second).distinctBy { it.sha256Hex }
        return ApkSigningSummary(
            hasV1Signature = v1Certs.isNotEmpty(),
            hasV2OrV3Signature = v2Result.first,
            certificates = combined,
        )
    }

    private fun readV1Certificates(archiveFile: File, limits: BinaryReadLimits): List<ApkCertificateInfo> {
        val factory = CertificateFactory.getInstance("X.509")
        val certs = mutableListOf<ApkCertificateInfo>()
        val budget = ZipReadBudget(limits)
        ZipFile(archiveFile).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                budget.recordEntry(entry.name)
                if (entry.isDirectory || !v1CertRegex.matches(entry.name)) continue
                val bytes = budget.readEntryBytes(zip, entry, MAX_CERT_ENTRY_BYTES)
                certs += parseX509Certificates(factory, bytes)
            }
        }
        return certs
    }

    private fun parseX509Certificates(factory: CertificateFactory, bytes: ByteArray): List<ApkCertificateInfo> =
        try {
            factory.generateCertificates(ByteArrayInputStream(bytes))
                .filterIsInstance<X509Certificate>()
                .map(::toInfo)
        } catch (_: CertificateException) {
            emptyList()
        }

    private fun readV2OrV3SigningBlock(apkFile: File): Pair<Boolean, List<ApkCertificateInfo>> {
        val fileLen = apkFile.length()
        if (fileLen < 22L) return false to emptyList()
        return RandomAccessFile(apkFile, "r").use { raf ->
            val centralDirOffset = findCentralDirectoryOffset(raf, fileLen)
            if (centralDirOffset == null || centralDirOffset < 32L) {
                false to emptyList()
            } else {
                parseSigningBlockAt(raf, centralDirOffset)
            }
        }
    }

    private fun parseSigningBlockAt(raf: RandomAccessFile, centralDirOffset: Long): Pair<Boolean, List<ApkCertificateInfo>> {
        val footer = ByteArray(24)
        raf.seek(centralDirOffset - 24L)
        raf.readFully(footer)
        if (!footer.copyOfRange(8, 24).contentEquals(apkSigBlockMagic)) return false to emptyList()
        val blockSizeExcludingInitial = ByteBuffer.wrap(footer, 0, 8).order(ByteOrder.LITTLE_ENDIAN).long
        val totalBlockSize = blockSizeExcludingInitial + 8L
        val blockStart = centralDirOffset - totalBlockSize
        return if (blockStart < 0L || totalBlockSize > MAX_SIG_BLOCK_BYTES) {
            true to emptyList()
        } else {
            val block = ByteArray(totalBlockSize.toInt())
            raf.seek(blockStart)
            raf.readFully(block)
            true to extractV2OrV3Certs(block)
        }
    }

    private fun findCentralDirectoryOffset(raf: RandomAccessFile, fileLen: Long): Long? {
        val searchLen = minOf(fileLen, 65557L).toInt()
        val tail = ByteArray(searchLen)
        raf.seek(fileLen - searchLen)
        raf.readFully(tail)
        val buf = ByteBuffer.wrap(tail).order(ByteOrder.LITTLE_ENDIAN)
        for (pos in (searchLen - 22) downTo 0) {
            if (buf.getInt(pos) == EOCD_SIGNATURE) {
                val commentLen = buf.getShort(pos + 20).toInt() and 0xFFFF
                if (pos + 22 + commentLen == searchLen) {
                    return buf.getInt(pos + 16).toLong() and 0xFFFFFFFFL
                }
            }
        }
        return null
    }

    private fun extractV2OrV3Certs(block: ByteArray): List<ApkCertificateInfo> {
        val buf = ByteBuffer.wrap(block).order(ByteOrder.LITTLE_ENDIAN)
        val pairsEnd = block.size - 24
        var pos = 8
        val factory = CertificateFactory.getInstance("X.509")
        val certs = mutableListOf<ApkCertificateInfo>()
        while (pos + 12 <= pairsEnd) {
            val pairLen = buf.getLong(pos)
            if (pairLen < 4L || pos + 8L + pairLen > pairsEnd) break
            val id = buf.getInt(pos + 8)
            val valueStart = pos + 12
            val valueLen = (pairLen - 4L).toInt()
            if (id == APK_SIGNATURE_SCHEME_V2_ID || id == APK_SIGNATURE_SCHEME_V3_ID) {
                certs += parseSignersSequence(block, valueStart, valueStart + valueLen, factory)
            }
            pos += (8L + pairLen).toInt()
        }
        return certs
    }

    private fun parseSignersSequence(
        block: ByteArray,
        start: Int,
        end: Int,
        factory: CertificateFactory,
    ): List<ApkCertificateInfo> {
        if (start + 4 > end) return emptyList()
        val buf = ByteBuffer.wrap(block).order(ByteOrder.LITTLE_ENDIAN)
        val signersLen = buf.getInt(start)
        var pos = start + 4
        val signersEnd = minOf(pos + signersLen, end)
        val certs = mutableListOf<ApkCertificateInfo>()
        while (pos + 4 <= signersEnd) {
            val signerLen = buf.getInt(pos)
            val signerStart = pos + 4
            val signerEnd = minOf(signerStart + signerLen, signersEnd)
            if (signerLen <= 0 || signerStart + 4 > signerEnd) break
            val signedDataLen = buf.getInt(signerStart)
            val sdStart = signerStart + 4
            val sdEnd = minOf(sdStart + signedDataLen, signerEnd)
            certs += parseSignedDataCerts(block, buf, sdStart, sdEnd, factory)
            pos = signerEnd
        }
        return certs
    }

    private fun parseSignedDataCerts(
        block: ByteArray,
        buf: ByteBuffer,
        start: Int,
        end: Int,
        factory: CertificateFactory,
    ): List<ApkCertificateInfo> {
        val certsLenPos = if (start + 4 <= end) start + 4 + buf.getInt(start) else end
        if (certsLenPos + 4 > end) return emptyList()
        val certsLen = buf.getInt(certsLenPos)
        var pos = certsLenPos + 4
        val certsEnd = minOf(pos + certsLen, end)
        val result = mutableListOf<ApkCertificateInfo>()
        while (pos + 4 <= certsEnd) {
            val certLen = buf.getInt(pos)
            val certStart = pos + 4
            val certEnd = minOf(certStart + certLen, certsEnd)
            if (certLen <= 0 || certEnd > certsEnd) break
            result += parseX509Certificates(factory, block.copyOfRange(certStart, certEnd))
            pos = certEnd
        }
        return result
    }

    private fun toInfo(cert: X509Certificate): ApkCertificateInfo {
        val subject = cert.subjectX500Principal.name
        val issuer = cert.issuerX500Principal.name
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(cert.encoded)
            .joinToString("") { byte -> String.format(Locale.ROOT, "%02x", byte) }
        val isDebug = subject.contains("CN=Android Debug", ignoreCase = true) ||
            issuer.contains("CN=Android Debug", ignoreCase = true)
        return ApkCertificateInfo(
            subjectDn = subject,
            issuerDn = issuer,
            sha256Hex = digest,
            isAndroidDebugCert = isDebug,
        )
    }
}

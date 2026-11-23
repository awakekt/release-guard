/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.analyzers

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Security-relevant Apple `Info.plist` and entitlements settings extracted from XML or binary `bplist00`. */
public data class ApplePlistSummary(
    public val allowsArbitraryLoads: Boolean = false,
    public val insecureExceptionDomains: List<String> = emptyList(),
    public val fileSharingEnabled: Boolean = false,
    public val supportsOpeningDocumentsInPlace: Boolean = false,
    public val getTaskAllow: Boolean = false,
    public val hasProvisionedDevices: Boolean = false,
    public val stringValues: List<String> = emptyList(),
)

/**
 * Pure-Kotlin Apple Property List parser supporting both XML `.plist` and binary `bplist00` formats
 * (as emitted by Xcode release archives and embedded inside `.mobileprovision` CMS containers).
 */
public object BinaryPlistInspector {
    private val bplistMagic = "bplist00".toByteArray(Charsets.US_ASCII)

    private val arbitraryLoadsRegex = Regex(
        """<key>\s*NSAllowsArbitraryLoads\s*</key>\s*<true\s*/>""",
        setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL),
    )
    private val exceptionHttpRegex = Regex(
        """<key>\s*([^<]+?)\s*</key>\s*<dict>(?:(?!</dict>).)*?<key>\s*(?:NSExceptionAllowsInsecureHTTPLoads|NSTemporaryExceptionAllowsInsecureHTTPLoads)\s*</key>\s*<true\s*/>""",
        setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL),
    )
    private val fileSharingRegex = Regex(
        """<key>\s*UIFileSharingEnabled\s*</key>\s*<true\s*/>""",
        setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL),
    )
    private val docsInPlaceRegex = Regex(
        """<key>\s*LSSupportsOpeningDocumentsInPlace\s*</key>\s*<true\s*/>""",
        setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL),
    )
    private val getTaskAllowRegex = Regex(
        """<key>\s*get-task-allow\s*</key>\s*<true\s*/>""",
        setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL),
    )
    private val provisionedDevicesRegex = Regex("""<key>\s*ProvisionedDevices\s*</key>""", RegexOption.IGNORE_CASE)
    private val xmlStringValueRegex = Regex("""<string>([^<]+)</string>""")

    /** Parses an XML plist, binary `bplist00` plist, or CMS-wrapped `.mobileprovision` plist payload. */
    public fun parse(bytes: ByteArray): ApplePlistSummary = when {
        isBinaryPlist(bytes) -> parseBinaryPlist(bytes)
        else -> parseXmlPlist(String(bytes, Charsets.UTF_8))
    }

    /** Returns `true` when [bytes] starts with the `bplist00` header. */
    public fun isBinaryPlist(bytes: ByteArray): Boolean =
        bytes.size >= 40 && bplistMagic.indices.all { idx -> bytes[idx] == bplistMagic[idx] }

    private fun parseXmlPlist(text: String): ApplePlistSummary {
        val start = text.indexOf("<plist")
        val slice = if (start >= 0) {
            val end = text.indexOf("</plist>", start)
            if (end > start) text.substring(start, end + "</plist>".length) else text.substring(start)
        } else {
            text
        }
        val exceptions = exceptionHttpRegex.findAll(slice)
            .map { it.groupValues[1].trim() }
            .filter { it.isNotEmpty() && !it.equals("NSAppTransportSecurity", ignoreCase = true) }
            .distinct()
            .sorted()
            .toList()
        val strings = xmlStringValueRegex.findAll(slice).map { it.groupValues[1] }.toList()
        return ApplePlistSummary(
            allowsArbitraryLoads = arbitraryLoadsRegex.containsMatchIn(slice),
            insecureExceptionDomains = exceptions,
            fileSharingEnabled = fileSharingRegex.containsMatchIn(slice),
            supportsOpeningDocumentsInPlace = docsInPlaceRegex.containsMatchIn(slice),
            getTaskAllow = getTaskAllowRegex.containsMatchIn(slice),
            hasProvisionedDevices = provisionedDevicesRegex.containsMatchIn(slice),
            stringValues = strings,
        )
    }

    private fun parseBinaryPlist(bytes: ByteArray): ApplePlistSummary {
        val trailer = ByteBuffer.wrap(bytes, bytes.size - 32, 32).slice().order(ByteOrder.BIG_ENDIAN)
        val offsetIntSize = trailer.get(6).toInt() and 0xFF
        val objectRefSize = trailer.get(7).toInt() and 0xFF
        val numObjects = trailer.getLong(8).toInt()
        val topObject = trailer.getLong(16).toInt()
        val offsetTableOffset = trailer.getLong(24).toInt()
        val valid = offsetIntSize in 1..8 &&
            objectRefSize in 1..8 &&
            numObjects in 1..100_000 &&
            offsetTableOffset >= 8 &&
            offsetTableOffset + numObjects * offsetIntSize <= bytes.size - 32
        val root = if (valid) {
            val offsets = IntArray(numObjects) { idx ->
                readBigEndianInt(bytes, offsetTableOffset + idx * offsetIntSize, offsetIntSize)
            }
            BinaryPlistReader(bytes, offsets, objectRefSize).readObject(topObject, 0) as? Map<*, *>
        } else {
            null
        }
        return root?.let(::summarizeMap) ?: ApplePlistSummary()
    }

    private fun summarizeMap(root: Map<*, *>): ApplePlistSummary {
        val ats = root["NSAppTransportSecurity"] as? Map<*, *>
        val allowsArbitrary = (ats?.get("NSAllowsArbitraryLoads") as? Boolean) == true
        val exceptionDomains = extractInsecureExceptionDomains(ats?.get("NSExceptionDomains") as? Map<*, *>)
        val entitlements = root["Entitlements"] as? Map<*, *>
        val getTaskAllow = (root["get-task-allow"] as? Boolean) == true ||
            (entitlements?.get("get-task-allow") as? Boolean) == true
        val strings = mutableListOf<String>()
        collectStrings(root, strings)
        return ApplePlistSummary(
            allowsArbitraryLoads = allowsArbitrary,
            insecureExceptionDomains = exceptionDomains,
            fileSharingEnabled = (root["UIFileSharingEnabled"] as? Boolean) == true,
            supportsOpeningDocumentsInPlace = (root["LSSupportsOpeningDocumentsInPlace"] as? Boolean) == true,
            getTaskAllow = getTaskAllow,
            hasProvisionedDevices = root.containsKey("ProvisionedDevices"),
            stringValues = strings,
        )
    }

    private fun extractInsecureExceptionDomains(domains: Map<*, *>?): List<String> {
        if (domains == null) return emptyList()
        return domains.entries.mapNotNull { (domain, cfg) ->
            val map = cfg as? Map<*, *>
            val insecure = (map?.get("NSExceptionAllowsInsecureHTTPLoads") as? Boolean) == true ||
                (map?.get("NSTemporaryExceptionAllowsInsecureHTTPLoads") as? Boolean) == true
            if (insecure) domain?.toString() else null
        }.sorted()
    }

    private fun collectStrings(node: Any?, out: MutableList<String>) {
        when (node) {
            is String -> out += node
            is List<*> -> node.forEach { collectStrings(it, out) }
            is Map<*, *> -> node.values.forEach { collectStrings(it, out) }
        }
    }

    private class BinaryPlistReader(
        private val bytes: ByteArray,
        private val offsets: IntArray,
        private val refSize: Int,
    ) {
        fun readObject(index: Int, depth: Int): Any? {
            val offset = if (depth <= 32 && index in offsets.indices) offsets[index] else -1
            if (offset !in 8 until bytes.size - 32) return null
            val marker = bytes[offset].toInt() and 0xFF
            val high = marker ushr 4
            val low = marker and 0x0F
            return when (high) {
                0x0 -> decodeSingleton(low)
                0x1 -> readSizedInt(offset + 1, 1 shl low)
                0x5 -> decodeAsciiString(offset, low)
                0x6 -> decodeUtf16String(offset, low)
                0xA -> decodeArray(offset, low, depth)
                0xD -> decodeDict(offset, low, depth)
                else -> null
            }
        }

        private fun decodeSingleton(low: Int): Any? = when (low) {
            0x08 -> false
            0x09 -> true
            else -> null
        }

        private fun decodeCount(offset: Int, low: Int): Pair<Int, Int> {
            if (low != 0x0F) return low to (offset + 1)
            val intMarker = bytes[offset + 1].toInt() and 0xFF
            val byteCount = 1 shl (intMarker and 0x0F)
            val count = readBigEndianInt(bytes, offset + 2, byteCount)
            return count to (offset + 2 + byteCount)
        }

        private fun decodeAsciiString(offset: Int, low: Int): String {
            val (len, start) = decodeCount(offset, low)
            val safeLen = len.coerceIn(0, (bytes.size - 32 - start).coerceAtLeast(0))
            return String(bytes, start, safeLen, Charsets.US_ASCII)
        }

        private fun decodeUtf16String(offset: Int, low: Int): String {
            val (charLen, start) = decodeCount(offset, low)
            val byteLen = (charLen * 2).coerceIn(0, (bytes.size - 32 - start).coerceAtLeast(0))
            return String(bytes, start, byteLen, Charsets.UTF_16BE)
        }

        private fun decodeArray(offset: Int, low: Int, depth: Int): List<Any?> {
            val (count, start) = decodeCount(offset, low)
            val safeCount = count.coerceIn(0, 10_000)
            return List(safeCount) { idx ->
                val ref = readBigEndianInt(bytes, start + idx * refSize, refSize)
                readObject(ref, depth + 1)
            }
        }

        private fun decodeDict(offset: Int, low: Int, depth: Int): Map<String, Any?> {
            val (count, start) = decodeCount(offset, low)
            val safeCount = count.coerceIn(0, 10_000)
            val map = LinkedHashMap<String, Any?>(safeCount)
            val valBase = start + safeCount * refSize
            for (idx in 0 until safeCount) {
                val keyRef = readBigEndianInt(bytes, start + idx * refSize, refSize)
                val valRef = readBigEndianInt(bytes, valBase + idx * refSize, refSize)
                val key = readObject(keyRef, depth + 1)?.toString()
                if (key != null) {
                    map[key] = readObject(valRef, depth + 1)
                }
            }
            return map
        }

        private fun readSizedInt(start: Int, byteCount: Int): Long =
            readBigEndianLong(bytes, start, byteCount.coerceIn(1, 8))
    }
}

private fun readBigEndianInt(bytes: ByteArray, start: Int, count: Int): Int =
    readBigEndianLong(bytes, start, count).toInt()

private fun readBigEndianLong(bytes: ByteArray, start: Int, count: Int): Long {
    if (start < 0 || start + count > bytes.size) return 0L
    var value = 0L
    for (i in 0 until count) {
        value = (value shl 8) or (bytes[start + i].toLong() and 0xFFL)
    }
    return value
}

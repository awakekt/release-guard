/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.analyzers

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Locale

/** One exported Android component declared in `AndroidManifest.xml`. */
public data class ExportedComponentInfo(
    public val kind: String,
    public val name: String,
    public val hasPermissionGuard: Boolean,
    public val isLauncherActivity: Boolean,
)

/** Security-relevant flags and exported components extracted from an Android APK or AAB `AndroidManifest.xml`. */
public data class AndroidManifestFlags(
    public val packageName: String? = null,
    public val debuggable: Boolean = false,
    public val allowBackup: Boolean? = null,
    public val usesCleartextTraffic: Boolean? = null,
    public val testOnly: Boolean = false,
    public val targetSdkVersion: Int? = null,
    public val hasNetworkSecurityConfig: Boolean = false,
    public val exportedComponents: List<ExportedComponentInfo> = emptyList(),
)

internal data class ManifestParsedAttr(
    val name: String,
    val resourceId: Int,
    val stringValue: String?,
    val boolValue: Boolean?,
    val intValue: Int?,
)

internal class ManifestFlagsAccumulator {
    var packageName: String? = null
    var debuggable: Boolean = false
    var allowBackup: Boolean? = null
    var usesCleartextTraffic: Boolean? = null
    var testOnly: Boolean = false
    var targetSdkVersion: Int? = null
    var hasNetworkSecurityConfig: Boolean = false
    private val exportedComponents: MutableList<ExportedComponentInfo> = mutableListOf()
    private var currentComponent: PendingComponent? = null

    private class PendingComponent(
        val kind: String,
        val name: String,
        val exported: Boolean,
        val hasPermission: Boolean,
        var hasMainAction: Boolean = false,
        var hasLauncherCategory: Boolean = false,
    )

    fun recordElement(elementName: String, attrs: List<ManifestParsedAttr>) {
        when (elementName) {
            "manifest" -> attrs.firstOrNull { it.name == "package" }?.stringValue?.let { packageName = it }
            "uses-sdk" -> attrs.firstOrNull { it.resourceId == ATTR_TARGET_SDK || it.name == "targetSdkVersion" }
                ?.intValue?.let { targetSdkVersion = it }
            "application" -> applyApplicationAttrs(attrs)
            in COMPONENT_TAGS -> beginComponent(elementName, attrs)
            "action" -> recordIntentFilterTag(attrs, isAction = true)
            "category" -> recordIntentFilterTag(attrs, isAction = false)
        }
    }

    fun finishComponent() {
        val comp = currentComponent ?: return
        if (comp.exported) {
            exportedComponents += ExportedComponentInfo(
                kind = comp.kind,
                name = comp.name,
                hasPermissionGuard = comp.hasPermission,
                isLauncherActivity = comp.hasMainAction && comp.hasLauncherCategory,
            )
        }
        currentComponent = null
    }

    fun build(): AndroidManifestFlags {
        finishComponent()
        return AndroidManifestFlags(
            packageName = packageName,
            debuggable = debuggable,
            allowBackup = allowBackup,
            usesCleartextTraffic = usesCleartextTraffic,
            testOnly = testOnly,
            targetSdkVersion = targetSdkVersion,
            hasNetworkSecurityConfig = hasNetworkSecurityConfig,
            exportedComponents = exportedComponents.toList(),
        )
    }

    private fun beginComponent(kind: String, attrs: List<ManifestParsedAttr>) {
        finishComponent()
        val compName = attrs.firstOrNull { it.resourceId == ATTR_NAME || it.name == "name" }?.stringValue ?: "<unnamed>"
        val exported = attrs.firstOrNull { it.resourceId == ATTR_EXPORTED || it.name == "exported" }?.boolValue == true
        val hasPerm = attrs.any(::isNonBlankPermissionAttr)
        currentComponent = PendingComponent(kind, compName, exported, hasPerm)
    }

    private fun isNonBlankPermissionAttr(attr: ManifestParsedAttr): Boolean {
        val isPermName = attr.resourceId == ATTR_PERMISSION ||
            attr.name == "permission" ||
            attr.name == "readPermission" ||
            attr.name == "writePermission"
        return isPermName && !attr.stringValue.isNullOrBlank()
    }

    private fun recordIntentFilterTag(attrs: List<ManifestParsedAttr>, isAction: Boolean) {
        val value = attrs.firstOrNull { it.resourceId == ATTR_NAME || it.name == "name" }?.stringValue ?: return
        if (isAction && value == "android.intent.action.MAIN") currentComponent?.hasMainAction = true
        if (!isAction && value == "android.intent.category.LAUNCHER") currentComponent?.hasLauncherCategory = true
    }

    private fun applyApplicationAttrs(attrs: List<ManifestParsedAttr>) {
        for (attr in attrs) {
            applySingleAppAttr(attr)
        }
    }

    private fun applySingleAppAttr(attr: ManifestParsedAttr) {
        when (attr.resourceId) {
            ATTR_DEBUGGABLE -> attr.boolValue?.let { debuggable = it }
            ATTR_ALLOW_BACKUP -> attr.boolValue?.let { allowBackup = it }
            ATTR_USES_CLEARTEXT_TRAFFIC -> attr.boolValue?.let { usesCleartextTraffic = it }
            ATTR_TEST_ONLY -> attr.boolValue?.let { testOnly = it }
            ATTR_NETWORK_SECURITY_CONFIG -> hasNetworkSecurityConfig = true
            else -> applyAppAttrByName(attr)
        }
    }

    private fun applyAppAttrByName(attr: ManifestParsedAttr) {
        when (attr.name) {
            "debuggable" -> attr.boolValue?.let { debuggable = it }
            "allowBackup" -> attr.boolValue?.let { allowBackup = it }
            "usesCleartextTraffic" -> attr.boolValue?.let { usesCleartextTraffic = it }
            "testOnly" -> attr.boolValue?.let { testOnly = it }
            "networkSecurityConfig" -> hasNetworkSecurityConfig = true
        }
    }

    companion object {
        val COMPONENT_TAGS: Set<String> = setOf("activity", "activity-alias", "service", "receiver", "provider")
        const val ATTR_NAME: Int = 0x01010003
        const val ATTR_PERMISSION: Int = 0x01010006
        const val ATTR_DEBUGGABLE: Int = 0x0101000F
        const val ATTR_EXPORTED: Int = 0x01010010
        const val ATTR_TARGET_SDK: Int = 0x01010270
        const val ATTR_TEST_ONLY: Int = 0x01010272
        const val ATTR_ALLOW_BACKUP: Int = 0x01010280
        const val ATTR_USES_CLEARTEXT_TRAFFIC: Int = 0x010104EC
        const val ATTR_NETWORK_SECURITY_CONFIG: Int = 0x01010527
    }
}

/**
 * Pure-Kotlin reader for Android `AndroidManifest.xml` in compiled Binary XML (AXML, `.apk`),
 * Protobuf XML (`aapt2` `.aab`), and plain XML formats.
 */
public object BinaryXmlManifestInspector {
    private const val RES_STRING_POOL_TYPE = 0x0001
    private const val RES_XML_TYPE = 0x0003
    private const val RES_XML_RESOURCE_MAP_TYPE = 0x0180
    private const val RES_XML_START_ELEMENT_TYPE = 0x0102
    private const val RES_XML_END_ELEMENT_TYPE = 0x0103
    private const val UTF8_FLAG = 0x00000100
    private const val TYPE_STRING = 0x03
    private const val TYPE_INT_DEC = 0x10
    private const val TYPE_INT_HEX = 0x11
    private const val TYPE_INT_BOOLEAN = 0x12

    /** Parses AXML (`.apk`), Protobuf XML (`.aab`), or plain XML bytes of `AndroidManifest.xml`. */
    public fun parse(bytes: ByteArray): AndroidManifestFlags {
        val isAxml = bytes.size >= 8 &&
            (ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getShort(0).toInt() and 0xFFFF) == RES_XML_TYPE
        return when {
            isAxml -> parseBinaryXml(bytes, ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN))
            else -> {
                val text = String(bytes, Charsets.UTF_8)
                if ("<manifest" in text) parsePlainXml(text) else ProtobufManifestParser.parse(bytes)
            }
        }
    }

    /** Extracts the string pool entries from a compiled AXML resource buffer. */
    public fun extractStringsFromBinaryXml(bytes: ByteArray): List<String> {
        if (bytes.size < 8) return emptyList()
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        var offset = buf.getShort(2).toInt() and 0xFFFF
        var found: List<String>? = null
        while (offset + 8 <= bytes.size && found == null) {
            val chunkType = buf.getShort(offset).toInt() and 0xFFFF
            val chunkSize = buf.getInt(offset + 4)
            if (chunkSize < 8 || offset + chunkSize > bytes.size) {
                offset = bytes.size
            } else {
                if (chunkType == RES_STRING_POOL_TYPE) found = parseStringPool(bytes, buf, offset, chunkSize)
                offset += chunkSize
            }
        }
        return found.orEmpty()
    }

    private fun parseBinaryXml(bytes: ByteArray, buf: ByteBuffer): AndroidManifestFlags {
        var offset = buf.getShort(2).toInt() and 0xFFFF
        var strings: List<String> = emptyList()
        var resourceIds = IntArray(0)
        val acc = ManifestFlagsAccumulator()

        while (offset + 8 <= bytes.size) {
            val chunkType = buf.getShort(offset).toInt() and 0xFFFF
            val headerSize = buf.getShort(offset + 2).toInt() and 0xFFFF
            val chunkSize = buf.getInt(offset + 4)
            if (chunkSize < 8 || offset + chunkSize > bytes.size) break

            when (chunkType) {
                RES_STRING_POOL_TYPE -> strings = parseStringPool(bytes, buf, offset, chunkSize)
                RES_XML_RESOURCE_MAP_TYPE -> resourceIds = IntArray(((chunkSize - headerSize) / 4).coerceAtLeast(0)) { idx ->
                    buf.getInt(offset + headerSize + idx * 4)
                }
                RES_XML_START_ELEMENT_TYPE -> applyStartElement(buf, offset, headerSize, chunkSize, strings, resourceIds, acc)
                RES_XML_END_ELEMENT_TYPE -> {
                    val body = offset + headerSize
                    val endName = if (body + 8 <= offset + chunkSize) strings.getOrNull(buf.getInt(body + 4)) else null
                    if (endName in ManifestFlagsAccumulator.COMPONENT_TAGS) acc.finishComponent()
                }
            }
            offset += chunkSize
        }
        return acc.build()
    }

    private fun applyStartElement(
        buf: ByteBuffer,
        chunkOffset: Int,
        headerSize: Int,
        chunkSize: Int,
        strings: List<String>,
        resourceIds: IntArray,
        acc: ManifestFlagsAccumulator,
    ) {
        val body = chunkOffset + headerSize
        val chunkEnd = chunkOffset + chunkSize
        val elementName = if (body + 20 <= chunkEnd) strings.getOrNull(buf.getInt(body + 4)) else null
        if (elementName != null) {
            acc.recordElement(elementName, readElementAttributes(buf, body, chunkEnd, strings, resourceIds))
        }
    }

    private fun readElementAttributes(
        buf: ByteBuffer,
        body: Int,
        chunkEnd: Int,
        strings: List<String>,
        resourceIds: IntArray,
    ): List<ManifestParsedAttr> {
        val attrStart = buf.getShort(body + 8).toInt() and 0xFFFF
        val attrSize = buf.getShort(body + 10).toInt() and 0xFFFF
        val attrCount = buf.getShort(body + 12).toInt() and 0xFFFF
        if (attrSize < 20) return emptyList()
        val attrsBase = body + attrStart
        val safeCount = minOf(attrCount, ((chunkEnd - attrsBase) / attrSize).coerceAtLeast(0))
        return List(safeCount) { idx ->
            val off = attrsBase + idx * attrSize
            val attrNameIdx = buf.getInt(off + 4)
            val rawValueIdx = buf.getInt(off + 8)
            val dataType = buf.get(off + 15).toInt() and 0xFF
            val dataValue = buf.getInt(off + 16)
            ManifestParsedAttr(
                name = strings.getOrNull(attrNameIdx).orEmpty(),
                resourceId = if (attrNameIdx in resourceIds.indices) resourceIds[attrNameIdx] else 0,
                stringValue = if (rawValueIdx >= 0) {
                    strings.getOrNull(rawValueIdx)
                } else if (dataType == TYPE_STRING) {
                    strings.getOrNull(dataValue)
                } else {
                    null
                },
                boolValue = decodeAxmlBoolean(dataType, dataValue, rawValueIdx, strings),
                intValue = decodeAxmlInt(dataType, dataValue, rawValueIdx, strings),
            )
        }
    }

    private fun parseStringPool(bytes: ByteArray, buf: ByteBuffer, chunkOffset: Int, chunkSize: Int): List<String> {
        val stringCount = buf.getInt(chunkOffset + 8).coerceAtLeast(0)
        val isUtf8 = (buf.getInt(chunkOffset + 16) and UTF8_FLAG) != 0
        val stringsStart = chunkOffset + buf.getInt(chunkOffset + 20)
        val offsetsStart = chunkOffset + (buf.getShort(chunkOffset + 2).toInt() and 0xFFFF)
        val chunkEnd = chunkOffset + chunkSize
        val maxEntries = minOf(stringCount, ((chunkEnd - offsetsStart) / 4).coerceAtLeast(0))
        return List(maxEntries) { idx ->
            val strOffset = stringsStart + buf.getInt(offsetsStart + idx * 4)
            when {
                strOffset !in 0 until chunkEnd -> ""
                isUtf8 -> readPoolUtf8(bytes, strOffset, chunkEnd)
                else -> readPoolUtf16(bytes, buf, strOffset, chunkEnd)
            }
        }
    }

    private fun readPoolUtf8(bytes: ByteArray, start: Int, limit: Int): String {
        val charLen = if (start < limit) bytes[start].toInt() and 0xFF else return ""
        var pos = start + if ((charLen and 0x80) != 0) 2 else 1
        return if (pos >= limit) {
            ""
        } else {
            val b1 = bytes[pos].toInt() and 0xFF
            val byteLen = if ((b1 and 0x80) != 0 && pos + 1 < limit) {
                val b2 = bytes[pos + 1].toInt() and 0xFF
                pos += 2
                ((b1 and 0x7F) shl 8) or b2
            } else {
                pos += 1
                b1
            }
            String(bytes, pos, byteLen.coerceIn(0, (limit - pos).coerceAtLeast(0)), Charsets.UTF_8)
        }
    }

    private fun readPoolUtf16(bytes: ByteArray, buf: ByteBuffer, start: Int, limit: Int): String {
        if (start + 2 > limit) return ""
        var pos = start
        val first = buf.getShort(pos).toInt() and 0xFFFF
        val charLen = if ((first and 0x8000) != 0 && pos + 4 <= limit) {
            val second = buf.getShort(pos + 2).toInt() and 0xFFFF
            pos += 4
            ((first and 0x7FFF) shl 16) or second
        } else {
            pos += 2
            first
        }
        return String(bytes, pos, (charLen * 2).coerceIn(0, (limit - pos).coerceAtLeast(0)), Charsets.UTF_16LE)
    }

    private fun decodeAxmlBoolean(dataType: Int, dataValue: Int, rawValueIdx: Int, strings: List<String>): Boolean? = when (dataType) {
        TYPE_INT_BOOLEAN, TYPE_INT_DEC, TYPE_INT_HEX -> dataValue != 0
        TYPE_STRING -> strings.getOrNull(dataValue)?.toBooleanStrictOrNull()
        else -> if (rawValueIdx >= 0) strings.getOrNull(rawValueIdx)?.toBooleanStrictOrNull() else null
    }

    private fun decodeAxmlInt(dataType: Int, dataValue: Int, rawValueIdx: Int, strings: List<String>): Int? = when (dataType) {
        TYPE_INT_DEC, TYPE_INT_HEX -> dataValue
        TYPE_STRING -> strings.getOrNull(dataValue)?.toIntOrNull()
        else -> if (rawValueIdx >= 0) strings.getOrNull(rawValueIdx)?.toIntOrNull() else null
    }
}

private fun parsePlainXml(xml: String): AndroidManifestFlags {
    val pkg = Regex("""<manifest\b[^>]*\bpackage\s*=\s*"([^"]+)"""").find(xml)?.groupValues?.get(1)
    val targetSdk = Regex("""<uses-sdk\b[^>]*\b(?:android:)?targetSdkVersion\s*=\s*"(\d+)"""").find(xml)?.groupValues?.get(1)?.toIntOrNull()
    val appTag = Regex("""<application\b[^>]*>""", RegexOption.DOT_MATCHES_ALL).find(xml)?.value.orEmpty()
    fun boolAttr(attr: String): Boolean? =
        Regex("""\b(?:android:)?$attr\s*=\s*"(true|false)"""", RegexOption.IGNORE_CASE)
            .find(appTag)?.groupValues?.get(1)?.lowercase(Locale.ROOT)?.toBooleanStrictOrNull()

    return AndroidManifestFlags(
        packageName = pkg,
        debuggable = boolAttr("debuggable") ?: false,
        allowBackup = boolAttr("allowBackup"),
        usesCleartextTraffic = boolAttr("usesCleartextTraffic"),
        testOnly = boolAttr("testOnly") ?: false,
        targetSdkVersion = targetSdk,
        hasNetworkSecurityConfig = Regex("""\b(?:android:)?networkSecurityConfig\s*=""").containsMatchIn(appTag),
        exportedComponents = parsePlainExportedComponents(xml),
    )
}

private fun parsePlainExportedComponents(xml: String): List<ExportedComponentInfo> {
    val regex = Regex("""<(activity|activity-alias|service|receiver|provider)\b([^>]*)(?:/>|>([\s\S]*?)</\1>)""", RegexOption.IGNORE_CASE)
    return regex.findAll(xml).mapNotNull { match ->
        val attrs = match.groupValues[2]
        val exported = Regex("""\b(?:android:)?exported\s*=\s*"true"""", RegexOption.IGNORE_CASE).containsMatchIn(attrs)
        if (!exported) {
            null
        } else {
            val body = match.groupValues[3]
            val name = Regex("""\b(?:android:)?name\s*=\s*"([^"]+)"""").find(attrs)?.groupValues?.get(1) ?: "<unnamed>"
            val hasPerm = Regex("""\b(?:android:)?(?:permission|readPermission|writePermission)\s*=\s*"[^"]+"""").containsMatchIn(attrs)
            val isLauncher = body.contains("android.intent.action.MAIN") && body.contains("android.intent.category.LAUNCHER")
            ExportedComponentInfo(match.groupValues[1].lowercase(Locale.ROOT), name, hasPerm, isLauncher)
        }
    }.toList()
}

/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.analyzers

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Summary of classes, declared members, Kotlin metadata exposure, and strings parsed from a `.dex` file. */
public data class DexSummary(
    public val definedClasses: List<String>,
    public val declaredMembersByClass: Map<String, List<String>>,
    public val strings: List<String>,
    public val hasKotlinMetadataDescriptor: Boolean = false,
)

/**
 * Pure-Kotlin Dalvik Executable (`.dex`) reader.
 *
 * Parses the DEX string table, type table, `class_defs`, `field_ids`, and `method_ids` so release
 * APK and AAB obfuscation coverage can be audited without external tools such as `dexdump` or `apktool`.
 */
public object DexInspector {
    private const val KOTLIN_METADATA_DESCRIPTOR = "Lkotlin/Metadata;"
    private val specialMembers = setOf("<init>", "<clinit>")
    private val frameworkPackagePrefixes = listOf(
        "android/",
        "androidx/",
        "java/",
        "javax/",
        "kotlin/",
        "kotlinx/",
        "dalvik/",
        "com/google/",
        "org/intellij/",
        "org/jetbrains/",
    )

    /** Returns `true` when [internalClassName] belongs to a standard Android/Kotlin/Jetpack framework package. */
    public fun isFrameworkClass(internalClassName: String): Boolean =
        frameworkPackagePrefixes.any { internalClassName.startsWith(it) }

    /** Parses a DEX binary buffer [data]. */
    public fun parse(data: ByteArray): DexSummary {
        require(data.size >= 112) { "DEX binary is truncated (${data.size} bytes)." }
        require(data[0] == 'd'.code.toByte() && data[1] == 'e'.code.toByte() && data[2] == 'x'.code.toByte() && data[3] == '\n'.code.toByte()) {
            "Invalid DEX magic header."
        }
        val buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
        val stringIdsSize = buf.getInt(56)
        val stringIdsOff = buf.getInt(60)
        val typeIdsSize = buf.getInt(64)
        val typeIdsOff = buf.getInt(68)
        val fieldIdsSize = buf.getInt(80)
        val fieldIdsOff = buf.getInt(84)
        val methodIdsSize = buf.getInt(88)
        val methodIdsOff = buf.getInt(92)
        val classDefsSize = buf.getInt(96)
        val classDefsOff = buf.getInt(100)

        val strings = readStrings(data, buf, stringIdsSize, stringIdsOff)
        val typeDescriptors = readTypeDescriptors(buf, typeIdsSize, typeIdsOff, strings)
        val definedTypeIndices = readDefinedClassIndices(buf, classDefsSize, classDefsOff)

        val definedClasses = mutableListOf<String>()
        val membersByClass = LinkedHashMap<String, MutableList<String>>()
        for (typeIdx in definedTypeIndices) {
            val internal = typeDescriptors.getOrNull(typeIdx)?.let(::descriptorToInternalName)
            if (internal != null) {
                definedClasses += internal
                membersByClass.putIfAbsent(internal, mutableListOf())
            }
        }

        collectDeclaredMembers(buf, fieldIdsSize, fieldIdsOff, definedTypeIndices, typeDescriptors, strings, membersByClass)
        collectDeclaredMembers(buf, methodIdsSize, methodIdsOff, definedTypeIndices, typeDescriptors, strings, membersByClass)

        val hasMetadata = typeDescriptors.any { it == KOTLIN_METADATA_DESCRIPTOR } ||
            strings.any { it == KOTLIN_METADATA_DESCRIPTOR }

        return DexSummary(
            definedClasses = definedClasses,
            declaredMembersByClass = membersByClass,
            strings = strings,
            hasKotlinMetadataDescriptor = hasMetadata,
        )
    }

    private fun readStrings(data: ByteArray, buf: ByteBuffer, count: Int, tableOffset: Int): List<String> {
        if (count <= 0 || tableOffset <= 0) return emptyList()
        val maxEntries = minOf(count, ((data.size - tableOffset) / 4).coerceAtLeast(0))
        val result = ArrayList<String>(maxEntries)
        for (i in 0 until maxEntries) {
            val dataOffset = buf.getInt(tableOffset + i * 4)
            result += readMutf8String(data, dataOffset)
        }
        return result
    }

    private fun readMutf8String(data: ByteArray, start: Int): String {
        if (start < 0 || start >= data.size) return ""
        var offset = start
        while (offset < data.size) {
            val byte = data[offset].toInt() and 0xFF
            offset += 1
            if ((byte and 0x80) == 0) break
        }
        val strStart = offset
        while (offset < data.size && data[offset].toInt() != 0) {
            offset += 1
        }
        return String(data, strStart, (offset - strStart).coerceAtLeast(0), Charsets.UTF_8)
    }

    private fun readTypeDescriptors(buf: ByteBuffer, count: Int, tableOffset: Int, strings: List<String>): List<String> {
        if (count <= 0 || tableOffset <= 0) return emptyList()
        val maxEntries = minOf(count, ((buf.limit() - tableOffset) / 4).coerceAtLeast(0))
        return List(maxEntries) { i ->
            strings.getOrElse(buf.getInt(tableOffset + i * 4)) { "" }
        }
    }

    private fun readDefinedClassIndices(buf: ByteBuffer, count: Int, tableOffset: Int): Set<Int> {
        if (count <= 0 || tableOffset <= 0) return emptySet()
        val maxEntries = minOf(count, ((buf.limit() - tableOffset) / 32).coerceAtLeast(0))
        val result = LinkedHashSet<Int>(maxEntries)
        for (i in 0 until maxEntries) {
            result += buf.getInt(tableOffset + i * 32)
        }
        return result
    }

    private fun collectDeclaredMembers(
        buf: ByteBuffer,
        count: Int,
        tableOffset: Int,
        definedTypeIndices: Set<Int>,
        typeDescriptors: List<String>,
        strings: List<String>,
        membersByClass: MutableMap<String, MutableList<String>>,
    ) {
        if (count <= 0 || tableOffset <= 0) return
        val safeCount = minOf(count, ((buf.limit() - tableOffset) / 8).coerceAtLeast(0))
        for (i in 0 until safeCount) {
            val entryPos = tableOffset + i * 8
            val classIdx = buf.getShort(entryPos).toInt() and 0xFFFF
            if (classIdx in definedTypeIndices) {
                val memberName = strings.getOrNull(buf.getInt(entryPos + 4))
                val internal = descriptorToInternalName(typeDescriptors.getOrNull(classIdx).orEmpty())
                if (memberName != null && memberName !in specialMembers && internal != null) {
                    membersByClass[internal]?.add(memberName)
                }
            }
        }
    }

    private fun descriptorToInternalName(descriptor: String): String? {
        if (descriptor.length < 3 || !descriptor.startsWith("L") || !descriptor.endsWith(";")) return null
        return descriptor.substring(1, descriptor.length - 1)
    }
}

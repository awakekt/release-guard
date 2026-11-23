/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.analyzers

import com.awakekt.releaseguard.io.BinaryReadLimits
import com.awakekt.releaseguard.io.ZipReadBudget
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipFile

/** Declared class metadata and debug-attribute exposure parsed directly from a JVM `.class` binary. */
public data class ClassFileInfo(
    public val internalName: String,
    public val members: List<String>,
    public val sourceFile: String?,
    public val hasKotlinMetadata: Boolean = false,
    public val hasLocalVariableTable: Boolean = false,
    public val hasMethodParameters: Boolean = false,
)

/**
 * Pure-Kotlin JVM `.class` file constant-pool and attribute reader.
 *
 * Extracts class internal names, field/method names, `SourceFile`, `LocalVariableTable`,
 * `LocalVariableTypeTable`, `MethodParameters`, and `@kotlin.Metadata` runtime annotations without
 * relying on external ASM or Python tooling.
 */
public object ClassFileReader {
    private const val CLASS_MAGIC = 0xCAFEBABE.toInt()
    private const val KOTLIN_METADATA_DESCRIPTOR = "Lkotlin/Metadata;"
    private val specialMembers = setOf("<init>", "<clinit>")
    private val localVarAttrNames = setOf("LocalVariableTable", "LocalVariableTypeTable")

    private val poolEntrySizes = mapOf(
        3 to 4, // Integer
        4 to 4, // Float
        7 to 2, // Class
        8 to 2, // String
        9 to 4, // Fieldref
        10 to 4, // Methodref
        11 to 4, // InterfaceMethodref
        12 to 4, // NameAndType
        15 to 3, // MethodHandle
        16 to 2, // MethodType
        17 to 4, // Dynamic
        18 to 4, // InvokeDynamic
        19 to 2, // Module
        20 to 2, // Package
    )

    private class DebugAttributeFlags {
        var sourceFile: String? = null
        var hasKotlinMetadata: Boolean = false
        var hasLocalVariableTable: Boolean = false
        var hasMethodParameters: Boolean = false
    }

    /** Reads every non-module `.class` entry inside [jarFile] within [limits]. */
    public fun readJar(
        jarFile: File,
        limits: BinaryReadLimits = BinaryReadLimits(),
    ): List<ClassFileInfo> {
        val classes = mutableListOf<ClassFileInfo>()
        val budget = ZipReadBudget(limits)
        ZipFile(jarFile).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                budget.recordEntry(entry.name)
                if (!entry.isDirectory && entry.name.endsWith(".class") && !entry.name.endsWith("module-info.class")) {
                    val bytes = budget.readEntryBytes(zip, entry)
                    classes += readClass(bytes)
                }
            }
        }
        return classes
    }

    /** Parses a single JVM class binary [data]. */
    public fun readClass(data: ByteArray): ClassFileInfo {
        require(data.size >= 24) { "Class file is truncated (${data.size} bytes)." }
        val buffer = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
        val magic = buffer.getInt(0)
        require(magic == CLASS_MAGIC) { "Invalid JVM class magic: 0x${magic.toUInt().toString(16)}" }

        val constantPoolCount = buffer.getShort(8).toInt() and 0xFFFF
        val utf8 = HashMap<Int, String>()
        val classNameIndices = HashMap<Int, Int>()
        var offset = parseConstantPool(data, buffer, constantPoolCount, utf8, classNameIndices)

        val thisClass = buffer.getShort(offset + 2).toInt() and 0xFFFF
        val interfacesCount = buffer.getShort(offset + 6).toInt() and 0xFFFF
        offset += 8 + 2 * interfacesCount

        val members = mutableListOf<String>()
        val flags = DebugAttributeFlags()
        offset = parseMembers(buffer, offset, utf8, members, flags)
        readClassAttributes(buffer, offset, utf8, flags)

        val internalName = utf8[classNameIndices[thisClass]] ?: ""
        return ClassFileInfo(
            internalName = internalName,
            members = members,
            sourceFile = flags.sourceFile,
            hasKotlinMetadata = flags.hasKotlinMetadata,
            hasLocalVariableTable = flags.hasLocalVariableTable,
            hasMethodParameters = flags.hasMethodParameters,
        )
    }

    private fun parseConstantPool(
        data: ByteArray,
        buffer: ByteBuffer,
        constantPoolCount: Int,
        utf8: MutableMap<Int, String>,
        classNameIndices: MutableMap<Int, Int>,
    ): Int {
        var offset = 10
        var index = 1
        while (index < constantPoolCount) {
            val tag = data[offset].toInt() and 0xFF
            when (tag) {
                1 -> {
                    val length = buffer.getShort(offset + 1).toInt() and 0xFFFF
                    utf8[index] = String(data, offset + 3, length, Charsets.UTF_8)
                    offset += 3 + length
                }
                5, 6 -> {
                    offset += 9
                    index += 1
                }
                else -> {
                    val size = requireNotNull(poolEntrySizes[tag]) { "Unsupported JVM constant pool tag: $tag" }
                    if (tag == 7) {
                        classNameIndices[index] = buffer.getShort(offset + 1).toInt() and 0xFFFF
                    }
                    offset += 1 + size
                }
            }
            index += 1
        }
        return offset
    }

    private fun parseMembers(
        buffer: ByteBuffer,
        startOffset: Int,
        utf8: Map<Int, String>,
        members: MutableList<String>,
        flags: DebugAttributeFlags,
    ): Int {
        var offset = startOffset
        repeat(2) {
            val memberCount = buffer.getShort(offset).toInt() and 0xFFFF
            offset += 2
            repeat(memberCount) {
                val nameIndex = buffer.getShort(offset + 2).toInt() and 0xFFFF
                val attrCount = buffer.getShort(offset + 6).toInt() and 0xFFFF
                offset += 8
                repeat(attrCount) {
                    val attrName = utf8[buffer.getShort(offset).toInt() and 0xFFFF]
                    val attrLength = buffer.getInt(offset + 2)
                    val attrBody = offset + 6
                    inspectMemberAttribute(buffer, attrName, attrBody, attrLength, utf8, flags)
                    offset = attrBody + attrLength
                }
                val memberName = utf8[nameIndex]
                if (memberName != null && memberName !in specialMembers) {
                    members += memberName
                }
            }
        }
        return offset
    }

    private fun inspectMemberAttribute(
        buffer: ByteBuffer,
        attrName: String?,
        bodyOffset: Int,
        attrLength: Int,
        utf8: Map<Int, String>,
        flags: DebugAttributeFlags,
    ) {
        when (attrName) {
            "MethodParameters" -> flags.hasMethodParameters = true
            "Code" -> inspectCodeAttributes(buffer, bodyOffset, attrLength, utf8, flags)
        }
    }

    private fun inspectCodeAttributes(
        buffer: ByteBuffer,
        bodyOffset: Int,
        attrLength: Int,
        utf8: Map<Int, String>,
        flags: DebugAttributeFlags,
    ) {
        val codeEnd = bodyOffset + attrLength
        if (bodyOffset + 8 > codeEnd || codeEnd > buffer.limit()) return
        val codeLen = buffer.getInt(bodyOffset + 4)
        var pos = bodyOffset + 8 + codeLen
        if (pos + 2 <= codeEnd) {
            val exceptionCount = buffer.getShort(pos).toInt() and 0xFFFF
            pos += 2 + exceptionCount * 8
        }
        val subAttrCount = if (pos + 2 <= codeEnd) buffer.getShort(pos).toInt() and 0xFFFF else 0
        pos += 2
        var idx = 0
        while (idx < subAttrCount && pos + 6 <= codeEnd) {
            val subName = utf8[buffer.getShort(pos).toInt() and 0xFFFF]
            val subLen = buffer.getInt(pos + 2)
            if (subName in localVarAttrNames) {
                flags.hasLocalVariableTable = true
            }
            pos += 6 + subLen
            idx += 1
        }
    }

    private fun readClassAttributes(
        buffer: ByteBuffer,
        startOffset: Int,
        utf8: Map<Int, String>,
        flags: DebugAttributeFlags,
    ) {
        if (startOffset + 2 > buffer.limit()) return
        var offset = startOffset
        val attrCount = buffer.getShort(offset).toInt() and 0xFFFF
        offset += 2
        var idx = 0
        while (idx < attrCount && offset + 6 <= buffer.limit()) {
            val name = utf8[buffer.getShort(offset).toInt() and 0xFFFF]
            val length = buffer.getInt(offset + 2)
            val body = offset + 6
            if (body + length > buffer.limit()) break
            when (name) {
                "SourceFile" -> if (length == 2) {
                    flags.sourceFile = utf8[buffer.getShort(body).toInt() and 0xFFFF]
                }
                "RuntimeVisibleAnnotations", "RuntimeInvisibleAnnotations" -> {
                    if (containsKotlinMetadataAnnotation(buffer, body, body + length, utf8)) {
                        flags.hasKotlinMetadata = true
                    }
                }
            }
            offset = body + length
            idx += 1
        }
    }

    private fun containsKotlinMetadataAnnotation(
        buffer: ByteBuffer,
        start: Int,
        end: Int,
        utf8: Map<Int, String>,
    ): Boolean {
        if (start + 2 > end) return false
        val count = buffer.getShort(start).toInt() and 0xFFFF
        var pos = start + 2
        var found = false
        var idx = 0
        while (idx < count && !found && pos + 4 <= end) {
            val typeName = utf8[buffer.getShort(pos).toInt() and 0xFFFF]
            if (typeName == KOTLIN_METADATA_DESCRIPTOR) {
                found = true
            } else {
                // Fast check across remaining UTF-8 indices if nested annotations are complex.
                pos = end
            }
            idx += 1
        }
        return found || utf8.values.any { it == KOTLIN_METADATA_DESCRIPTOR }
    }
}

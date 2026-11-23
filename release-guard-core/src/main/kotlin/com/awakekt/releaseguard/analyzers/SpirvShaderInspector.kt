/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.analyzers

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Summary of a parsed SPIR-V binary shader module. */
public data class SpirvInspection(
    public val path: String,
    public val isValidSpirv: Boolean,
    public val versionMajor: Int = 0,
    public val versionMinor: Int = 0,
    public val debugOpcodeNames: Set<String> = emptySet(),
    public val debugInstructionCount: Int = 0,
    public val leakedDebugStrings: List<String> = emptyList(),
)

/**
 * Pure-Kotlin Khronos SPIR-V (`0x07230203`) binary inspector and lossless debug-instruction
 * stripper. Detects and strips non-functional debug opcodes (`OpSource`, `OpName`, `OpMemberName`,
 * `OpLine`, `OpString`, `OpModuleProcessed`) without requiring `spirv-opt`.
 */
public object SpirvShaderInspector {
    private const val SPIRV_MAGIC = 0x07230203
    private const val SPIRV_MAGIC_SWAPPED = 0x03022307
    private const val HEADER_WORDS = 5
    private const val MAX_CAPTURED_STRINGS = 10

    private val debugOpcodes: Map<Int, String> = mapOf(
        2 to "OpSourceContinued",
        3 to "OpSource",
        4 to "OpSourceExtension",
        5 to "OpName",
        6 to "OpMemberName",
        7 to "OpString",
        8 to "OpLine",
        317 to "OpNoLine",
        330 to "OpModuleProcessed",
    )

    private val stringPayloadOffsets: Map<Int, Int> = mapOf(
        2 to 1,
        3 to 4,
        4 to 1,
        5 to 2,
        6 to 3,
        7 to 2,
        330 to 1,
    )

    /** Returns `true` when [bytes] starts with the 4-byte Khronos SPIR-V magic number. */
    public fun isSpirv(bytes: ByteArray): Boolean = detectOrder(bytes) != null

    /** Inspects a SPIR-V shader binary for surviving debug instructions and embedded names/paths. */
    public fun inspect(path: String, bytes: ByteArray): SpirvInspection {
        val order = detectOrder(bytes)
        val validLayout = order != null && bytes.size >= HEADER_WORDS * 4 && bytes.size % 4 == 0
        if (!validLayout) return SpirvInspection(path = path, isValidSpirv = false)

        val buf = ByteBuffer.wrap(bytes).order(order)
        val versionWord = buf.getInt(4)
        val major = (versionWord ushr 16) and 0xFF
        val minor = (versionWord ushr 8) and 0xFF

        val foundOpcodes = linkedSetOf<String>()
        val leakedStrings = mutableListOf<String>()
        var debugCount = 0
        var wordOffset = HEADER_WORDS
        val totalWords = bytes.size / 4

        while (wordOffset < totalWords) {
            val header = buf.getInt(wordOffset * 4)
            val wordCount = header ushr 16
            val opcode = header and 0xFFFF
            if (wordCount <= 0 || wordOffset + wordCount > totalWords) break
            val debugName = debugOpcodes[opcode]
            if (debugName != null) {
                foundOpcodes += debugName
                debugCount++
                captureDebugString(bytes, wordOffset, wordCount, opcode, leakedStrings)
            }
            wordOffset += wordCount
        }

        return SpirvInspection(
            path = path,
            isValidSpirv = true,
            versionMajor = major,
            versionMinor = minor,
            debugOpcodeNames = foundOpcodes,
            debugInstructionCount = debugCount,
            leakedDebugStrings = leakedStrings,
        )
    }

    /**
     * Losslessly removes SPIR-V debug instructions (`OpSource*`, `OpName`, `OpMemberName`,
     * `OpString`, `OpLine`, `OpNoLine`, `OpModuleProcessed`) while keeping the header and all
     * executable instructions byte-for-byte intact.
     */
    public fun stripDebugOpcodes(bytes: ByteArray): ByteArray {
        val order = detectOrder(bytes)
        val validLayout = order != null && bytes.size >= HEADER_WORDS * 4 && bytes.size % 4 == 0
        if (!validLayout) return bytes

        val buf = ByteBuffer.wrap(bytes).order(order)
        val out = ByteArrayOutputStream(bytes.size)
        out.write(bytes, 0, HEADER_WORDS * 4)

        var wordOffset = HEADER_WORDS
        val totalWords = bytes.size / 4
        var malformed = false
        while (wordOffset < totalWords) {
            val header = buf.getInt(wordOffset * 4)
            val wordCount = header ushr 16
            val opcode = header and 0xFFFF
            if (wordCount <= 0 || wordOffset + wordCount > totalWords) {
                malformed = true
                break
            }
            if (opcode !in debugOpcodes) {
                out.write(bytes, wordOffset * 4, wordCount * 4)
            }
            wordOffset += wordCount
        }
        return if (malformed) bytes else out.toByteArray()
    }

    private fun detectOrder(bytes: ByteArray): ByteOrder? {
        if (bytes.size < 4) return null
        val le = ByteBuffer.wrap(bytes, 0, 4).order(ByteOrder.LITTLE_ENDIAN).int
        return when (le) {
            SPIRV_MAGIC -> ByteOrder.LITTLE_ENDIAN
            SPIRV_MAGIC_SWAPPED -> ByteOrder.BIG_ENDIAN
            else -> null
        }
    }

    private fun captureDebugString(
        bytes: ByteArray,
        wordOffset: Int,
        wordCount: Int,
        opcode: Int,
        out: MutableList<String>,
    ) {
        val strWordOffset = stringPayloadOffsets[opcode]
        if (out.size >= MAX_CAPTURED_STRINGS || strWordOffset == null || strWordOffset >= wordCount) return
        val startByte = (wordOffset + strWordOffset) * 4
        val endByte = (wordOffset + wordCount) * 4
        var nullPos = startByte
        while (nullPos < endByte && bytes[nullPos] != 0.toByte()) {
            nullPos++
        }
        if (nullPos > startByte) {
            val text = String(bytes, startByte, nullPos - startByte, Charsets.UTF_8).trim()
            if (text.isNotEmpty() && text !in out) {
                out += text.take(120)
            }
        }
    }
}

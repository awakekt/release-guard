/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.analyzers

import java.io.ByteArrayOutputStream

/** One top-level section in a WebAssembly binary module. */
public data class WasmSection(
    public val id: Int,
    public val name: String,
    public val isCustom: Boolean,
    public val sizeBytes: Int,
)

/** Result of stripping debug/name/producer custom sections from a WebAssembly binary. */
public data class WasmStripResult(
    public val strippedBytes: ByteArray,
    public val removedSections: List<WasmSection>,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is WasmStripResult) return false
        return strippedBytes.contentEquals(other.strippedBytes) && removedSections == other.removedSections
    }

    override fun hashCode(): Int = 31 * strippedBytes.contentHashCode() + removedSections.hashCode()
}

/**
 * Pure-Kotlin WebAssembly binary section reader, export table reader, and lossless custom-section stripper.
 */
public object WasmBinaryInspector {
    private val wasmMagic = byteArrayOf(0x00, 0x61, 0x73, 0x6D) // \0asm
    private const val EXPORT_SECTION_ID = 7

    private val standardSectionNames = mapOf(
        1 to "type",
        2 to "import",
        3 to "function",
        4 to "table",
        5 to "memory",
        6 to "global",
        7 to "export",
        8 to "start",
        9 to "element",
        10 to "code",
        11 to "data",
        12 to "datacount",
        13 to "tag",
        14 to "strings",
    )

    /** Custom section names treated as debug or metadata leaks in production WASM bundles. */
    public val DEBUG_CUSTOM_SECTIONS: Set<String> = setOf(
        "name",
        "producers",
        "sourceMappingURL",
        "external_debug_info",
        "binaryen.js.called",
    )

    /** Returns `true` when [section] is a debug, name, or producer custom section. */
    public fun isDebugSection(section: WasmSection): Boolean =
        section.isCustom && (section.name in DEBUG_CUSTOM_SECTIONS || section.name.startsWith(".debug"))

    /** Reads every top-level section header from WebAssembly module [data]. */
    public fun readSections(data: ByteArray): List<WasmSection> {
        validateHeader(data)
        val sections = mutableListOf<WasmSection>()
        var offset = 8
        while (offset < data.size) {
            val sectionStart = offset
            val sectionId = data[offset].toInt() and 0xFF
            val (payloadSize, payloadStart) = readUleb128(data, offset + 1)
            val sectionEnd = payloadStart + payloadSize
            require(sectionEnd <= data.size) {
                "WASM section $sectionId at $sectionStart extends past end of module ($sectionEnd > ${data.size})."
            }
            val (name, isCustom) = if (sectionId == 0) {
                val (nameLen, nameStart) = readUleb128(data, payloadStart)
                require(nameStart + nameLen <= sectionEnd) { "WASM custom section name overflows section bounds." }
                String(data, nameStart, nameLen, Charsets.UTF_8) to true
            } else {
                (standardSectionNames[sectionId] ?: "id_$sectionId") to false
            }
            sections += WasmSection(
                id = sectionId,
                name = name,
                isCustom = isCustom,
                sizeBytes = sectionEnd - sectionStart,
            )
            offset = sectionEnd
        }
        return sections
    }

    /** Reads exported symbol names from the WASM export section (section id `7`). */
    public fun readExports(data: ByteArray): List<String> {
        validateHeader(data)
        val exports = mutableListOf<String>()
        var offset = 8
        while (offset < data.size) {
            val sectionId = data[offset].toInt() and 0xFF
            val (payloadSize, payloadStart) = readUleb128(data, offset + 1)
            val sectionEnd = payloadStart + payloadSize
            if (sectionEnd > data.size) break
            if (sectionId == EXPORT_SECTION_ID) {
                parseExportSection(data, payloadStart, sectionEnd, exports)
            }
            offset = sectionEnd
        }
        return exports
    }

    /** Strips debug, name, and producer custom sections from WebAssembly module [data]. */
    public fun stripDebugSections(data: ByteArray): WasmStripResult {
        validateHeader(data)
        val out = ByteArrayOutputStream(data.size)
        out.write(data, 0, 8)
        val removed = mutableListOf<WasmSection>()
        var offset = 8
        while (offset < data.size) {
            val sectionStart = offset
            val sectionId = data[offset].toInt() and 0xFF
            val (payloadSize, payloadStart) = readUleb128(data, offset + 1)
            val sectionEnd = payloadStart + payloadSize
            require(sectionEnd <= data.size) {
                "WASM section $sectionId at $sectionStart extends past end of module ($sectionEnd > ${data.size})."
            }
            if (sectionId == 0) {
                val (nameLen, nameStart) = readUleb128(data, payloadStart)
                val name = String(data, nameStart, nameLen, Charsets.UTF_8)
                val section = WasmSection(0, name, true, sectionEnd - sectionStart)
                if (isDebugSection(section)) {
                    removed += section
                    offset = sectionEnd
                    continue
                }
            }
            out.write(data, sectionStart, sectionEnd - sectionStart)
            offset = sectionEnd
        }
        return WasmStripResult(strippedBytes = out.toByteArray(), removedSections = removed)
    }

    private fun parseExportSection(data: ByteArray, start: Int, end: Int, out: MutableList<String>) {
        if (start >= end) return
        val (count, firstPos) = readUleb128(data, start)
        var pos = firstPos
        var idx = 0
        while (idx < count && pos < end) {
            val (nameLen, nameStart) = readUleb128(data, pos)
            val nameEnd = nameStart + nameLen
            if (nameEnd + 1 > end) break
            out += String(data, nameStart, nameLen, Charsets.UTF_8)
            // Skip export kind (1 byte) + exported index (ULEB128).
            val (_, nextPos) = readUleb128(data, nameEnd + 1)
            pos = nextPos
            idx += 1
        }
    }

    private fun validateHeader(data: ByteArray) {
        require(data.size >= 8) { "WASM module is truncated (${data.size} bytes)." }
        for (i in wasmMagic.indices) {
            require(data[i] == wasmMagic[i]) { "Input is not a WebAssembly binary module (missing \\0asm magic)." }
        }
    }

    private fun readUleb128(data: ByteArray, start: Int): Pair<Int, Int> {
        var offset = start
        var result = 0
        var shift = 0
        while (true) {
            require(offset < data.size) { "Unexpected EOF while reading ULEB128 at $start." }
            val byte = data[offset].toInt() and 0xFF
            offset += 1
            result = result or ((byte and 0x7F) shl shift)
            if ((byte and 0x80) == 0) return result to offset
            shift += 7
            require(shift <= 35) { "ULEB128 integer overflow at $start." }
        }
    }
}

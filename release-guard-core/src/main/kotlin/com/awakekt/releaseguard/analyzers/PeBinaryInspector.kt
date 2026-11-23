/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.analyzers

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Security hardening and debug-path metadata parsed from a Windows PE32/PE32+ `.dll` or `.exe`. */
public data class PeInspectionResult(
    public val is64Bit: Boolean,
    public val hasAslr: Boolean,
    public val hasDepNx: Boolean,
    public val hasControlFlowGuard: Boolean,
    public val leakedPdbPaths: List<String>,
)

/**
 * Pure-Kotlin Windows Portable Executable (PE32/PE32+) inspector for Desktop JVM native `.dll`/`.exe`
 * libraries, checking ASLR (`DYNAMIC_BASE`), DEP (`NX_COMPAT`), CFG (`GUARD_CF`), and leaked `.pdb`
 * workstation paths inside CodeView records.
 */
public object PeBinaryInspector {
    private const val PE_SIGNATURE = 0x00004550 // "PE\0\0"
    private const val PE32_MAGIC = 0x010B
    private const val PE32_PLUS_MAGIC = 0x020B
    private const val DLL_CHAR_DYNAMIC_BASE = 0x0040
    private const val DLL_CHAR_NX_COMPAT = 0x0100
    private const val DLL_CHAR_GUARD_CF = 0x4000

    private val pdbPathRegex = Regex("""(?:[A-Za-z]:\\|/(?:Users|home)/)[^\r\n"'<>]{3,}\.pdb\b""", RegexOption.IGNORE_CASE)

    /** Returns `true` when [bytes] begins with the DOS `MZ` magic and points to a valid `PE\0\0` header. */
    public fun isPe(bytes: ByteArray): Boolean {
        if (bytes.size < 64 || bytes[0] != 'M'.code.toByte() || bytes[1] != 'Z'.code.toByte()) return false
        val peOffset = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getInt(60)
        return peOffset >= 0 && peOffset + 24 <= bytes.size &&
            ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getInt(peOffset) == PE_SIGNATURE
    }

    /** Parses a PE32 or PE32+ binary buffer [bytes]. */
    public fun parse(bytes: ByteArray): PeInspectionResult {
        require(isPe(bytes)) { "Input is not a valid PE32/PE32+ executable or DLL." }
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val peOffset = buf.getInt(60)
        val optHeaderStart = peOffset + 24
        val optHeaderSize = buf.getShort(peOffset + 20).toInt() and 0xFFFF
        require(optHeaderSize >= 72 && optHeaderStart + 72 <= bytes.size) {
            "PE optional header is truncated ($optHeaderSize bytes)."
        }
        val optMagic = buf.getShort(optHeaderStart).toInt() and 0xFFFF
        val is64Bit = when (optMagic) {
            PE32_PLUS_MAGIC -> true
            PE32_MAGIC -> false
            else -> throw IllegalArgumentException("Unsupported PE optional header magic: 0x${optMagic.toString(16)}")
        }
        // DllCharacteristics sits at offset +70 inside both PE32 and PE32+ optional headers.
        val dllChars = buf.getShort(optHeaderStart + 70).toInt() and 0xFFFF
        val strings = IdentifierHeuristics.extractPrintableStrings(bytes)
        val pdbPaths = strings.flatMap { text -> pdbPathRegex.findAll(text).map { it.value }.toList() }
            .distinct()
            .sorted()

        return PeInspectionResult(
            is64Bit = is64Bit,
            hasAslr = (dllChars and DLL_CHAR_DYNAMIC_BASE) != 0,
            hasDepNx = (dllChars and DLL_CHAR_NX_COMPAT) != 0,
            hasControlFlowGuard = (dllChars and DLL_CHAR_GUARD_CF) != 0,
            leakedPdbPaths = pdbPaths,
        )
    }
}

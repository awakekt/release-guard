/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.analyzers

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Structural and hardening metadata parsed from a single-architecture or universal Fat Mach-O binary. */
public data class MachOInspectionResult(
    public val sliceCount: Int,
    public val segmentNames: List<String>,
    public val hasDwarfSegment: Boolean,
    public val totalSymbolCount: Int,
    public val debugStabSymbolCount: Int,
    public val localSymbolNames: List<String>,
    public val isExecutable: Boolean = false,
    public val isPie: Boolean = true,
    public val hasCodeSignature: Boolean = false,
    public val hasStackCanary: Boolean = false,
)

/**
 * Pure-Kotlin Mach-O 64-bit and Universal Fat binary inspector for iOS frameworks, IPAs, and macOS `.dylib`s.
 *
 * Inspects `LC_SEGMENT_64` (`__DWARF`), `LC_SYMTAB` symbol tables, `MH_PIE` (ASLR),
 * `LC_CODE_SIGNATURE`, and stack canaries (`___stack_chk_fail`).
 */
public object MachOInspector {
    private const val MH_MAGIC_64_LE = 0xFEEDFACF.toInt()
    private const val MH_CIGAM_64_BE = 0xCFFAEDFE.toInt()
    private const val FAT_MAGIC_BE = 0xCAFEBABE.toInt()
    private const val FAT_CIGAM_LE = 0xBEBAFECA.toInt()

    private const val MH_EXECUTE = 0x2
    private const val MH_PIE = 0x00200000

    private const val LC_SYMTAB = 0x02
    private const val LC_SEGMENT_64 = 0x19
    private const val LC_CODE_SIGNATURE = 0x1D
    private const val N_STAB_MASK = 0xE0
    private const val N_EXT_MASK = 0x01

    /** Returns `true` when [bytes] starts with a recognized 64-bit Mach-O or Fat/Universal header. */
    public fun isMachO(bytes: ByteArray): Boolean {
        if (bytes.size < 32) return false
        val leMagic = ByteBuffer.wrap(bytes, 0, 4).order(ByteOrder.LITTLE_ENDIAN).int
        val beMagic = ByteBuffer.wrap(bytes, 0, 4).order(ByteOrder.BIG_ENDIAN).int
        return leMagic == MH_MAGIC_64_LE ||
            leMagic == MH_CIGAM_64_BE ||
            beMagic == FAT_MAGIC_BE ||
            beMagic == FAT_CIGAM_LE
    }

    /** Parses a Mach-O or Fat/Universal binary [bytes]. */
    public fun parse(bytes: ByteArray): MachOInspectionResult {
        require(bytes.size >= 32) { "Mach-O binary is truncated (${bytes.size} bytes)." }
        val beMagic = ByteBuffer.wrap(bytes, 0, 4).order(ByteOrder.BIG_ENDIAN).int
        val leMagic = ByteBuffer.wrap(bytes, 0, 4).order(ByteOrder.LITTLE_ENDIAN).int

        val slices: List<Pair<Int, Int>> = when {
            beMagic == FAT_MAGIC_BE || leMagic == FAT_MAGIC_BE -> readFatSlices(bytes, ByteOrder.BIG_ENDIAN)
            beMagic == FAT_CIGAM_LE -> readFatSlices(bytes, ByteOrder.LITTLE_ENDIAN)
            else -> listOf(0 to bytes.size)
        }

        val parsed = slices.mapNotNull { (sliceOffset, sliceSize) ->
            val valid = sliceOffset >= 0 && sliceSize >= 32 && sliceOffset + sliceSize <= bytes.size
            if (valid) parseSingleSlice(bytes, sliceOffset, sliceSize) else null
        }
        require(parsed.isNotEmpty()) { "Input is not a recognized 64-bit Mach-O or Universal Fat binary." }

        val segments = parsed.flatMap { it.segmentNames }.distinct()
        val hasCanary = containsAscii(bytes, "___stack_chk_fail") || containsAscii(bytes, "__stack_chk_guard")
        return MachOInspectionResult(
            sliceCount = parsed.size,
            segmentNames = segments,
            hasDwarfSegment = parsed.any { it.hasDwarfSegment },
            totalSymbolCount = parsed.sumOf { it.totalSymbolCount },
            debugStabSymbolCount = parsed.sumOf { it.debugStabSymbolCount },
            localSymbolNames = parsed.flatMap { it.localSymbolNames }.distinct(),
            isExecutable = parsed.any { it.isExecutable },
            isPie = parsed.all { !it.isExecutable || it.isPie },
            hasCodeSignature = parsed.all { it.hasCodeSignature },
            hasStackCanary = hasCanary,
        )
    }

    private fun readFatSlices(bytes: ByteArray, order: ByteOrder): List<Pair<Int, Int>> {
        val buf = ByteBuffer.wrap(bytes).order(order)
        val archCount = buf.getInt(4)
        require(archCount in 1..64) { "Invalid Fat Mach-O architecture count: $archCount" }
        val slices = mutableListOf<Pair<Int, Int>>()
        var pos = 8
        repeat(archCount) {
            if (pos + 20 > bytes.size) return slices
            slices += buf.getInt(pos + 8) to buf.getInt(pos + 12)
            pos += 20
        }
        return slices
    }

    private fun parseSingleSlice(bytes: ByteArray, sliceOffset: Int, sliceSize: Int): MachOInspectionResult? {
        val leMagic = ByteBuffer.wrap(bytes, sliceOffset, 4).order(ByteOrder.LITTLE_ENDIAN).int
        val order = when (leMagic) {
            MH_MAGIC_64_LE -> ByteOrder.LITTLE_ENDIAN
            MH_CIGAM_64_BE -> ByteOrder.BIG_ENDIAN
            else -> return null
        }
        val buf = ByteBuffer.wrap(bytes).order(order)
        val fileType = buf.getInt(sliceOffset + 12)
        val ncmds = buf.getInt(sliceOffset + 16)
        val headerFlags = buf.getInt(sliceOffset + 24)
        val sliceEnd = sliceOffset + sliceSize
        var cmdPos = sliceOffset + 32

        val segments = mutableListOf<String>()
        var totalSymbols = 0
        var debugStabSymbols = 0
        val localSymbols = mutableListOf<String>()
        var hasCodeSignature = false

        repeat(ncmds.coerceAtLeast(0)) {
            if (cmdPos + 8 > sliceEnd) return@repeat
            val cmd = buf.getInt(cmdPos)
            val cmdSize = buf.getInt(cmdPos + 4)
            if (cmdSize < 8 || cmdPos + cmdSize > sliceEnd) return@repeat

            when (cmd) {
                LC_SEGMENT_64 -> if (cmdPos + 24 <= sliceEnd) {
                    val rawName = readCString(bytes, cmdPos + 8, 16)
                    if (rawName.isNotEmpty()) segments += rawName
                }
                LC_CODE_SIGNATURE -> hasCodeSignature = true
                LC_SYMTAB -> if (cmdPos + 24 <= sliceEnd) {
                    val parsed = parseSymtab(bytes, buf, sliceOffset, sliceEnd, cmdPos)
                    totalSymbols += parsed.total
                    debugStabSymbols += parsed.debugStab
                    localSymbols += parsed.localNames
                }
            }
            cmdPos += cmdSize
        }

        val isExec = fileType == MH_EXECUTE
        return MachOInspectionResult(
            sliceCount = 1,
            segmentNames = segments,
            hasDwarfSegment = segments.any { it.equals("__DWARF", ignoreCase = true) },
            totalSymbolCount = totalSymbols,
            debugStabSymbolCount = debugStabSymbols,
            localSymbolNames = localSymbols,
            isExecutable = isExec,
            isPie = !isExec || (headerFlags and MH_PIE) != 0,
            hasCodeSignature = hasCodeSignature,
        )
    }

    private data class SymtabSummary(
        val total: Int,
        val debugStab: Int,
        val localNames: List<String>,
    )

    private fun parseSymtab(
        bytes: ByteArray,
        buf: ByteBuffer,
        sliceOffset: Int,
        sliceEnd: Int,
        cmdPos: Int,
    ): SymtabSummary {
        val symoff = buf.getInt(cmdPos + 8)
        val nsyms = buf.getInt(cmdPos + 12)
        val stroff = buf.getInt(cmdPos + 16)
        val strsize = buf.getInt(cmdPos + 20)
        val symStart = sliceOffset + symoff
        val strStart = sliceOffset + stroff
        val fits = nsyms > 0 && symoff >= 0 && stroff >= 0 && strsize > 0 && strStart + strsize <= sliceEnd
        if (!fits) return SymtabSummary(0, 0, emptyList())

        val safeCount = minOf(nsyms, ((sliceEnd - symStart) / 16).coerceAtLeast(0))
        val strEnd = strStart + strsize
        var debugStab = 0
        val localNames = mutableListOf<String>()
        for (i in 0 until safeCount) {
            val nlistPos = symStart + i * 16
            val strx = buf.getInt(nlistPos)
            val nType = bytes[nlistPos + 4].toInt() and 0xFF
            val isStab = (nType and N_STAB_MASK) != 0
            val isLocalOrDebug = isStab || (nType and N_EXT_MASK) == 0
            if (isStab) debugStab += 1
            val nameOffset = strStart + strx
            if (isLocalOrDebug && strx > 0 && nameOffset < strEnd) {
                val name = readNullTerminated(bytes, nameOffset, strEnd)
                if (name.isNotEmpty()) localNames += name
            }
        }
        return SymtabSummary(total = safeCount, debugStab = debugStab, localNames = localNames)
    }

    private fun readCString(bytes: ByteArray, start: Int, maxLen: Int): String {
        val limit = minOf(start + maxLen, bytes.size)
        var end = start
        while (end < limit && bytes[end].toInt() != 0) end += 1
        return String(bytes, start, (end - start).coerceAtLeast(0), Charsets.UTF_8)
    }

    private fun readNullTerminated(bytes: ByteArray, start: Int, limit: Int): String {
        var end = start
        while (end < limit && bytes[end].toInt() != 0) end += 1
        return String(bytes, start, (end - start).coerceAtLeast(0), Charsets.UTF_8)
    }

    private fun containsAscii(bytes: ByteArray, needle: String): Boolean {
        val target = needle.toByteArray(Charsets.US_ASCII)
        return target.isNotEmpty() && bytes.size >= target.size &&
            (0..(bytes.size - target.size)).any { start ->
                target.indices.all { j -> bytes[start + j] == target[j] }
            }
    }
}

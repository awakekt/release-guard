/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.analyzers

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Security hardening and alignment metadata parsed from a 32-bit or 64-bit ELF shared object (`.so`). */
public data class ElfInspectionResult(
    public val is64Bit: Boolean,
    public val isPieOrShared: Boolean,
    public val hasNxStack: Boolean,
    public val hasRelro: Boolean,
    public val hasFullRelro: Boolean,
    public val hasStackCanary: Boolean,
    public val hasDebugSections: Boolean,
    public val hasSymbolTable: Boolean,
    public val is16KbAligned: Boolean,
    public val minLoadAlignment: Long,
    public val debugSectionNames: List<String>,
)

/**
 * Pure-Kotlin 32-bit and 64-bit ELF binary inspector for Android JNI `.so` libraries and Linux native binaries.
 *
 * Inspects PIE (`ET_DYN`), non-executable stack (`PT_GNU_STACK`), RELRO + `BIND_NOW` (`PT_GNU_RELRO`
 * + `PT_DYNAMIC`), 16 KB `PT_LOAD` page alignment (Android 15+ requirement), `.debug*`/`.symtab`
 * stripping, and `__stack_chk_fail` stack canaries without requiring `readelf` or `objdump`.
 */
public object ElfBinaryInspector {
    private const val ELF_CLASS_32 = 1
    private const val ELF_CLASS_64 = 2
    private const val ELF_DATA_LE = 1
    private const val ELF_DATA_BE = 2
    private const val ET_DYN = 3

    private const val PT_LOAD = 1
    private const val PT_DYNAMIC = 2
    private const val PT_GNU_STACK = 0x6474E551
    private const val PT_GNU_RELRO = 0x6474E552
    private const val PF_X = 0x1

    private const val DT_NULL = 0L
    private const val DT_BIND_NOW = 24L
    private const val DT_FLAGS = 30L
    private const val DT_FLAGS_1 = 0x6FFFFFFBL
    private const val DF_BIND_NOW = 0x8L
    private const val DF_1_NOW = 0x1L

    private const val SHT_SYMTAB = 2
    private const val PAGE_SIZE_16KB = 16_384L

    private class ProgramFlags {
        var hasNxStack: Boolean = true
        var hasRelro: Boolean = false
        var hasBindNow: Boolean = false
        var minLoadAlignment: Long = Long.MAX_VALUE
        var hasLoadSegment: Boolean = false
    }

    private class SectionFlags {
        var hasSymbolTable: Boolean = false
        val debugSections: MutableList<String> = mutableListOf()
    }

    /** Returns `true` when [bytes] starts with the 4-byte ELF magic header (`\u007FELF`). */
    public fun isElf(bytes: ByteArray): Boolean =
        bytes.size >= 16 &&
            bytes[0] == 0x7F.toByte() &&
            bytes[1] == 'E'.code.toByte() &&
            bytes[2] == 'L'.code.toByte() &&
            bytes[3] == 'F'.code.toByte()

    /** Parses an ELF binary buffer [bytes]. */
    public fun parse(bytes: ByteArray): ElfInspectionResult {
        require(isElf(bytes)) { "Input is not an ELF binary (missing 0x7F ELF magic)." }
        val elfClass = bytes[4].toInt() and 0xFF
        val is64Bit = when (elfClass) {
            ELF_CLASS_64 -> true
            ELF_CLASS_32 -> false
            else -> throw IllegalArgumentException("Unsupported ELF class: $elfClass")
        }
        val order = when (val dataEnc = bytes[5].toInt() and 0xFF) {
            ELF_DATA_LE -> ByteOrder.LITTLE_ENDIAN
            ELF_DATA_BE -> ByteOrder.BIG_ENDIAN
            else -> throw IllegalArgumentException("Unsupported ELF endianness: $dataEnc")
        }
        val minHeader = if (is64Bit) 64 else 52
        require(bytes.size >= minHeader) { "ELF header is truncated (${bytes.size} bytes)." }

        val buf = ByteBuffer.wrap(bytes).order(order)
        val eType = buf.getShort(16).toInt() and 0xFFFF
        val progFlags = readProgramHeaders(bytes, buf, is64Bit)
        val secFlags = readSectionHeaders(bytes, buf, is64Bit)
        val hasCanary = bytes.containsAscii("__stack_chk_fail") || bytes.containsAscii("__stack_chk_guard")
        val effectiveAlign = if (progFlags.hasLoadSegment) progFlags.minLoadAlignment else 0L

        return ElfInspectionResult(
            is64Bit = is64Bit,
            isPieOrShared = eType == ET_DYN,
            hasNxStack = progFlags.hasNxStack,
            hasRelro = progFlags.hasRelro,
            hasFullRelro = progFlags.hasRelro && progFlags.hasBindNow,
            hasStackCanary = hasCanary,
            hasDebugSections = secFlags.debugSections.isNotEmpty(),
            hasSymbolTable = secFlags.hasSymbolTable,
            is16KbAligned = !progFlags.hasLoadSegment || effectiveAlign >= PAGE_SIZE_16KB,
            minLoadAlignment = effectiveAlign,
            debugSectionNames = secFlags.debugSections,
        )
    }

    private fun readProgramHeaders(bytes: ByteArray, buf: ByteBuffer, is64Bit: Boolean): ProgramFlags {
        val phoff = readElfWord(buf, is64Bit, 32, 28)
        val phentsize = buf.getShort(if (is64Bit) 54 else 42).toInt() and 0xFFFF
        val phnum = buf.getShort(if (is64Bit) 56 else 44).toInt() and 0xFFFF
        val flags = ProgramFlags()
        if (phoff <= 0L || phentsize <= 0 || phnum <= 0) return flags

        for (i in 0 until phnum) {
            val pos = (phoff + i.toLong() * phentsize).toInt()
            if (pos < 0 || pos + phentsize > bytes.size) break
            applyProgramHeader(bytes, buf, is64Bit, pos, flags)
        }
        return flags
    }

    private fun applyProgramHeader(
        bytes: ByteArray,
        buf: ByteBuffer,
        is64Bit: Boolean,
        pos: Int,
        flags: ProgramFlags,
    ) {
        val pType = buf.getInt(pos)
        val pFlags = buf.getInt(pos + if (is64Bit) 4 else 24)
        val pOffset = readElfWord(buf, is64Bit, pos + 8, pos + 4)
        val pFilesz = readElfWord(buf, is64Bit, pos + 32, pos + 16)
        val pAlign = readElfWord(buf, is64Bit, pos + 48, pos + 28)
        when (pType) {
            PT_LOAD -> {
                flags.hasLoadSegment = true
                if (pAlign < flags.minLoadAlignment) flags.minLoadAlignment = pAlign
            }
            PT_GNU_STACK -> if ((pFlags and PF_X) != 0) flags.hasNxStack = false
            PT_GNU_RELRO -> flags.hasRelro = true
            PT_DYNAMIC -> if (hasBindNowInDynamic(bytes, buf, is64Bit, pOffset, pFilesz)) flags.hasBindNow = true
        }
    }

    private fun hasBindNowInDynamic(
        bytes: ByteArray,
        buf: ByteBuffer,
        is64Bit: Boolean,
        offset: Long,
        size: Long,
    ): Boolean {
        val entrySize = if (is64Bit) 16 else 8
        if (offset < 0L || size <= 0L || offset + size > bytes.size.toLong()) return false
        var pos = offset.toInt()
        val end = (offset + size).toInt()
        var found = false
        while (pos + entrySize <= end && !found) {
            val tag = readElfWord(buf, is64Bit, pos, pos)
            val value = readElfWord(buf, is64Bit, pos + 8, pos + 4)
            if (tag == DT_NULL) {
                pos = end
            } else {
                found = isBindNowTag(tag, value)
                pos += entrySize
            }
        }
        return found
    }

    private fun isBindNowTag(tag: Long, value: Long): Boolean =
        tag == DT_BIND_NOW ||
            (tag == DT_FLAGS && (value and DF_BIND_NOW) != 0L) ||
            (tag == DT_FLAGS_1 && (value and DF_1_NOW) != 0L)

    private fun readSectionHeaders(bytes: ByteArray, buf: ByteBuffer, is64Bit: Boolean): SectionFlags {
        val shoff = readElfWord(buf, is64Bit, 40, 32)
        val shentsize = buf.getShort(if (is64Bit) 58 else 46).toInt() and 0xFFFF
        val shnum = buf.getShort(if (is64Bit) 60 else 48).toInt() and 0xFFFF
        val shstrndx = buf.getShort(if (is64Bit) 62 else 50).toInt() and 0xFFFF
        val out = SectionFlags()
        if (shoff <= 0L || shentsize < 40 || shnum <= 0) return out

        val strTable = resolveSectionStringTable(bytes, buf, is64Bit, shoff, shentsize, shnum, shstrndx)
        for (i in 0 until shnum) {
            val pos = (shoff + i.toLong() * shentsize).toInt()
            if (pos < 0 || pos + shentsize > bytes.size) break
            inspectSectionHeader(bytes, buf, pos, strTable, out)
        }
        return out
    }

    private fun inspectSectionHeader(
        bytes: ByteArray,
        buf: ByteBuffer,
        pos: Int,
        strTable: Pair<Int, Int>?,
        out: SectionFlags,
    ) {
        if (buf.getInt(pos + 4) == SHT_SYMTAB) out.hasSymbolTable = true
        val name = strTable?.let { (start, end) -> readCString(bytes, start + buf.getInt(pos), end) }.orEmpty()
        if (name.startsWith(".debug") || name == ".zdebug_info") out.debugSections += name
    }

    private fun resolveSectionStringTable(
        bytes: ByteArray,
        buf: ByteBuffer,
        is64Bit: Boolean,
        shoff: Long,
        shentsize: Int,
        shnum: Int,
        shstrndx: Int,
    ): Pair<Int, Int>? {
        val hdrPos = if (shstrndx in 0 until shnum) (shoff + shstrndx.toLong() * shentsize).toInt() else -1
        if (hdrPos < 0 || hdrPos + shentsize > bytes.size) return null
        val strOff = readElfWord(buf, is64Bit, hdrPos + 24, hdrPos + 16)
        val strSize = readElfWord(buf, is64Bit, hdrPos + 32, hdrPos + 20)
        return if (strOff >= 0L && strSize > 0L && strOff + strSize <= bytes.size.toLong()) {
            strOff.toInt() to (strOff + strSize).toInt()
        } else {
            null
        }
    }

    private fun readElfWord(buf: ByteBuffer, is64Bit: Boolean, off64: Int, off32: Int): Long =
        if (is64Bit) buf.getLong(off64) else buf.getInt(off32).toLong() and 0xFFFFFFFFL

    private fun readCString(bytes: ByteArray, start: Int, limit: Int): String {
        if (start < 0 || start >= limit) return ""
        var end = start
        while (end < limit && bytes[end].toInt() != 0) end += 1
        return String(bytes, start, end - start, Charsets.US_ASCII)
    }
}

private fun ByteArray.containsAscii(needle: String): Boolean {
    val target = needle.toByteArray(Charsets.US_ASCII)
    return target.isNotEmpty() && size >= target.size &&
        (0..(size - target.size)).any { start ->
            target.indices.all { j -> this[start + j] == target[j] }
        }
}

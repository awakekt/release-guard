/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/** Deterministic binary fixture builders for JVM, DEX, ELF, PE, WASM, Mach-O, Protobuf XML, bplist00, and AWKB tests. */
internal object SyntheticFixtures {
    @Suppress("CyclomaticComplexMethod")
    fun buildMinimalClassBytes(
        internalName: String,
        fieldNames: List<String> = emptyList(),
        methodNames: List<String> = emptyList(),
        sourceFile: String? = null,
        includeKotlinMetadata: Boolean = false,
        includeLocalVariableTable: Boolean = false,
        includeMethodParameters: Boolean = false,
    ): ByteArray {
        val pool = mutableListOf<ByteArray>()
        fun addUtf8(s: String): Int {
            val b = s.toByteArray(Charsets.UTF_8)
            val entry = ByteArrayOutputStream()
            DataOutputStream(entry).use { d -> d.writeByte(1); d.writeShort(b.size); d.write(b) }
            pool += entry.toByteArray()
            return pool.size
        }
        fun addClass(nameIdx: Int): Int {
            val entry = ByteArrayOutputStream()
            DataOutputStream(entry).use { d -> d.writeByte(7); d.writeShort(nameIdx) }
            pool += entry.toByteArray()
            return pool.size
        }

        val thisClassIdx = addClass(addUtf8(internalName))
        val superClassIdx = addClass(addUtf8("java/lang/Object"))
        val fieldDescIdx = addUtf8("I")
        val methodDescIdx = addUtf8("()V")
        val fieldIdxPairs = fieldNames.map { addUtf8(it) to fieldDescIdx }
        val methodIdxPairs = methodNames.map { addUtf8(it) to methodDescIdx }
        val sourceFileAttrIdx = sourceFile?.let { addUtf8("SourceFile") to addUtf8(it) }
        val codeAttrIdx = if (includeLocalVariableTable) addUtf8("Code") else null
        val lvtAttrIdx = if (includeLocalVariableTable) addUtf8("LocalVariableTable") else null
        val mpAttrIdx = if (includeMethodParameters) addUtf8("MethodParameters") else null
        val rvaAttrIdx = if (includeKotlinMetadata) addUtf8("RuntimeVisibleAnnotations") else null
        val kotlinMetaIdx = if (includeKotlinMetadata) addUtf8("Lkotlin/Metadata;") else null

        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { d ->
            d.writeInt(0xCAFEBABE.toInt())
            d.writeShort(0); d.writeShort(52)
            d.writeShort(pool.size + 1)
            pool.forEach(d::write)
            d.writeShort(0x0021); d.writeShort(thisClassIdx); d.writeShort(superClassIdx)
            d.writeShort(0)
            d.writeShort(fieldIdxPairs.size)
            for ((nameIdx, descIdx) in fieldIdxPairs) {
                d.writeShort(0x0001); d.writeShort(nameIdx); d.writeShort(descIdx); d.writeShort(0)
            }
            d.writeShort(methodIdxPairs.size)
            for ((idx, pair) in methodIdxPairs.withIndex()) {
                val (nameIdx, descIdx) = pair
                d.writeShort(0x0001); d.writeShort(nameIdx); d.writeShort(descIdx)
                val attachExtras = idx == 0
                val mAttrCount = (if (attachExtras && codeAttrIdx != null) 1 else 0) +
                    (if (attachExtras && mpAttrIdx != null) 1 else 0)
                d.writeShort(mAttrCount)
                if (attachExtras && codeAttrIdx != null && lvtAttrIdx != null) {
                    // Code attr: maxStack(2)+maxLocals(2)+codeLen(4)+code(1:return)+exLen(2)+attrsCount(2)+LVT(6+2)
                    d.writeShort(codeAttrIdx)
                    d.writeInt(2 + 2 + 4 + 1 + 2 + 2 + 8)
                    d.writeShort(1); d.writeShort(1); d.writeInt(1); d.writeByte(0xB1)
                    d.writeShort(0); d.writeShort(1)
                    d.writeShort(lvtAttrIdx); d.writeInt(2); d.writeShort(0)
                }
                if (attachExtras && mpAttrIdx != null) {
                    d.writeShort(mpAttrIdx); d.writeInt(1); d.writeByte(0)
                }
            }
            val classAttrCount = (if (sourceFileAttrIdx != null) 1 else 0) +
                (if (rvaAttrIdx != null) 1 else 0)
            d.writeShort(classAttrCount)
            if (sourceFileAttrIdx != null) {
                d.writeShort(sourceFileAttrIdx.first); d.writeInt(2); d.writeShort(sourceFileAttrIdx.second)
            }
            if (rvaAttrIdx != null && kotlinMetaIdx != null) {
                // RuntimeVisibleAnnotations: count=1, type_index=kotlinMetaIdx, num_element_value_pairs=0
                d.writeShort(rvaAttrIdx); d.writeInt(6); d.writeShort(1); d.writeShort(kotlinMetaIdx); d.writeShort(0)
            }
        }
        return out.toByteArray()
    }

    fun writeZip(target: File, entries: Map<String, ByteArray>) {
        target.parentFile?.mkdirs()
        ZipOutputStream(target.outputStream()).use { zos ->
            for ((name, bytes) in entries) {
                zos.putNextEntry(ZipEntry(name))
                zos.write(bytes)
                zos.closeEntry()
            }
        }
    }

    /** Appends a minimal valid APK Signature Scheme v2 Signing Block before the ZIP central directory. */
    fun writeV2SignedApk(target: File, entries: Map<String, ByteArray>, derCert: ByteArray? = null) {
        val raw = File.createTempFile("rg-unsigned-", ".apk")
        try {
            writeZip(raw, entries)
            val zipBytes = raw.readBytes()
            val buf = ByteBuffer.wrap(zipBytes).order(ByteOrder.LITTLE_ENDIAN)
            var eocdPos = -1
            for (pos in (zipBytes.size - 22) downTo 0) {
                if (buf.getInt(pos) == 0x06054B50) {
                    eocdPos = pos
                    break
                }
            }
            val cdOffset = buf.getInt(eocdPos + 16)
            val v2Value = buildV2SchemeValue(derCert)
            val pairLen = 4L + v2Value.size.toLong()
            val blockSizeExclInitial = 8L + pairLen + 24L
            val sigBlock = ByteArrayOutputStream()
            val header = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(blockSizeExclInitial).array()
            val pairHdr = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN).putLong(pairLen).putInt(0x7109871A).array()
            val footer = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN)
                .putLong(blockSizeExclInitial)
                .put("APK Sig Block 42".toByteArray(Charsets.US_ASCII))
                .array()
            sigBlock.write(header); sigBlock.write(pairHdr); sigBlock.write(v2Value); sigBlock.write(footer)
            val blockBytes = sigBlock.toByteArray()

            val patched = ByteArray(zipBytes.size + blockBytes.size)
            System.arraycopy(zipBytes, 0, patched, 0, cdOffset)
            System.arraycopy(blockBytes, 0, patched, cdOffset, blockBytes.size)
            System.arraycopy(zipBytes, cdOffset, patched, cdOffset + blockBytes.size, zipBytes.size - cdOffset)
            val patchedEocd = eocdPos + blockBytes.size
            ByteBuffer.wrap(patched).order(ByteOrder.LITTLE_ENDIAN).putInt(patchedEocd + 16, cdOffset + blockBytes.size)
            target.parentFile?.mkdirs()
            target.writeBytes(patched)
        } finally {
            raw.delete()
        }
    }

    private fun buildV2SchemeValue(derCert: ByteArray?): ByteArray {
        val certsPayload = ByteArrayOutputStream()
        if (derCert != null) {
            certsPayload.write(leInt(derCert.size))
            certsPayload.write(derCert)
        }
        val certsBytes = certsPayload.toByteArray()
        val signedData = ByteArrayOutputStream().apply {
            write(leInt(0)) // digests len = 0
            write(leInt(certsBytes.size))
            write(certsBytes)
        }.toByteArray()
        val signer = ByteArrayOutputStream().apply {
            write(leInt(signedData.size))
            write(signedData)
        }.toByteArray()
        return ByteArrayOutputStream().apply {
            write(leInt(signer.size))
            write(signer)
        }.toByteArray()
    }

    fun buildMinimalWasmBytes(
        customSections: List<Pair<String, ByteArray>> = emptyList(),
        exports: List<String> = emptyList(),
        dataStrings: List<String> = emptyList(),
    ): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(byteArrayOf(0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00))
        if (exports.isNotEmpty()) {
            val payload = ByteArrayOutputStream()
            writeUleb128(payload, exports.size)
            exports.forEachIndexed { idx, name ->
                val nb = name.toByteArray(Charsets.UTF_8)
                writeUleb128(payload, nb.size); payload.write(nb)
                payload.write(0) // func export kind
                writeUleb128(payload, idx)
            }
            val bytes = payload.toByteArray()
            out.write(7); writeUleb128(out, bytes.size); out.write(bytes)
        }
        if (dataStrings.isNotEmpty()) {
            val payload = dataStrings.joinToString("\u0000").toByteArray(Charsets.UTF_8)
            out.write(11); writeUleb128(out, payload.size); out.write(payload)
        }
        for ((name, body) in customSections) {
            val nameBytes = name.toByteArray(Charsets.UTF_8)
            val payload = ByteArrayOutputStream()
            writeUleb128(payload, nameBytes.size); payload.write(nameBytes); payload.write(body)
            val pb = payload.toByteArray()
            out.write(0); writeUleb128(out, pb.size); out.write(pb)
        }
        return out.toByteArray()
    }

    fun buildMinimalDexBytes(
        classesAndMembers: Map<String, List<String>>,
        extraStrings: List<String> = emptyList(),
        includeKotlinMetadata: Boolean = false,
    ): ByteArray {
        val strings = linkedSetOf<String>()
        if (includeKotlinMetadata) strings += "Lkotlin/Metadata;"
        for ((internalName, members) in classesAndMembers) {
            strings += "L$internalName;"
            strings.addAll(members)
        }
        strings.addAll(extraStrings)
        val sortedStrings = strings.sorted()
        val strIdx = sortedStrings.withIndex().associate { (i, s) -> s to i }

        val typeDescriptors = buildList {
            if (includeKotlinMetadata) add("Lkotlin/Metadata;")
            addAll(classesAndMembers.keys.map { "L$it;" })
        }
        val typeIdx = typeDescriptors.withIndex().associate { (i, d) -> d to i }

        val methods = classesAndMembers.entries.flatMap { (cls, members) ->
            val tIdx = typeIdx.getValue("L$cls;")
            members.map { m -> tIdx to strIdx.getValue(m) }
        }
        val definedTypeIds = classesAndMembers.keys.map { typeIdx.getValue("L$it;") }

        val stringIdsOff = 112
        val typeIdsOff = stringIdsOff + sortedStrings.size * 4
        val methodIdsOff = typeIdsOff + typeDescriptors.size * 4
        val classDefsOff = methodIdsOff + methods.size * 8
        val dataStart = classDefsOff + definedTypeIds.size * 32

        val stringDataOut = ByteArrayOutputStream()
        val stringDataOffsets = IntArray(sortedStrings.size)
        for ((i, s) in sortedStrings.withIndex()) {
            stringDataOffsets[i] = dataStart + stringDataOut.size()
            val utf8 = s.toByteArray(Charsets.UTF_8)
            writeUleb128(stringDataOut, s.length); stringDataOut.write(utf8); stringDataOut.write(0)
        }

        val totalSize = dataStart + stringDataOut.size()
        val bytes = ByteArray(totalSize)
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        "dex\n035\u0000".toByteArray(Charsets.US_ASCII).copyInto(bytes, 0)
        buf.putInt(32, totalSize); buf.putInt(36, 112); buf.putInt(40, 0x12345678)
        buf.putInt(56, sortedStrings.size); buf.putInt(60, stringIdsOff)
        buf.putInt(64, typeDescriptors.size); buf.putInt(68, typeIdsOff)
        buf.putInt(88, methods.size); buf.putInt(92, methodIdsOff)
        buf.putInt(96, definedTypeIds.size); buf.putInt(100, classDefsOff)
        for (i in sortedStrings.indices) buf.putInt(stringIdsOff + i * 4, stringDataOffsets[i])
        for (i in typeDescriptors.indices) buf.putInt(typeIdsOff + i * 4, strIdx.getValue(typeDescriptors[i]))
        for ((i, pair) in methods.withIndex()) {
            val pos = methodIdsOff + i * 8
            buf.putShort(pos, pair.first.toShort()); buf.putShort(pos + 2, 0); buf.putInt(pos + 4, pair.second)
        }
        for ((i, tIdx) in definedTypeIds.withIndex()) buf.putInt(classDefsOff + i * 32, tIdx)
        stringDataOut.toByteArray().copyInto(bytes, dataStart)
        return bytes
    }

    /** Builds a minimal 64-bit little-endian ELF shared library with configurable hardening & alignment. */
    @Suppress("CyclomaticComplexMethod")
    fun buildMinimalElf64Bytes(
        isPie: Boolean = true,
        loadAlignment: Long = 16_384L,
        nxStack: Boolean = true,
        hasRelro: Boolean = true,
        hasBindNow: Boolean = true,
        hasDebugSection: Boolean = false,
        hasSymtab: Boolean = false,
        hasStackCanary: Boolean = true,
    ): ByteArray {
        val ehdrSize = 64
        val phEntSize = 56
        val phCount = 3 + if (hasRelro) 1 else 0
        val phOff = ehdrSize.toLong()
        val dynOff = (ehdrSize + phCount * phEntSize).toLong()
        val dynEntries = if (hasBindNow) 2 else 1
        val dynSize = dynEntries * 16L

        val strTabBytes = ByteArrayOutputStream().apply {
            write(0)
            write(".shstrtab\u0000".toByteArray(Charsets.US_ASCII))
            if (hasDebugSection) write(".debug_info\u0000".toByteArray(Charsets.US_ASCII))
            if (hasSymtab) write(".symtab\u0000".toByteArray(Charsets.US_ASCII))
        }.toByteArray()
        val canaryBytes = if (hasStackCanary) "__stack_chk_fail\u0000".toByteArray(Charsets.US_ASCII) else ByteArray(0)
        val strTabOff = dynOff + dynSize
        val canaryOff = strTabOff + strTabBytes.size
        val shOff = canaryOff + canaryBytes.size
        val shEntSize = 64
        val shCount = 2 + (if (hasDebugSection) 1 else 0) + (if (hasSymtab) 1 else 0)
        val total = (shOff + shCount * shEntSize).toInt()
        val bytes = ByteArray(total)
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)

        bytes[0] = 0x7F; bytes[1] = 'E'.code.toByte(); bytes[2] = 'L'.code.toByte(); bytes[3] = 'F'.code.toByte()
        bytes[4] = 2; bytes[5] = 1; bytes[6] = 1
        buf.putShort(16, if (isPie) 3 else 2) // ET_DYN vs ET_EXEC
        buf.putShort(18, 183) // EM_AARCH64
        buf.putInt(20, 1)
        buf.putLong(32, phOff); buf.putLong(40, shOff)
        buf.putShort(52, ehdrSize.toShort())
        buf.putShort(54, phEntSize.toShort()); buf.putShort(56, phCount.toShort())
        buf.putShort(58, shEntSize.toShort()); buf.putShort(60, shCount.toShort())
        buf.putShort(62, 1) // shstrndx = 1

        var p = phOff.toInt()
        // PT_LOAD
        buf.putInt(p, 1); buf.putInt(p + 4, 5); buf.putLong(p + 48, loadAlignment); p += phEntSize
        // PT_GNU_STACK
        buf.putInt(p, 0x6474E551); buf.putInt(p + 4, if (nxStack) 6 else 7); p += phEntSize
        // PT_DYNAMIC
        buf.putInt(p, 2); buf.putInt(p + 4, 6); buf.putLong(p + 8, dynOff); buf.putLong(p + 32, dynSize); p += phEntSize
        if (hasRelro) {
            buf.putInt(p, 0x6474E552); buf.putInt(p + 4, 4)
        }
        // Dynamic table
        var dp = dynOff.toInt()
        if (hasBindNow) {
            buf.putLong(dp, 24L); buf.putLong(dp + 8, 1L); dp += 16 // DT_BIND_NOW
        }
        buf.putLong(dp, 0L)

        strTabBytes.copyInto(bytes, strTabOff.toInt())
        canaryBytes.copyInto(bytes, canaryOff.toInt())

        // Section headers: 0=NULL, 1=.shstrtab, optional .debug_info, optional .symtab
        var s = shOff.toInt() + shEntSize
        // 1: .shstrtab
        buf.putInt(s, 1); buf.putInt(s + 4, 3); buf.putLong(s + 24, strTabOff); buf.putLong(s + 32, strTabBytes.size.toLong())
        s += shEntSize
        var nameCursor = 1 + ".shstrtab".length + 1
        if (hasDebugSection) {
            buf.putInt(s, nameCursor); buf.putInt(s + 4, 1); s += shEntSize
            nameCursor += ".debug_info".length + 1
        }
        if (hasSymtab) {
            buf.putInt(s, nameCursor); buf.putInt(s + 4, 2) // SHT_SYMTAB
        }
        return bytes
    }

    /** Builds a minimal PE32+ Windows DLL with configurable ASLR/DEP and optional leaked PDB path. */
    fun buildMinimalPe64Bytes(
        hasAslr: Boolean = true,
        hasDep: Boolean = true,
        pdbPath: String? = null,
    ): ByteArray {
        val pdbBytes = pdbPath?.toByteArray(Charsets.US_ASCII) ?: ByteArray(0)
        val bytes = ByteArray(256 + pdbBytes.size)
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        bytes[0] = 'M'.code.toByte(); bytes[1] = 'Z'.code.toByte()
        val peOff = 0x80
        buf.putInt(60, peOff)
        buf.putInt(peOff, 0x00004550) // PE\0\0
        buf.putShort(peOff + 20, 112) // SizeOfOptionalHeader
        val optStart = peOff + 24
        buf.putShort(optStart, 0x020B) // PE32+
        var dllChars = 0
        if (hasAslr) dllChars = dllChars or 0x0040
        if (hasDep) dllChars = dllChars or 0x0100
        buf.putShort(optStart + 70, dllChars.toShort())
        if (pdbBytes.isNotEmpty()) pdbBytes.copyInto(bytes, 256)
        return bytes
    }

    /** Builds a minimal 64-bit Mach-O binary with configurable PIE, code signature, DWARF, symbols, and strings. */
    fun buildMinimalMachO64Bytes(
        includeDwarf: Boolean = false,
        localSymbols: List<String> = emptyList(),
        debugStabCount: Int = 0,
        isExecutable: Boolean = false,
        isPie: Boolean = true,
        hasCodeSignature: Boolean = true,
        embeddedStrings: List<String> = emptyList(),
    ): ByteArray {
        val strBuf = ByteArrayOutputStream().apply { write(0) }
        val symRecords = mutableListOf<Pair<Int, Int>>()
        repeat(debugStabCount) { idx ->
            val off = strBuf.size()
            strBuf.write("debug_stab_$idx\u0000".toByteArray(Charsets.UTF_8))
            symRecords += off to 0x20
        }
        for (sym in localSymbols) {
            val off = strBuf.size()
            strBuf.write("$sym\u0000".toByteArray(Charsets.UTF_8))
            symRecords += off to 0x0E
        }
        val strBytes = strBuf.toByteArray()
        val segNames = buildList { add("__TEXT"); if (includeDwarf) add("__DWARF") }
        val ncmds = segNames.size + 1 + (if (hasCodeSignature) 1 else 0)
        val cmdBytesSize = segNames.size * 72 + 24 + (if (hasCodeSignature) 16 else 0)
        val symOff = 32 + cmdBytesSize
        val strOff = symOff + symRecords.size * 16
        val extraPayload = embeddedStrings.joinToString("\u0000").toByteArray(Charsets.UTF_8)
        val total = strOff + strBytes.size + extraPayload.size

        val bytes = ByteArray(total)
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        buf.putInt(0, 0xFEEDFACF.toInt())
        buf.putInt(12, if (isExecutable) 0x2 else 0x6) // MH_EXECUTE vs MH_DYLIB
        buf.putInt(16, ncmds)
        buf.putInt(20, cmdBytesSize)
        buf.putInt(24, if (isPie) 0x00200000 else 0)

        var pos = 32
        for (seg in segNames) {
            buf.putInt(pos, 0x19); buf.putInt(pos + 4, 72)
            seg.toByteArray(Charsets.US_ASCII).copyInto(bytes, pos + 8)
            pos += 72
        }
        buf.putInt(pos, 0x02); buf.putInt(pos + 4, 24)
        buf.putInt(pos + 8, symOff); buf.putInt(pos + 12, symRecords.size)
        buf.putInt(pos + 16, strOff); buf.putInt(pos + 20, strBytes.size)
        pos += 24
        if (hasCodeSignature) {
            buf.putInt(pos, 0x1D); buf.putInt(pos + 4, 16)
        }
        var symPos = symOff
        for ((strx, nType) in symRecords) {
            buf.putInt(symPos, strx); bytes[symPos + 4] = nType.toByte(); symPos += 16
        }
        strBytes.copyInto(bytes, strOff)
        extraPayload.copyInto(bytes, strOff + strBytes.size)
        return bytes
    }

    /** Builds a valid binary Apple Property List (`bplist00`) for ATS tests. */
    fun buildBinaryAtsPlist(
        allowsArbitraryLoads: Boolean,
        insecureExceptionDomain: String? = null,
    ): ByteArray {
        // Object table layout:
        // 0: root dict { "NSAppTransportSecurity": 2 }
        // 1: "NSAppTransportSecurity"
        // 2: ats dict { "NSAllowsArbitraryLoads": 4 [, "NSExceptionDomains": 6] }
        // 3: "NSAllowsArbitraryLoads"
        // 4: bool (true=0x09 / false=0x08)
        // [5: "NSExceptionDomains", 6: dict { 7: 8 }, 7: domain, 8: dict { 9: 10 }, 9: "NSExceptionAllowsInsecureHTTPLoads", 10: true]
        val objects = mutableListOf<ByteArray>()
        fun ascii(s: String): ByteArray {
            val b = s.toByteArray(Charsets.US_ASCII)
            val out = ByteArrayOutputStream()
            if (b.size < 15) {
                out.write(0x50 or b.size)
            } else {
                out.write(0x5F); out.write(0x10); out.write(b.size)
            }
            out.write(b)
            return out.toByteArray()
        }
        fun dict(vararg pairs: Pair<Int, Int>): ByteArray {
            val out = ByteArrayOutputStream()
            out.write(0xD0 or pairs.size)
            pairs.forEach { out.write(it.first) }
            pairs.forEach { out.write(it.second) }
            return out.toByteArray()
        }

        objects += dict(1 to 2)
        objects += ascii("NSAppTransportSecurity")
        if (insecureExceptionDomain != null) {
            objects += dict(3 to 4, 5 to 6)
        } else {
            objects += dict(3 to 4)
        }
        objects += ascii("NSAllowsArbitraryLoads")
        objects += byteArrayOf(if (allowsArbitraryLoads) 0x09 else 0x08)
        if (insecureExceptionDomain != null) {
            objects += ascii("NSExceptionDomains")
            objects += dict(7 to 8)
            objects += ascii(insecureExceptionDomain)
            objects += dict(9 to 10)
            objects += ascii("NSExceptionAllowsInsecureHTTPLoads")
            objects += byteArrayOf(0x09)
        }

        val out = ByteArrayOutputStream()
        out.write("bplist00".toByteArray(Charsets.US_ASCII))
        val offsets = IntArray(objects.size)
        for ((i, obj) in objects.withIndex()) {
            offsets[i] = out.size()
            out.write(obj)
        }
        val offsetTableOffset = out.size().toLong()
        offsets.forEach { off ->
            out.write((off ushr 8) and 0xFF)
            out.write(off and 0xFF)
        }
        val trailer = ByteBuffer.allocate(32).order(ByteOrder.BIG_ENDIAN)
        trailer.put(6, 2) // offsetIntSize = 2
        trailer.put(7, 1) // objectRefSize = 1
        trailer.putLong(8, objects.size.toLong())
        trailer.putLong(16, 0L)
        trailer.putLong(24, offsetTableOffset)
        out.write(trailer.array())
        return out.toByteArray()
    }

    /** Builds a minimal AAB Protobuf `AndroidManifest.xml` for verifying AAB manifest parsing. */
    fun buildProtobufManifest(
        packageName: String,
        debuggable: Boolean,
        exportedServiceName: String? = null,
    ): ByteArray {
        fun protoStr(field: Int, value: String): ByteArray = protoBytes(field, value.toByteArray(Charsets.UTF_8))
        fun protoVarint(field: Int, value: Long): ByteArray = ByteArrayOutputStream().apply {
            writeUleb128(this, (field shl 3) or 0)
            writeUleb128(this, value.toInt())
        }.toByteArray()
        fun protoAttr(name: String, resId: Int, strVal: String? = null, boolVal: Boolean? = null): ByteArray {
            val out = ByteArrayOutputStream()
            out.write(protoStr(2, name))
            if (strVal != null) out.write(protoStr(3, strVal))
            if (resId != 0) out.write(protoVarint(4, resId.toLong()))
            if (boolVal != null) {
                val prim = protoVarint(12, if (boolVal) 1L else 0L)
                val item = protoBytes(4, prim)
                out.write(protoBytes(5, item))
            }
            return out.toByteArray()
        }
        fun protoElement(name: String, attrs: List<ByteArray>, children: List<ByteArray> = emptyList()): ByteArray {
            val elem = ByteArrayOutputStream()
            elem.write(protoStr(2, name))
            attrs.forEach { elem.write(protoBytes(3, it)) }
            children.forEach { elem.write(protoBytes(4, it)) }
            return protoBytes(1, elem.toByteArray())
        }

        val appChildren = buildList {
            if (exportedServiceName != null) {
                add(
                    protoElement(
                        "service",
                        listOf(
                            protoAttr("name", 0x01010003, strVal = exportedServiceName),
                            protoAttr("exported", 0x01010010, boolVal = true),
                        ),
                    ),
                )
            }
        }
        val appNode = protoElement(
            "application",
            listOf(
                protoAttr("debuggable", 0x0101000F, boolVal = debuggable),
                protoAttr("allowBackup", 0x01010280, boolVal = false),
            ),
            appChildren,
        )
        return protoElement(
            "manifest",
            listOf(protoAttr("package", 0, strVal = packageName)),
            listOf(appNode),
        )
    }

    /** Builds a minimal `.awkb` content bundle header (big-endian v1 plaintext or v2 encrypted). */
    fun buildAwkbHeader(version: Int, encrypted: Boolean): ByteArray {
        val bytes = ByteArray(16)
        "AWKB".toByteArray(Charsets.US_ASCII).copyInto(bytes, 0)
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN)
        buf.putShort(4, version.toShort())
        buf.putShort(6, if (encrypted) 1 else 0)
        return bytes
    }

    private fun protoBytes(field: Int, payload: ByteArray): ByteArray = ByteArrayOutputStream().apply {
        writeUleb128(this, (field shl 3) or 2)
        writeUleb128(this, payload.size)
        write(payload)
    }.toByteArray()

    private fun leInt(v: Int): ByteArray = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(v).array()

    private fun writeUleb128(out: ByteArrayOutputStream, value: Int) {
        var v = value
        do {
            var byte = v and 0x7F
            v = v ushr 7
            if (v != 0) byte = byte or 0x80
            out.write(byte)
        } while (v != 0)
    }
}

/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.analyzers

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SpirvShaderInspectorTest {
    @Test
    fun detectsAndLosslesslyStripsDebugOpcodes() {
        val raw = buildSpirvBinary(includeDebug = true)
        assertTrue(SpirvShaderInspector.isSpirv(raw))

        val before = SpirvShaderInspector.inspect("lit.spv", raw)
        assertTrue(before.isValidSpirv)
        assertEquals(1, before.versionMajor)
        assertEquals(5, before.versionMinor)
        assertTrue("OpSource" in before.debugOpcodeNames)
        assertTrue("OpName" in before.debugOpcodeNames)
        assertTrue("OpLine" in before.debugOpcodeNames)
        assertTrue(before.leakedDebugStrings.any { it.contains("secretLighting") || it.contains("main") })

        val stripped = SpirvShaderInspector.stripDebugOpcodes(raw)
        assertTrue(stripped.size < raw.size)
        val after = SpirvShaderInspector.inspect("lit.spv", stripped)
        assertTrue(after.isValidSpirv)
        assertEquals(0, after.debugInstructionCount)
        assertTrue(after.debugOpcodeNames.isEmpty())
        assertEquals(buildSpirvBinary(includeDebug = false).toList(), stripped.toList())
    }

    @Test
    fun rejectsNonSpirvBytes() {
        val invalid = "not-a-spirv-shader".toByteArray()
        assertFalse(SpirvShaderInspector.isSpirv(invalid))
        assertFalse(SpirvShaderInspector.inspect("bad.spv", invalid).isValidSpirv)
    }

    private fun buildSpirvBinary(includeDebug: Boolean): ByteArray {
        val out = ByteArrayOutputStream()
        fun writeWord(word: Int) {
            val buf = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(word)
            out.write(buf.array())
        }
        fun writeStringWords(text: String): List<Int> {
            val raw = text.toByteArray(Charsets.UTF_8) + 0.toByte()
            val paddedSize = ((raw.size + 3) / 4) * 4
            val padded = raw.copyOf(paddedSize)
            val buf = ByteBuffer.wrap(padded).order(ByteOrder.LITTLE_ENDIAN)
            return List(paddedSize / 4) { buf.getInt(it * 4) }
        }
        // SPIR-V 1.5 header (5 words)
        writeWord(0x07230203)
        writeWord(0x00010500)
        writeWord(0)
        writeWord(10)
        writeWord(0)
        // OpCapability Shader (opcode=17, words=2)
        writeWord((2 shl 16) or 17)
        writeWord(1)
        if (includeDebug) {
            // OpSource GLSL 450 0 "secretLighting" (opcode=3)
            val srcWords = writeStringWords("secretLighting.glsl")
            writeWord(((4 + srcWords.size) shl 16) or 3)
            writeWord(2)
            writeWord(450)
            writeWord(0)
            srcWords.forEach(::writeWord)
            // OpName %1 "main" (opcode=5)
            val nameWords = writeStringWords("main")
            writeWord(((2 + nameWords.size) shl 16) or 5)
            writeWord(1)
            nameWords.forEach(::writeWord)
            // OpLine %2 42 1 (opcode=8, words=4)
            writeWord((4 shl 16) or 8)
            writeWord(2)
            writeWord(42)
            writeWord(1)
        }
        // OpReturn (opcode=253, words=1)
        writeWord((1 shl 16) or 253)
        return out.toByteArray()
    }
}

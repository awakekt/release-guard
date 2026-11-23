/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.analyzers

import com.awakekt.releaseguard.model.AssetEncryptionPolicy
import com.awakekt.releaseguard.model.AssetSecurityPolicy
import com.awakekt.releaseguard.model.CheckStatus
import com.awakekt.releaseguard.model.ContainerHeaderRule
import com.awakekt.releaseguard.model.ReleaseGuardPolicy
import com.awakekt.releaseguard.model.ShaderSecurityPolicy
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.util.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ShaderAndAssetAnalyzerTest {
    @Test
    fun flagsRawModelsRenamedGlbMagicCustomContainersAndShaderExposure() {
        val tempDir = Files.createTempDirectory("rg-assets").toFile()
        try {
            val (assetsDir, shadersDir) = createSampleFixtures(tempDir)
            val policy = ReleaseGuardPolicy(
                assetSecurity = AssetSecurityPolicy(enabled = true, allowedPlaintextPathRegexes = listOf("""^public/""")),
                assetEncryption = AssetEncryptionPolicy(
                    enabled = true,
                    customContainerRules = listOf(
                        ContainerHeaderRule(
                            extension = "gpak",
                            expectedMagicAscii = "GPAK",
                            versionOffset = 4,
                            minVersion = 2,
                            flagsOffset = 6,
                            requiredFlagsMask = 0x0001,
                        ),
                    ),
                    minContainerEntropy = 7.0,
                ),
                shaderSecurity = ShaderSecurityPolicy(enabled = true, forbidSpirvDebugInfo = true, forbidWgslComments = true),
            )

            val out = ShaderAndAssetAnalyzer.analyze(
                AssetAuditInput(assetDirectories = listOf(assetsDir), shaderDirectories = listOf(shadersDir)),
                policy,
            )
            val byId = out.findings.associateBy { it.checkId }
            assertEquals(CheckStatus.FAIL, byId.getValue("assets.models.unencrypted_leak").status)
            assertEquals(2, byId.getValue("assets.models.unencrypted_leak").evidence.size)
            assertEquals(CheckStatus.FAIL, byId.getValue("assets.containers.encryption").status)
            assertTrue(byId.getValue("assets.containers.encryption").evidence.single().contains("plaintext.gpak"))
            assertEquals(CheckStatus.FAIL, byId.getValue("shaders.spirv.debug_info").status)
            assertEquals(CheckStatus.FAIL, byId.getValue("shaders.source.exposure").status)
            assertEquals(2, byId.getValue("shaders.source.exposure").evidence.size)
        } finally {
            tempDir.deleteRecursively()
        }
    }

    private fun createSampleFixtures(tempDir: File): Pair<File, File> {
        val assetsDir = File(tempDir, "assets").apply { mkdirs() }
        val glbHeader = byteArrayOf('g'.code.toByte(), 'l'.code.toByte(), 'T'.code.toByte(), 'F'.code.toByte(), 2, 0, 0, 0)
        File(assetsDir, "hero.glb").writeBytes(glbHeader)
        File(assetsDir, "a1b2c3d4").writeBytes(glbHeader)
        File(assetsDir, "public/preview.glb").apply { parentFile.mkdirs(); writeBytes(glbHeader) }

        val goodPak = ByteArray(1024).also { Random(42).nextBytes(it) }
        "GPAK".toByteArray(Charsets.US_ASCII).copyInto(goodPak, 0)
        ByteBuffer.wrap(goodPak).order(ByteOrder.LITTLE_ENDIAN).putShort(4, 2).putShort(6, 1)
        File(assetsDir, "world.gpak").writeBytes(goodPak)

        val badPak = ByteArray(1024) { 'A'.code.toByte() }
        "GPAK".toByteArray(Charsets.US_ASCII).copyInto(badPak, 0)
        ByteBuffer.wrap(badPak).order(ByteOrder.LITTLE_ENDIAN).putShort(4, 2).putShort(6, 1)
        File(assetsDir, "plaintext.gpak").writeBytes(badPak)

        val shadersDir = File(tempDir, "shaders").apply { mkdirs() }
        File(shadersDir, "custom.glsl").writeText("void main() {}")
        File(shadersDir, "water.wgsl").writeText("// secret water shader\n@fragment fn fs() {}")
        File(shadersDir, "debug.spv").writeBytes(minimalSpirvWithOpName())
        return assetsDir to shadersDir
    }

    private fun minimalSpirvWithOpName(): ByteArray {
        val out = ByteArrayOutputStream()
        fun word(v: Int) = out.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(v).array())
        word(0x07230203)
        word(0x00010500)
        word(0)
        word(4)
        word(0)
        // OpName %1 "foo\0" (3 words)
        word((3 shl 16) or 5)
        word(1)
        out.write(byteArrayOf('f'.code.toByte(), 'o'.code.toByte(), 'o'.code.toByte(), 0))
        return out.toByteArray()
    }
}

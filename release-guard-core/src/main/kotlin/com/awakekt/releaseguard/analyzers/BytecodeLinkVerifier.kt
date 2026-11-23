/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.analyzers

import com.awakekt.releaseguard.io.BinaryReadLimits
import java.io.File
import java.net.URLClassLoader
import java.util.zip.ZipFile

/** One class rejected by the JVM bytecode verifier during linking. */
public data class RejectedClass(
    public val jarName: String,
    public val className: String,
    public val reason: String,
)

/** Summary of linking every class across obfuscated desktop game JARs. */
public data class BytecodeVerificationResult(
    public val checkedClasses: Int,
    public val rejectedClasses: List<RejectedClass>,
)

/**
 * Links every class inside obfuscated game JARs against their runtime libraries to catch JVM
 * [VerifyError] failures before shipping installers.
 */
public object BytecodeLinkVerifier {
    /** Links all classes in [gameJars] using [libraryJars] as supporting classpath entries. */
    public fun verify(
        gameJars: List<File>,
        libraryJars: List<File>,
        limits: BinaryReadLimits = BinaryReadLimits(),
    ): BytecodeVerificationResult {
        val gameNames = gameJars.mapTo(HashSet()) { it.name }
        val urls = buildList {
            gameJars.forEach { add(it.toURI().toURL()) }
            libraryJars.filter { it.name !in gameNames }.forEach { add(it.toURI().toURL()) }
        }.toTypedArray()

        var checked = 0
        val rejected = mutableListOf<RejectedClass>()

        URLClassLoader(urls, ClassLoader.getPlatformClassLoader()).use { loader ->
            for (jar in gameJars) {
                checked += verifyJar(jar, loader, rejected, limits)
            }
        }
        return BytecodeVerificationResult(checkedClasses = checked, rejectedClasses = rejected)
    }

    private fun verifyJar(
        jar: File,
        loader: URLClassLoader,
        rejected: MutableList<RejectedClass>,
        limits: BinaryReadLimits,
    ): Int {
        var checked = 0
        var entriesSeen = 0
        ZipFile(jar).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                entriesSeen += 1
                require(entriesSeen <= limits.maxZipEntries) {
                    "JAR '${jar.name}' exceeded maximum entry limit (${limits.maxZipEntries})."
                }
                val name = entry.name
                if (entry.isDirectory || !name.endsWith(".class") || name.endsWith("module-info.class")) continue
                val binaryName = name.removeSuffix(".class").replace('/', '.')
                checked += 1
                val verifyFailure = linkClass(binaryName, loader)
                if (verifyFailure != null) {
                    rejected += RejectedClass(jar.name, binaryName, verifyFailure)
                }
            }
        }
        return checked
    }

    @Suppress("TooGenericExceptionCaught")
    private fun linkClass(binaryName: String, loader: ClassLoader): String? = try {
        Class.forName(binaryName, true, loader)
        null
    } catch (error: VerifyError) {
        error.message.orEmpty().lineSequence().firstOrNull().orEmpty().ifBlank { "VerifyError" }
    } catch (_: Throwable) {
        null
    }
}

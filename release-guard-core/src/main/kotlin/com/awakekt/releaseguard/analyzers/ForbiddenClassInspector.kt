/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.analyzers

import com.awakekt.releaseguard.model.AuditFinding
import com.awakekt.releaseguard.model.AuditTarget
import com.awakekt.releaseguard.model.CheckSeverity
import com.awakekt.releaseguard.model.CheckStatus
import java.io.File

/**
 * Checks whether any forbidden class FQCNs (e.g. dev overlays, debug menus, or offline simulation
 * entrypoints) survived shrinking—inspecting both compiled internal names and an optional
 * ProGuard/R8 `mapping.txt` so classes renamed to `a.b` are still caught.
 */
public object ForbiddenClassInspector {
    private val mappingClassHeaderRegex = Regex("""^([A-Za-z0-9_$.]+)\s+->\s+([A-Za-z0-9_$.]+):$""")

    /** Inspects [compiledInternalNames] and optional [mappingFile] for any [forbiddenClasses]. */
    public fun check(
        checkId: String,
        target: AuditTarget,
        compiledInternalNames: Collection<String>,
        mappingFile: File?,
        forbiddenClasses: List<String>,
    ): AuditFinding {
        if (forbiddenClasses.isEmpty()) {
            return AuditFinding(
                checkId = checkId,
                target = target,
                title = "Forbidden release classes absent",
                status = CheckStatus.SKIP,
                severity = CheckSeverity.CRITICAL,
                weight = 20,
                summary = "No forbidden classes configured.",
            )
        }
        val normalizedTargets = forbiddenClasses
            .map { it.trim().replace('/', '.') }
            .filter { it.isNotEmpty() }
            .toSet()
        val matches = linkedSetOf<String>()

        for (internalName in compiledInternalNames) {
            val dotted = internalName.replace('/', '.')
            if (matchesForbidden(dotted, normalizedTargets)) {
                matches += "bytecode:$dotted"
            }
        }
        scanMappingFile(mappingFile, normalizedTargets, matches)

        val passed = matches.isEmpty()
        return AuditFinding(
            checkId = checkId,
            target = target,
            title = "Forbidden release classes absent",
            status = if (passed) CheckStatus.PASS else CheckStatus.FAIL,
            severity = CheckSeverity.CRITICAL,
            weight = 20,
            summary = if (passed) {
                "Verified ${normalizedTargets.size} forbidden class(es) are absent from release bytecode and mapping."
            } else {
                "Found ${matches.size} forbidden class match(es) surviving in release build."
            },
            evidence = matches.take(10),
            remediation = "Remove runtime references to debug/offline classes in production builds so R8/ProGuard shrinks them completely.",
        )
    }

    private fun scanMappingFile(
        mappingFile: File?,
        normalizedTargets: Set<String>,
        matches: MutableSet<String>,
    ) {
        if (mappingFile == null || !mappingFile.isFile) return
        mappingFile.useLines { lines ->
            lines
                .filter { it.isNotEmpty() && !it.startsWith(' ') && !it.startsWith('#') }
                .mapNotNull { mappingClassHeaderRegex.matchEntire(it.trimEnd()) }
                .forEach { match ->
                    val original = match.groupValues[1]
                    val obfuscated = match.groupValues[2]
                    if (matchesForbidden(original, normalizedTargets)) {
                        matches += "mapping:$original -> $obfuscated"
                    }
                }
        }
    }

    private fun matchesForbidden(candidate: String, forbidden: Set<String>): Boolean =
        forbidden.any { target ->
            candidate == target ||
                candidate.startsWith("$target$") ||
                (target.endsWith(".*") && candidate.startsWith(target.removeSuffix("*")))
        }
}

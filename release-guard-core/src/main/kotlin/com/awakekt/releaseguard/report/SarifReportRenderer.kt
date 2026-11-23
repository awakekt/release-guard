/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.report

import com.awakekt.releaseguard.model.AuditFinding
import com.awakekt.releaseguard.model.CheckSeverity
import com.awakekt.releaseguard.model.CheckStatus
import com.awakekt.releaseguard.model.ReleaseScorecard
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Renders a [ReleaseScorecard] as SARIF 2.1.0 JSON so findings upload directly into GitHub Code
 * Scanning and pull-request Security alerts.
 */
public object SarifReportRenderer {
    private const val SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
    private val json: Json = Json { prettyPrint = true }

    /** Serializes [scorecard] as SARIF 2.1.0 JSON. */
    public fun renderSarif(
        scorecard: ReleaseScorecard,
        toolVersion: String = "0.1.0",
    ): String {
        val actionable = scorecard.findings.filter { it.status == CheckStatus.FAIL || it.status == CheckStatus.WARN }
        val rules = scorecard.findings.distinctBy { it.checkId }
        val root = buildJsonObject {
            put("\$schema", SARIF_SCHEMA)
            put("version", "2.1.0")
            put(
                "runs",
                buildJsonArray {
                    add(
                        buildJsonObject {
                            put("tool", buildToolDriver(rules, toolVersion))
                            put("results", buildResults(actionable))
                        },
                    )
                },
            )
        }
        return json.encodeToString(JsonObject.serializer(), root) + "\n"
    }

    private fun buildToolDriver(rules: List<AuditFinding>, toolVersion: String): JsonObject = buildJsonObject {
        put(
            "driver",
            buildJsonObject {
                put("name", "Release Guard")
                put("informationUri", "https://github.com/awakekt/release-guard")
                put("version", toolVersion)
                put(
                    "rules",
                    buildJsonArray {
                        for (finding in rules) {
                            add(
                                buildJsonObject {
                                    put("id", finding.checkId)
                                    put("name", finding.title)
                                    put("shortDescription", buildJsonObject { put("text", finding.title) })
                                    put(
                                        "help",
                                        buildJsonObject {
                                            put("text", finding.remediation.ifBlank { finding.summary })
                                        },
                                    )
                                    put(
                                        "defaultConfiguration",
                                        buildJsonObject { put("level", mapSeverityLevel(finding.severity, CheckStatus.FAIL)) },
                                    )
                                    put(
                                        "properties",
                                        buildJsonObject {
                                            put("target", finding.target.name)
                                            put("security-severity", mapSecuritySeverityScore(finding.severity))
                                        },
                                    )
                                },
                            )
                        }
                    },
                )
            },
        )
    }

    private fun buildResults(findings: List<AuditFinding>) = buildJsonArray {
        for (finding in findings) {
            val detail = buildString {
                append(finding.summary)
                if (finding.evidence.isNotEmpty()) {
                    append(" Evidence: ")
                    append(finding.evidence.take(5).joinToString(", "))
                }
            }
            add(
                buildJsonObject {
                    put("ruleId", finding.checkId)
                    put("level", mapSeverityLevel(finding.severity, finding.status))
                    put("message", buildJsonObject { put("text", detail) })
                    put(
                        "locations",
                        buildJsonArray {
                            add(
                                buildJsonObject {
                                    put(
                                        "physicalLocation",
                                        buildJsonObject {
                                            put(
                                                "artifactLocation",
                                                buildJsonObject {
                                                    put("uri", finding.target.name.lowercase())
                                                },
                                            )
                                        },
                                    )
                                },
                            )
                        },
                    )
                },
            )
        }
    }

    private fun mapSeverityLevel(severity: CheckSeverity, status: CheckStatus): String = when {
        status == CheckStatus.WARN -> "warning"
        severity == CheckSeverity.CRITICAL || severity == CheckSeverity.HIGH -> "error"
        severity == CheckSeverity.MEDIUM -> "warning"
        else -> "note"
    }

    private fun mapSecuritySeverityScore(severity: CheckSeverity): String = when (severity) {
        CheckSeverity.CRITICAL -> "9.5"
        CheckSeverity.HIGH -> "7.5"
        CheckSeverity.MEDIUM -> "5.0"
        CheckSeverity.LOW -> "2.5"
        CheckSeverity.INFO -> "1.0"
    }
}

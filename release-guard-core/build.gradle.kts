/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
plugins {
    `java-library`
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.vanniktech.publish)
}

kotlin {
    explicitApi()
}

dependencies {
    implementation(libs.kotlinx.serialization.json)

    testImplementation(kotlin("test"))
    testImplementation(libs.junit)
}

mavenPublishing {
    pom {
        name.set("Release Guard Core")
        description.set(
            "Pure-Kotlin release-hardening auditor, binary inspector, web bundle stripper, " +
                "and weighted scorecard engine for KMP apps and games.",
        )
    }
}

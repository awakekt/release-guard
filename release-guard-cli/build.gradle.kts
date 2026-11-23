/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
plugins {
    application
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.vanniktech.publish)
}

kotlin {
    explicitApi()
}

application {
    mainClass.set("com.awakekt.releaseguard.cli.ReleaseGuardCliKt")
}

dependencies {
    api(project(":release-guard-core"))
    implementation(libs.kotlinx.serialization.json)

    testImplementation(kotlin("test"))
    testImplementation(libs.junit)
}

mavenPublishing {
    pom {
        name.set("Release Guard CLI")
        description.set(
            "Standalone CLI for auditing KMP release binaries, stripping web bundles, " +
                "verifying TLS SPKI pins, and exporting HTML/JSON/Markdown/SARIF scorecards.",
        )
    }
}

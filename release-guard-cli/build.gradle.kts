/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
plugins {
    application
    `maven-publish`
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
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

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
            pom {
                name.set("Release Guard CLI")
                description.set(
                    "Standalone CLI for auditing KMP release binaries, stripping web bundles, " +
                        "verifying TLS SPKI pins, and exporting JSON/Markdown/SARIF scorecards.",
                )
                url.set("https://github.com/awakekt/release-guard")
                licenses {
                    license {
                        name.set("Apache-2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
            }
        }
    }
}

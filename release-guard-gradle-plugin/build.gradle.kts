/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
plugins {
    `java-gradle-plugin`
    `maven-publish`
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
}

kotlin {
    explicitApi()
}

dependencies {
    implementation(project(":release-guard-core"))
    implementation(libs.kotlinx.serialization.json)

    compileOnly(libs.kotlin.gradle.plugin)
    compileOnly(libs.android.gradle.plugin)

    testImplementation(kotlin("test"))
    testImplementation(libs.junit)
    testImplementation(gradleTestKit())
}

gradlePlugin {
    website.set("https://github.com/awakekt/release-guard")
    vcsUrl.set("https://github.com/awakekt/release-guard.git")
    plugins {
        create("releaseGuard") {
            id = "com.awakekt.release-guard"
            implementationClass = "com.awakekt.releaseguard.gradle.ReleaseGuardPlugin"
            displayName = "Release Guard Gradle Plugin"
            description =
                "Configurable KMP release hardening, binary verification, and weighted hygiene scoring " +
                "for Desktop JVM, Android APK/AAB, Web WASM/JS, iOS, and TLS."
            tags.set(listOf("kmp", "kotlin", "security", "hardening", "obfuscation", "release", "audit"))
        }
    }
}

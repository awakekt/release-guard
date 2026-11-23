/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
import com.diffplug.gradle.spotless.SpotlessExtension
import dev.detekt.gradle.Detekt
import dev.detekt.gradle.extensions.DetektExtension
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.KotlinJvmProjectExtension

plugins {
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.kotlin.serialization) apply false
    alias(libs.plugins.detekt) apply false
    alias(libs.plugins.spotless) apply false
    alias(libs.plugins.binary.compat)
}

apiValidation {
    ignoredProjects += listOf("release-guard-cli", "release-guard-gradle-plugin")
}

val detektVersion = libs.versions.detekt.get()

subprojects {
    group = rootProject.group
    version = rootProject.version

    apply(plugin = "dev.detekt")
    apply(plugin = "com.diffplug.spotless")

    extensions.configure<DetektExtension> {
        toolVersion.set(detektVersion)
        config.setFrom(rootProject.file("config/detekt/detekt.yml"))
        buildUponDefaultConfig.set(true)
    }

    tasks.withType<Detekt>().matching { it.name == "detekt" }.configureEach {
        setSource(
            fileTree("src") {
                include("**/*.kt")
                exclude("**/build/**")
            },
        )
    }

    extensions.configure<SpotlessExtension> {
        kotlin {
            target("src/**/*.kt")
            targetExclude("**/build/**")
            ktlint("1.7.1").editorConfigOverride(
                mapOf(
                    "ktlint_standard_no-wildcard-imports" to "enabled",
                    "ktlint_standard_max-line-length" to "disabled",
                    "ktlint_standard_function-signature" to "disabled",
                    "ktlint_standard_multiline-expression-wrapping" to "disabled",
                    "ktlint_standard_string-template-indent" to "disabled",
                    "ktlint_standard_statement-wrapping" to "disabled",
                    "ktlint_standard_filename" to "disabled",
                    "ktlint_standard_no-empty-file" to "disabled",
                    "ktlint_standard_value-parameter-comment" to "disabled",
                ),
            )
            licenseHeader(
                """
                /*
                 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
                 *
                 * SPDX-License-Identifier: Apache-2.0
                 */
                """.trimIndent(),
                "^(/\\*\\*|package |@file|import |fun |class |object |interface |val |var |private |internal |public )",
            )
        }
    }

    plugins.withId("org.jetbrains.kotlin.jvm") {
        extensions.configure<JavaPluginExtension> {
            sourceCompatibility = JavaVersion.VERSION_17
            targetCompatibility = JavaVersion.VERSION_17
            withSourcesJar()
        }
        extensions.configure<KotlinJvmProjectExtension> {
            compilerOptions {
                jvmTarget.set(JvmTarget.JVM_17)
            }
        }
    }
}

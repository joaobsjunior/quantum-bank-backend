import kotlinx.kover.gradle.plugin.dsl.CoverageUnit

plugins {
    kotlin("jvm") version "2.2.21"
    kotlin("plugin.spring") version "2.2.21"
    id("org.springframework.boot") version "4.0.6"
    id("io.spring.dependency-management") version "1.1.7"
    id("org.jetbrains.kotlinx.kover") version "0.9.1"
}

group = "com.quantumbank"
version = "0.0.1-SNAPSHOT"

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-oauth2-resource-server")
    implementation("org.springframework.boot:spring-boot-starter-jdbc")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.80")
    implementation("tools.jackson.module:jackson-module-kotlin")
    implementation("org.jetbrains.kotlin:kotlin-reflect")

    runtimeOnly("com.h2database:h2")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.boot:spring-boot-starter-webmvc-test")
    testImplementation("org.springframework.security:spring-security-test")
}

tasks.withType<Test> {
    useJUnitPlatform()
}

// Coverage enforcement (test-coverage-enforcement capability).
// Generates XML + HTML reports and enforces a 100% line-coverage minimum,
// wired into the `check` lifecycle so `./gradlew check` fails below target.
kover {
    reports {
        filters {
            excludes {
                // Reviewed exclusions: Spring Boot bootstrap entrypoint has no
                // testable branching logic (only `runApplication`). Keep this
                // list minimal and justified so 100% stays honest.
                classes(
                    "com.quantumbank.backend.QuantumBankApplication",
                    "com.quantumbank.backend.QuantumBankApplicationKt",
                )
            }
        }
        total {
            xml { onCheck = true }
            html { onCheck = true }
            verify {
                onCheck = true
                rule {
                    bound {
                        minValue = 100
                        coverageUnits = CoverageUnit.LINE
                    }
                }
            }
        }
    }
}

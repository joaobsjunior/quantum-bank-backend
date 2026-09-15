package com.quantumbank.backend.bootstrap

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class BootstrapIdentifiersTest {

    @Test
    fun acceptsCanonicalIdentifiers() {
        assertThat(BootstrapIdentifiers.isClientIdentifier("app-local-001")).isTrue()
        assertThat(BootstrapIdentifiers.isClientIdentifier("Device_01.beta")).isTrue()
        assertThat(BootstrapIdentifiers.isCertificateProfile("quantum-bank-mobile-client-v1")).isTrue()
        assertThat(BootstrapIdentifiers.isEnvironment("local")).isTrue()
        assertThat(BootstrapIdentifiers.isSubject("00000000-0000-0000-0000-000000000001")).isTrue()
        assertThat(BootstrapIdentifiers.isSubject("alice@quantumbank.local")).isTrue()
    }

    @Test
    fun rejectsOpenSslConfigurationAndLogInjectionPayloads() {
        listOf(
            "device\n[v3_client]\nbasicConstraints=CA:TRUE",
            "device # comment",
            "device \${ENV::HOME}",
            "device\"quoted\"",
            "",
            "-leading-dash",
            "x".repeat(65),
        ).forEach { value ->
            assertThat(BootstrapIdentifiers.isClientIdentifier(value)).`as`(value).isFalse()
        }
        assertThat(BootstrapIdentifiers.isCertificateProfile("Profile With Spaces")).isFalse()
        assertThat(BootstrapIdentifiers.isEnvironment("prod\n")).isFalse()
        assertThat(BootstrapIdentifiers.isSubject("alice\nmallory")).isFalse()
        assertThat(BootstrapIdentifiers.isSubject("a".repeat(161))).isFalse()
    }
}

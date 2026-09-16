package com.quantumbank.backend.security

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path

class BackendMtlsX509Test {

    @Test
    fun x509TransportIsConfiguredWithoutReplacingJwtResourceServer() {
        val securityConfig = Files.readString(
            Path.of("src/main/kotlin/com/quantumbank/backend/security/SecurityConfig.kt"),
        )

        assertThat(securityConfig).contains(".x509")
        assertThat(securityConfig).contains("authenticationUserDetailsService")
        assertThat(securityConfig).contains("oauth2ResourceServer")
        assertThat(securityConfig).contains(".jwt { }")
        assertThat(securityConfig).contains("scope(\"pix:write\")")
        assertThat(securityConfig).contains("scope(\"statements:read\")")
        assertThat(securityConfig).contains("scope(\"profile:read\")")
    }

    @Test
    fun backendSslRequiresClientAuthenticationWhenEnabled() {
        val applicationYaml = Files.readString(Path.of("src/main/resources/application.yml"))

        assertThat(applicationYaml).contains("server:")
        assertThat(applicationYaml).contains("ssl:")
        assertThat(applicationYaml).contains("client-auth: NEED")
        assertThat(applicationYaml).contains("trust-store-type: PKCS12")
        assertThat(applicationYaml).contains("key-store-type: PKCS12")
        assertThat(applicationYaml).contains("enabled-protocols: TLSv1.3")
        assertThat(applicationYaml).contains("ciphers: TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_AES_128_GCM_SHA256")
    }

    @Test
    fun postQuantumTlsIsInstalledBeforeAnySocketExists() {
        val application = Files.readString(Path.of("src/main/kotlin/com/quantumbank/backend/QuantumBankApplication.kt"))
        val configuration = Files.readString(Path.of("src/main/kotlin/com/quantumbank/backend/security/PostQuantumTlsConfiguration.kt"))

        assertThat(application).contains("PostQuantumTls.install()")
        assertThat(application.indexOf("PostQuantumTls.install()")).isLessThan(application.indexOf("runApplication<QuantumBankApplication>"))
        assertThat(configuration).contains("@Configuration")
        assertThat(configuration).contains("PostQuantumTls.install()")
    }

    @Test
    fun contractDocumentsHandshakeFailureAndJwtIdentityBoundary() {
        val contract = Files.readString(Path.of("docs/contracts/oauth2-backend-policy.md"))

        assertThat(contract).contains("MTLS-02")
        assertThat(contract).contains("JWT remains the authoritative user identity")
        assertThat(contract).contains("handshake failure")
        assertThat(contract).contains("ML-DSA")
        assertThat(contract).contains("X25519MLKEM768")
    }
}

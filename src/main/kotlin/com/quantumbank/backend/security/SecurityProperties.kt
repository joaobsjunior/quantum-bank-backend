package com.quantumbank.backend.security

import org.springframework.boot.context.properties.ConfigurationProperties
import java.time.Duration

@ConfigurationProperties(prefix = "quantum-bank.security")
data class SecurityProperties(
    val issuerUri: String = "https://localhost:8180/realms/quantum-bank-local",
    val jwkSetUri: String = "https://localhost:8180/realms/quantum-bank-local/protocol/openid-connect/certs",
    val audience: String = SecurityConfig.ACCEPTED_AUDIENCE,
    val clockSkew: Duration = Duration.ofSeconds(60),
    val otkTtl: Duration = Duration.ofMinutes(5),
    /** Hard cap on OTK records kept in memory; issuance fails closed above it. */
    val otkMaxRecords: Int = 10_000,
    /** How long a non-issued OTK record is retained for audit/replay detection after expiry. */
    val otkRetention: Duration = Duration.ofHours(1),
    val certificateProfile: String = "quantum-bank-mobile-client-v1",
    val environment: String = "local",
    val pki: PkiProperties = PkiProperties(),
    val mtls: MtlsProperties = MtlsProperties(),
) {
    init {
        // Fail closed: only the explicitly local environment may fetch issuer
        // metadata and signing keys over plaintext HTTP.
        if (environment != LOCAL_ENVIRONMENT) {
            require(issuerUri.startsWith("https://")) {
                "quantum-bank.security.issuer-uri must use https outside the local environment"
            }
            require(jwkSetUri.startsWith("https://")) {
                "quantum-bank.security.jwk-set-uri must use https outside the local environment"
            }
        }
        require(otkMaxRecords > 0) { "quantum-bank.security.otk-max-records must be positive" }
    }

    data class PkiProperties(
        val signCommand: String = "../pki/scripts/sign-csr.sh",
        val issuingCert: String = "../pki/local-ca/trust/issuing-ca.crt",
        val signTimeout: Duration = Duration.ofSeconds(30),
    )

    /**
     * Gateway-only enforcement at the transport layer. When enabled, every
     * request must present a client certificate whose CN is in the allow list,
     * so a leaked mobile or service certificate cannot bypass KrakenD.
     */
    data class MtlsProperties(
        val enforceGatewayIdentity: Boolean = false,
        val allowedClientNames: List<String> = listOf("gateway-client"),
    )

    companion object {
        const val LOCAL_ENVIRONMENT = "local"
    }
}

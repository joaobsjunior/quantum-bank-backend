package com.quantumbank.backend.security

import org.springframework.boot.context.properties.ConfigurationProperties
import java.time.Duration

@ConfigurationProperties(prefix = "quantum-bank.security")
data class SecurityProperties(
    val issuerUri: String = "http://localhost:8180/realms/quantum-bank-local",
    val jwkSetUri: String = "http://localhost:8180/realms/quantum-bank-local/protocol/openid-connect/certs",
    val audience: String = SecurityConfig.ACCEPTED_AUDIENCE,
    val clockSkew: Duration = Duration.ofSeconds(60),
    val otkTtl: Duration = Duration.ofMinutes(5),
    val certificateProfile: String = "quantum-bank-mobile-client-v1",
    val environment: String = "local",
    val pki: PkiProperties = PkiProperties(),
) {
    data class PkiProperties(
        val signCommand: String = "../pki/scripts/sign-csr.sh",
        val issuingCert: String = "../pki/local-ca/trust/issuing-ca.crt",
        val signTimeout: Duration = Duration.ofSeconds(30),
    )
}

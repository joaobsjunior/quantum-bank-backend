package com.quantumbank.backend.security

import org.springframework.boot.context.properties.ConfigurationProperties
import java.time.Duration

@ConfigurationProperties(prefix = "quantum-bank.security")
data class SecurityProperties(
    val issuerUri: String = "http://localhost:8180/realms/quantum-bank-local",
    val jwkSetUri: String = "http://localhost:8180/realms/quantum-bank-local/protocol/openid-connect/certs",
    val audience: String = SecurityConfig.ACCEPTED_AUDIENCE,
    val clockSkew: Duration = Duration.ofSeconds(60),
)

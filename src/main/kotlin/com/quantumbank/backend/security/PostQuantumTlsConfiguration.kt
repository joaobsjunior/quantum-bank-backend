package com.quantumbank.backend.security

import org.springframework.context.annotation.Configuration

/**
 * Guarantees the post-quantum TLS policy is installed before the embedded
 * Tomcat connector or any outbound TLS client (JWK-set retrieval) is created,
 * even when the application context is started without `main` (tests,
 * embedded launchers).
 */
@Configuration
class PostQuantumTlsConfiguration {
    init {
        PostQuantumTls.install()
    }
}

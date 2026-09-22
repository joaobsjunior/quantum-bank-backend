package com.quantumbank.backend

import com.quantumbank.backend.envelope.EnvelopeProperties
import com.quantumbank.backend.security.PostQuantumTls
import com.quantumbank.backend.security.SecurityProperties
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.runApplication

@SpringBootApplication
@EnableConfigurationProperties(SecurityProperties::class, EnvelopeProperties::class)
class QuantumBankApplication

fun main(args: Array<String>) {
    // Post-quantum TLS must be in place before any socket exists.
    PostQuantumTls.install()
    runApplication<QuantumBankApplication>(*args)
}

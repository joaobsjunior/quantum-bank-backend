package com.quantumbank.backend

import com.quantumbank.backend.security.SecurityProperties
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.runApplication

@SpringBootApplication
@EnableConfigurationProperties(SecurityProperties::class)
class QuantumBankApplication

fun main(args: Array<String>) {
    runApplication<QuantumBankApplication>(*args)
}

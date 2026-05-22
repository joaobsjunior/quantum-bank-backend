package com.quantumbank.backend.security

import org.springframework.security.oauth2.jwt.Jwt

fun Jwt.quantumBankSubject(): String =
    getClaimAsString("sub")
        ?: getClaimAsString("preferred_username")
        ?: getClaimAsString("azp")
        ?: throw IllegalArgumentException("JWT has no stable Quantum Bank subject claim")

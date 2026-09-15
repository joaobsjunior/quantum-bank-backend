package com.quantumbank.backend.security

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import org.springframework.security.oauth2.jwt.Jwt
import java.time.Instant

class JwtSubjectTest {

    @Test
    fun usesTheSubClaimOnly() {
        val jwt = jwt(mapOf("sub" to "00000000-0000-0000-0000-000000000001", "azp" to "quantum-bank-test"))

        assertThat(jwt.quantumBankSubject()).isEqualTo("00000000-0000-0000-0000-000000000001")
    }

    @Test
    fun neverFallsBackToUsernameOrClientIdClaims() {
        listOf(
            mapOf("preferred_username" to "alice@quantumbank.local"),
            mapOf("azp" to "quantum-bank-test"),
            mapOf("scope" to "pix:write"),
        ).forEach { claims ->
            assertThatThrownBy { jwt(claims).quantumBankSubject() }
                .isInstanceOf(InvalidJwtSubjectException::class.java)
                .hasMessageContaining("no sub claim")
        }
    }

    @Test
    fun rejectsSubjectsOutsideTheCanonicalCharset() {
        listOf("alice\nmallory", "alice mallory", "", "a".repeat(161), "-leading").forEach { subject ->
            assertThatThrownBy { jwt(mapOf("sub" to subject)).quantumBankSubject() }
                .`as`(subject)
                .isInstanceOf(InvalidJwtSubjectException::class.java)
                .hasMessageContaining("unsupported format")
        }
    }

    private fun jwt(claims: Map<String, Any>): Jwt {
        val now = Instant.now()
        return Jwt(
            "token",
            now,
            now.plusSeconds(300),
            mapOf("alg" to "RS256"),
            claims,
        )
    }
}

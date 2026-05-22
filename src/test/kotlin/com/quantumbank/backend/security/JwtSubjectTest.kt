package com.quantumbank.backend.security

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import org.springframework.security.oauth2.jwt.Jwt
import java.time.Instant

class JwtSubjectTest {

    @Test
    fun prefersSubClaimWhenPresent() {
        val jwt = jwt(mapOf("sub" to "alice-sub", "azp" to "quantum-bank-test"))

        assertThat(jwt.quantumBankSubject()).isEqualTo("alice-sub")
    }

    @Test
    fun fallsBackToPreferredUsernameThenAuthorizedPartyForLocalTokens() {
        assertThat(jwt(mapOf("preferred_username" to "alice@quantumbank.local")).quantumBankSubject())
            .isEqualTo("alice@quantumbank.local")

        assertThat(jwt(mapOf("azp" to "quantum-bank-test")).quantumBankSubject())
            .isEqualTo("quantum-bank-test")
    }

    @Test
    fun rejectsTokensWithoutStableIdentityClaims() {
        assertThatThrownBy { jwt(mapOf("scope" to "pix:write")).quantumBankSubject() }
            .isInstanceOf(IllegalArgumentException::class.java)
            .hasMessageContaining("stable Quantum Bank subject")
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

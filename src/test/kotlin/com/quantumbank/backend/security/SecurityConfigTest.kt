package com.quantumbank.backend.security

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.mockito.Mockito
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken
import java.time.Instant

class SecurityConfigTest {

    private val config = SecurityConfig(
        SecurityProperties(),
        Mockito.mock(ProblemDetailsAuthenticationEntryPoint::class.java),
        Mockito.mock(ProblemDetailsAccessDeniedHandler::class.java),
    )

    @Test
    fun mtlsUserDetailsServiceGrantsMtlsRole() {
        val token = PreAuthenticatedAuthenticationToken("CN=client-001", "n/a")

        val details = config.mtlsUserDetailsService().loadUserDetails(token)

        assertThat(details.username).isEqualTo("CN=client-001")
        assertThat(details.authorities.map { it.authority }).containsExactly("ROLE_MTLS_CLIENT")
    }

    @Test
    fun audienceValidatorAcceptsExpectedAudience() {
        val validator = config.audienceValidator(SecurityConfig.ACCEPTED_AUDIENCE)

        val result = validator.validate(jwt(audience = listOf(SecurityConfig.ACCEPTED_AUDIENCE)))

        assertThat(result.hasErrors()).isFalse()
    }

    @Test
    fun audienceValidatorRejectsMissingAudience() {
        val validator = config.audienceValidator(SecurityConfig.ACCEPTED_AUDIENCE)

        val result = validator.validate(jwt(audience = listOf("some-other-api")))

        assertThat(result.hasErrors()).isTrue()
    }

    @Test
    fun jwtDecoderIsConfigured() {
        assertThat(config.jwtDecoder()).isNotNull()
    }

    private fun jwt(audience: List<String>): Jwt {
        val now = Instant.now()
        return Jwt.withTokenValue("token")
            .header("alg", "RS256")
            .subject("alice@quantumbank.local")
            .audience(audience)
            .issuedAt(now.minusSeconds(30))
            .expiresAt(now.plusSeconds(300))
            .claim("scope", "profile:read")
            .build()
    }
}

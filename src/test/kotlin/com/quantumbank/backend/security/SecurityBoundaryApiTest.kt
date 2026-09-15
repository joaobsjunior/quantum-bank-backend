package com.quantumbank.backend.security

import org.hamcrest.Matchers.equalTo
import org.hamcrest.Matchers.not
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.context.TestConfiguration
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Primary
import org.springframework.http.HttpHeaders
import org.springframework.security.oauth2.jwt.BadJwtException
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.header
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.time.Instant

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecurityBoundaryApiTest {

    @Autowired
    private lateinit var mockMvc: MockMvc

    @Test
    fun tokensWithoutSubClaimAreRejectedWithProblemDetails() {
        mockMvc.perform(get("/profile").header(HttpHeaders.AUTHORIZATION, "Bearer no-sub-token"))
            .andExpect(status().isUnauthorized)
            .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
            .andExpect(jsonPath("$.errorCode", equalTo("auth_invalid_token")))
            .andExpect(jsonPath("$.instance", equalTo("/profile")))
    }

    @Test
    fun unmappedRoutesAreDeniedEvenForAuthenticatedCallers() {
        mockMvc.perform(get("/actuator/health").header(HttpHeaders.AUTHORIZATION, "Bearer profile-read-token"))
            .andExpect(status().isForbidden)
            .andExpect(jsonPath("$.errorCode", equalTo("auth_missing_scope")))

        mockMvc.perform(get("/h2-console"))
            .andExpect(status().isUnauthorized)
    }

    @Test
    fun unsafeCorrelationIdsAreReplacedInsteadOfEchoed() {
        val unsafe = "corr with spaces; injected=true"
        mockMvc.perform(
            get("/profile")
                .header(HttpHeaders.AUTHORIZATION, "Bearer profile-read-token")
                .header(CORRELATION_ID_HEADER, unsafe),
        )
            .andExpect(status().isOk)
            .andExpect(header().string(CORRELATION_ID_HEADER, not(unsafe)))
            .andExpect(jsonPath("$.correlationId", not(unsafe)))

        mockMvc.perform(
            get("/profile")
                .header(HttpHeaders.AUTHORIZATION, "Bearer profile-read-token")
                .header(CORRELATION_ID_HEADER, "corr-safe-001"),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.correlationId", equalTo("corr-safe-001")))
    }

    @TestConfiguration
    class TestJwtConfiguration {
        @Bean
        @Primary
        fun testJwtDecoder(): JwtDecoder =
            JwtDecoder { token ->
                when (token) {
                    "profile-read-token" -> jwt(token, subject = "alice@quantumbank.local")
                    "no-sub-token" -> jwt(token, subject = null)
                    else -> throw BadJwtException("unknown token")
                }
            }

        private fun jwt(token: String, subject: String?): Jwt {
            val now = Instant.now()
            val builder = Jwt.withTokenValue(token)
                .header("alg", "RS256")
                .issuer("http://localhost:8180/realms/quantum-bank-local")
                .audience(listOf("quantum-bank-api"))
                .issuedAt(now.minusSeconds(30))
                .expiresAt(now.plusSeconds(300))
                .claim("azp", "quantum-bank-mobile")
                .claim("preferred_username", "alice@quantumbank.local")
                .claim("scope", "profile:read")
            if (subject != null) {
                builder.subject(subject)
            }
            return builder.build()
        }
    }
}

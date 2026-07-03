package com.quantumbank.backend.bootstrap

import org.hamcrest.Matchers.equalTo
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.context.TestConfiguration
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Primary
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.security.oauth2.jwt.BadJwtException
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.time.Instant

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class BootstrapProblemDetailsTest {

    @Autowired
    private lateinit var mockMvc: MockMvc

    @Test
    fun blankRequestFieldsReturnRequestInvalidProblem() {
        mockMvc.perform(
            post("/auth/csr")
                .header(HttpHeaders.AUTHORIZATION, "Bearer profile-read-token")
                .header("X-Correlation-Id", "corr-provided-123")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {
                      "otk": "",
                      "csr": "",
                      "appInstanceId": "",
                      "deviceId": ""
                    }
                    """.trimIndent(),
                ),
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.errorCode", equalTo("request_invalid")))
            .andExpect(jsonPath("$.correlationId", equalTo("corr-provided-123")))
    }

    @Test
    fun malformedJsonReturnsRequestInvalidProblem() {
        mockMvc.perform(
            post("/auth/otk")
                .header(HttpHeaders.AUTHORIZATION, "Bearer profile-read-token")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{ not-json"),
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.errorCode", equalTo("request_invalid")))
    }

    @TestConfiguration
    class TestJwtConfiguration {
        @Bean
        @Primary
        fun testJwtDecoder(): JwtDecoder =
            JwtDecoder { token ->
                when (token) {
                    "profile-read-token" -> jwt(token)
                    else -> throw BadJwtException("unknown token")
                }
            }

        private fun jwt(token: String): Jwt {
            val now = Instant.now()
            return Jwt.withTokenValue(token)
                .header("alg", "RS256")
                .issuer("http://localhost:8180/realms/quantum-bank-local")
                .subject("alice@quantumbank.local")
                .audience(listOf("quantum-bank-api"))
                .issuedAt(now.minusSeconds(30))
                .expiresAt(now.plusSeconds(300))
                .claim("scope", "profile:read")
                .build()
        }
    }
}

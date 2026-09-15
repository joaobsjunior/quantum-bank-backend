package com.quantumbank.backend.banking

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
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.time.Instant

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class RequestValidationApiTest {

    @Autowired
    private lateinit var mockMvc: MockMvc

    @Test
    fun pixRejectsOversizedAmountsAndFields() {
        listOf(
            """{"amount": 1000000.01, "recipientKey": "r@example.com", "scenario": "SUCCESS"}""",
            """{"amount": 10.001, "recipientKey": "r@example.com", "scenario": "SUCCESS"}""",
            """{"amount": 10.00, "recipientKey": "${"r".repeat(161)}", "scenario": "SUCCESS"}""",
            """{"amount": 10.00, "recipientKey": "r@example.com", "description": "${"d".repeat(241)}", "scenario": "SUCCESS"}""",
        ).forEach { body ->
            mockMvc.perform(
                post("/pix/transfers")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer all-scopes-token")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(body),
            )
                .andExpect(status().isBadRequest)
                .andExpect(jsonPath("$.errorCode", equalTo("request_invalid")))
        }
    }

    @Test
    fun profileRejectsFieldsLongerThanTheirColumns() {
        mockMvc.perform(
            put("/profile")
                .header(HttpHeaders.AUTHORIZATION, "Bearer all-scopes-token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {
                      "fullName": "${"n".repeat(161)}",
                      "email": "alice@quantumbank.local",
                      "phone": "+55 71 90000-0001",
                      "address": "Rua"
                    }
                    """.trimIndent(),
                ),
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.errorCode", equalTo("request_invalid")))
    }

    @Test
    fun bootstrapRejectsIdentifiersThatCouldReachTheOpenSslConfiguration() {
        mockMvc.perform(
            post("/auth/otk")
                .header(HttpHeaders.AUTHORIZATION, "Bearer all-scopes-token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {
                      "appInstanceId": "app-local-001",
                      "deviceId": "device\n[v3_client]\nbasicConstraints=CA:TRUE",
                      "certificateProfile": "quantum-bank-mobile-client-v1"
                    }
                    """.trimIndent(),
                ),
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.errorCode", equalTo("request_invalid")))

        mockMvc.perform(
            post("/auth/csr")
                .header(HttpHeaders.AUTHORIZATION, "Bearer all-scopes-token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {
                      "otk": "not a token",
                      "csr": "-----BEGIN CERTIFICATE REQUEST-----",
                      "appInstanceId": "app-local-001",
                      "deviceId": "device-local-001",
                      "environment": "local\n"
                    }
                    """.trimIndent(),
                ),
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
                    "all-scopes-token" -> {
                        val now = Instant.now()
                        Jwt.withTokenValue(token)
                            .header("alg", "RS256")
                            .issuer("http://localhost:8180/realms/quantum-bank-local")
                            .subject("alice@quantumbank.local")
                            .audience(listOf("quantum-bank-api"))
                            .issuedAt(now.minusSeconds(30))
                            .expiresAt(now.plusSeconds(300))
                            .claim("scope", "pix:write profile:read profile:write statements:read")
                            .build()
                    }
                    else -> throw BadJwtException("unknown token")
                }
            }
    }
}

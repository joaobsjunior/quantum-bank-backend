package com.quantumbank.backend.banking

import org.hamcrest.Matchers.equalTo
import org.hamcrest.Matchers.notNullValue
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
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.time.Instant

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class PixApiTest {

    @Autowired
    private lateinit var mockMvc: MockMvc

    @Test
    fun pixSuccessScenarioReturnsCompletedTransfer() {
        mockMvc.perform(
            post("/pix/transfers")
                .header(HttpHeaders.AUTHORIZATION, "Bearer pix-write-token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {
                      "amount": 25.30,
                      "recipientKey": "recipient@example.com",
                      "description": "Local success",
                      "scenario": "SUCCESS"
                    }
                    """.trimIndent(),
                ),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.transactionId", notNullValue()))
            .andExpect(jsonPath("$.status", equalTo("COMPLETED")))
            .andExpect(jsonPath("$.amount", equalTo(25.30)))
            .andExpect(jsonPath("$.correlationId", notNullValue()))
    }

    @Test
    fun pixSuccessScenarioCreatesStatementDebitEntry() {
        mockMvc.perform(
            post("/pix/transfers")
                .header(HttpHeaders.AUTHORIZATION, "Bearer banking-flow-token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {
                      "amount": 25.30,
                      "recipientKey": "recipient@example.com",
                      "description": "Pix para atualizar extrato",
                      "scenario": "SUCCESS"
                    }
                    """.trimIndent(),
                ),
        )
            .andExpect(status().isOk)

        mockMvc.perform(get("/statements").header(HttpHeaders.AUTHORIZATION, "Bearer banking-flow-token"))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.entries[0].description", equalTo("Pix para atualizar extrato")))
            .andExpect(jsonPath("$.entries[0].amount", equalTo(-25.30)))
            .andExpect(jsonPath("$.entries[0].type", equalTo("DEBIT")))
    }

    @Test
    fun pixErrorScenarioReturnsStructuredProblemDetails() {
        mockMvc.perform(
            post("/pix/transfers")
                .header(HttpHeaders.AUTHORIZATION, "Bearer pix-write-token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {
                      "amount": 25.30,
                      "recipientKey": "recipient@example.com",
                      "description": "Local error",
                      "scenario": "ERROR"
                    }
                    """.trimIndent(),
                ),
        )
            .andExpect(status().`is`(422))
            .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
            .andExpect(jsonPath("$.errorCode", equalTo("pix_simulated_error")))
            .andExpect(jsonPath("$.correlationId", notNullValue()))
    }

    @TestConfiguration
    class TestJwtConfiguration {
        @Bean
        @Primary
        fun testJwtDecoder(): JwtDecoder =
            JwtDecoder { token ->
                when (token) {
                    "pix-write-token" -> jwt(token, scopes = listOf("pix:write"))
                    "banking-flow-token" -> jwt(token, scopes = listOf("pix:write", "statements:read"))
                    else -> throw BadJwtException("unknown token")
                }
            }

        private fun jwt(token: String, scopes: List<String>): Jwt {
            val now = Instant.now()
            return Jwt.withTokenValue(token)
                .header("alg", "RS256")
                .issuer("http://localhost:8180/realms/quantum-bank-local")
                .subject("alice@quantumbank.local")
                .audience(listOf("quantum-bank-api"))
                .issuedAt(now.minusSeconds(30))
                .expiresAt(now.plusSeconds(300))
                .claim("scope", scopes.joinToString(" "))
                .build()
        }
    }
}

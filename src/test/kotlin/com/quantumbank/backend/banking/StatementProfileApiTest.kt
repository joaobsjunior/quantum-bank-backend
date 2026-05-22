package com.quantumbank.backend.banking

import org.hamcrest.Matchers.equalTo
import org.hamcrest.Matchers.greaterThanOrEqualTo
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
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.time.Instant

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class StatementProfileApiTest {

    @Autowired
    private lateinit var mockMvc: MockMvc

    @Test
    fun returnsStatementFixturesForAuthenticatedSubject() {
        mockMvc.perform(get("/statements").header(HttpHeaders.AUTHORIZATION, "Bearer statements-read-token"))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.entries.length()", greaterThanOrEqualTo(2)))
            .andExpect(jsonPath("$.entries[0].description", notNullValue()))
            .andExpect(jsonPath("$.correlationId", notNullValue()))
    }

    @Test
    fun returnsAndUpdatesProfileWithWriteScope() {
        mockMvc.perform(get("/profile").header(HttpHeaders.AUTHORIZATION, "Bearer profile-read-token"))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.subject", equalTo("alice@quantumbank.local")))
            .andExpect(jsonPath("$.fullName", notNullValue()))

        mockMvc.perform(
            put("/profile")
                .header(HttpHeaders.AUTHORIZATION, "Bearer profile-write-token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {
                      "fullName": "Alice Quantum Editable",
                      "email": "alice.editable@quantumbank.local",
                      "phone": "+55 71 90000-0100",
                      "address": "Rua Perfil Editado, 300 - Salvador, BA"
                    }
                    """.trimIndent(),
                ),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.fullName", equalTo("Alice Quantum Editable")))
            .andExpect(jsonPath("$.email", equalTo("alice.editable@quantumbank.local")))
            .andExpect(jsonPath("$.correlationId", notNullValue()))
    }

    @Test
    fun profileWriteRequiresProfileWriteScope() {
        mockMvc.perform(
            put("/profile")
                .header(HttpHeaders.AUTHORIZATION, "Bearer profile-read-token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {
                      "fullName": "Alice Quantum Editable",
                      "email": "alice.editable@quantumbank.local",
                      "phone": "+55 71 90000-0100",
                      "address": "Rua Perfil Editado, 300 - Salvador, BA"
                    }
                    """.trimIndent(),
                ),
        )
            .andExpect(status().isForbidden)
    }

    @TestConfiguration
    class TestJwtConfiguration {
        @Bean
        @Primary
        fun testJwtDecoder(): JwtDecoder =
            JwtDecoder { token ->
                when (token) {
                    "statements-read-token" -> jwt(token, scopes = listOf("statements:read"))
                    "profile-read-token" -> jwt(token, scopes = listOf("profile:read"))
                    "profile-write-token" -> jwt(token, scopes = listOf("profile:write"))
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

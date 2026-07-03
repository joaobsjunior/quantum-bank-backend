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
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.time.Instant

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class ProfileNotFoundTest {

    @Autowired
    private lateinit var mockMvc: MockMvc

    @Test
    fun getProfileReturnsNotFoundWhenSubjectHasNoFixture() {
        mockMvc.perform(get("/profile").header(HttpHeaders.AUTHORIZATION, "Bearer ghost-read-token"))
            .andExpect(status().isNotFound)
            .andExpect(jsonPath("$.errorCode", equalTo("profile_not_found")))
    }

    @Test
    fun updateProfileReturnsNotFoundWhenSubjectHasNoFixture() {
        mockMvc.perform(
            put("/profile")
                .header(HttpHeaders.AUTHORIZATION, "Bearer ghost-write-token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {
                      "fullName": "Ghost User",
                      "email": "ghost@quantumbank.local",
                      "phone": "+55 71 90000-0000",
                      "address": "Rua Fantasma, 1 - Salvador, BA"
                    }
                    """.trimIndent(),
                ),
        )
            .andExpect(status().isNotFound)
            .andExpect(jsonPath("$.errorCode", equalTo("profile_not_found")))
    }

    @TestConfiguration
    class TestJwtConfiguration {
        @Bean
        @Primary
        fun testJwtDecoder(): JwtDecoder =
            JwtDecoder { token ->
                when (token) {
                    "ghost-read-token" -> jwt(token, scopes = listOf("profile:read"))
                    "ghost-write-token" -> jwt(token, scopes = listOf("profile:write"))
                    else -> throw BadJwtException("unknown token")
                }
            }

        private fun jwt(token: String, scopes: List<String>): Jwt {
            val now = Instant.now()
            return Jwt.withTokenValue(token)
                .header("alg", "RS256")
                .issuer("http://localhost:8180/realms/quantum-bank-local")
                .subject("ghost@quantumbank.local")
                .audience(listOf("quantum-bank-api"))
                .issuedAt(now.minusSeconds(30))
                .expiresAt(now.plusSeconds(300))
                .claim("scope", scopes.joinToString(" "))
                .build()
        }
    }
}

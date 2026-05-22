package com.quantumbank.backend.security

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
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.time.Instant

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class BackendJwtSecurityTest {

    @Autowired
    private lateinit var mockMvc: MockMvc

    private val protectedRoutes = listOf(
        Route("POST", "/auth/otk"),
        Route("POST", "/auth/csr"),
        Route("POST", "/pix/transfers"),
        Route("GET", "/statements"),
        Route("GET", "/profile"),
    )

    @Test
    fun missingToken() {
        protectedRoutes.forEach { route ->
            mockMvc.perform(route.request())
                .andExpect(status().isUnauthorized)
                .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
                .andExpect(jsonPath("$.errorCode", equalTo("auth_invalid_token")))
                .andExpect(jsonPath("$.correlationId").exists())
        }
    }

    @Test
    fun malformedToken() {
        protectedRoutes.forEach { route ->
            mockMvc.perform(route.request("malformed-token"))
                .andExpect(status().isUnauthorized)
                .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
                .andExpect(jsonPath("$.errorCode", equalTo("auth_invalid_token")))
        }
    }

    @Test
    fun expiredToken() {
        protectedRoutes.forEach { route ->
            mockMvc.perform(route.request("expired-token"))
                .andExpect(status().isUnauthorized)
                .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
                .andExpect(jsonPath("$.errorCode", equalTo("auth_invalid_token")))
        }
    }

    @Test
    fun wrongIssuer() {
        protectedRoutes.forEach { route ->
            mockMvc.perform(route.request("wrong-issuer-token"))
                .andExpect(status().isUnauthorized)
                .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
                .andExpect(jsonPath("$.errorCode", equalTo("auth_invalid_token")))
        }
    }

    @Test
    fun wrongAudience() {
        protectedRoutes.forEach { route ->
            mockMvc.perform(route.request("wrong-audience-token"))
                .andExpect(status().isUnauthorized)
                .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
                .andExpect(jsonPath("$.errorCode", equalTo("auth_invalid_token")))
        }
    }

    @Test
    fun missingScope() {
        mockMvc.perform(post("/pix/transfers").withBearer("openid-profile-token"))
            .andExpect(status().isForbidden)
            .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
            .andExpect(jsonPath("$.errorCode", equalTo("auth_missing_scope")))
            .andExpect(jsonPath("$.correlationId").exists())
    }

    @Test
    fun validScopedTokensReachSecuredStubs() {
        mockMvc.perform(
            post("/auth/otk")
                .withBearer("openid-profile-token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {
                      "appInstanceId": "app-local-001",
                      "deviceId": "device-local-001",
                      "certificateProfile": "quantum-bank-mobile-client-v1"
                    }
                    """.trimIndent(),
                ),
        )
            .andExpect(status().isAccepted)
            .andExpect(jsonPath("$.otk").exists())

        mockMvc.perform(
            post("/auth/csr")
                .withBearer("openid-profile-token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {
                      "otk": "missing",
                      "csr": "not-a-csr",
                      "appInstanceId": "app-local-001",
                      "deviceId": "device-local-001",
                      "certificateProfile": "quantum-bank-mobile-client-v1"
                    }
                    """.trimIndent(),
                ),
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.errorCode", equalTo("csr_invalid")))

        mockMvc.perform(post("/pix/transfers").withBearer("pix-write-token"))
            .andExpect(status().isAccepted)

        mockMvc.perform(get("/statements").withBearer("statements-read-token"))
            .andExpect(status().isOk)

        mockMvc.perform(get("/profile").withBearer("profile-read-token"))
            .andExpect(status().isOk)
    }

    private data class Route(
        val method: String,
        val path: String,
    ) {
        fun request(token: String? = null): MockHttpServletRequestBuilder {
            val request = when (method) {
                "POST" -> post(path).contentType(MediaType.APPLICATION_JSON)
                "GET" -> get(path)
                else -> error("Unsupported method: $method")
            }

            return if (token == null) {
                request
            } else {
                request.header(HttpHeaders.AUTHORIZATION, "Bearer $token")
            }
        }
    }

    private fun MockHttpServletRequestBuilder.withBearer(token: String): MockHttpServletRequestBuilder =
        header(HttpHeaders.AUTHORIZATION, "Bearer $token")

    @TestConfiguration
    class TestJwtConfiguration {

        @Bean
        @Primary
        fun testJwtDecoder(): JwtDecoder =
            JwtDecoder { token ->
                when (token) {
                    "malformed-token" -> throw BadJwtException("malformed token")
                    "expired-token" -> throw BadJwtException("expired token")
                    "wrong-issuer-token" -> throw BadJwtException("wrong issuer")
                    "wrong-audience-token" -> throw BadJwtException("wrong audience")
                    "openid-profile-token" -> jwt(token, scopes = listOf("openid", "profile"))
                    "pix-write-token" -> jwt(token, scopes = listOf("pix:write"))
                    "statements-read-token" -> jwt(token, scopes = listOf("statements:read"))
                    "profile-read-token" -> jwt(token, scopes = listOf("profile:read"))
                    else -> throw BadJwtException("unknown token")
                }
            }

        private fun jwt(
            token: String,
            scopes: List<String>,
        ): Jwt {
            val now = Instant.now()

            return Jwt.withTokenValue(token)
                .header("alg", "RS256")
                .issuer("http://localhost:8180/realms/quantum-bank-local")
                .subject("alice@quantumbank.local")
                .audience(listOf("quantum-bank-api"))
                .issuedAt(now.minusSeconds(30))
                .expiresAt(now.plusSeconds(300))
                .claim("azp", "quantum-bank-mobile")
                .claim("scope", scopes.joinToString(" "))
                .build()
        }
    }
}

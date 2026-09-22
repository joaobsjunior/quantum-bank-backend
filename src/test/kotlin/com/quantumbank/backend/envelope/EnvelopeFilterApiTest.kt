package com.quantumbank.backend.envelope

import jakarta.servlet.ReadListener
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
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
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.security.oauth2.jwt.BadJwtException
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.header
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import tools.jackson.databind.ObjectMapper
import java.time.Instant

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class EnvelopeFilterApiTest {

    @Autowired
    private lateinit var mockMvc: MockMvc

    @Autowired
    private lateinit var keyService: HybridEnvelopeKeyService

    @Autowired
    private lateinit var objectMapper: ObjectMapper

    @Autowired
    private lateinit var filter: EnvelopeFilter

    private fun client() = TestEnvelopeClient(keyService.signedKeySet().keySet)

    @Test
    fun mobileClientMustUseTheEnvelopeOnBankingPaths() {
        mockMvc.perform(get("/statements").header(HttpHeaders.AUTHORIZATION, "Bearer mobile-token"))
            .andExpect(status().isBadRequest)
            .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
            .andExpect(jsonPath("$.errorCode", equalTo(EnvelopeErrorCodes.ENVELOPE_REQUIRED)))
    }

    @Test
    fun serviceClientsKeepPlaintextOverStrictTls() {
        mockMvc.perform(get("/statements").header(HttpHeaders.AUTHORIZATION, "Bearer service-token"))
            .andExpect(status().isOk)
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andExpect(jsonPath("$.entries").isArray)
    }

    @Test
    fun envelopedGetIsOpenedAndTheResponseIsSealed() {
        val client = client()
        val sealed = client.seal("GET /statements")

        val result = mockMvc.perform(
            get("/statements")
                .header(HttpHeaders.AUTHORIZATION, "Bearer mobile-token")
                .header(EnvelopeMessage.REQUEST_HEADER, TestEnvelopeClient.headerValue(sealed.message, objectMapper)),
        )
            .andExpect(status().isOk)
            .andExpect(content().contentTypeCompatibleWith(EnvelopeMessage.MEDIA_TYPE))
            .andExpect(header().string(EnvelopeMessage.CONTENT_TYPE_HEADER, "application/json"))
            .andReturn()

        val response = objectMapper.readValue(result.response.contentAsByteArray, EnvelopeMessage::class.java)
        val plaintext = String(client.open(response, sealed.responseKey, "GET /statements"))
        assertThat(plaintext).contains("\"entries\"")
        assertThat(result.response.contentAsString).doesNotContain("entries")
    }

    @Test
    fun envelopedPostWithoutSignatureIsRejectedInsideTheEnvelope() {
        val client = client()
        val body = """{"amount":25.30,"recipientKey":"recipient@example.com","description":"x","scenario":"SUCCESS"}"""
        val sealed = client.seal("POST /pix/transfers", body.toByteArray())

        val result = mockMvc.perform(
            post("/pix/transfers")
                .header(HttpHeaders.AUTHORIZATION, "Bearer mobile-token")
                .contentType(EnvelopeMessage.MEDIA_TYPE)
                .content(objectMapper.writeValueAsBytes(sealed.message)),
        )
            .andExpect(status().isBadRequest)
            .andExpect(content().contentTypeCompatibleWith(EnvelopeMessage.MEDIA_TYPE))
            .andExpect(header().string(EnvelopeMessage.CONTENT_TYPE_HEADER, "application/problem+json"))
            .andReturn()

        val response = objectMapper.readValue(result.response.contentAsByteArray, EnvelopeMessage::class.java)
        assertThat(String(client.open(response, sealed.responseKey, "POST /pix/transfers")))
            .contains(EnvelopeErrorCodes.TRANSACTION_SIGNATURE_REQUIRED)
    }

    @Test
    fun rejectsUnknownKeyIdsMalformedAndTamperedEnvelopes() {
        val client = client()
        val sealed = client.seal("GET /profile")

        mockMvc.perform(
            get("/profile")
                .header(HttpHeaders.AUTHORIZATION, "Bearer mobile-token")
                .header(EnvelopeMessage.REQUEST_HEADER, TestEnvelopeClient.headerValue(sealed.message.copy(kid = "unknown"), objectMapper)),
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.errorCode", equalTo(EnvelopeErrorCodes.ENVELOPE_KEY_UNKNOWN)))

        mockMvc.perform(
            get("/profile")
                .header(HttpHeaders.AUTHORIZATION, "Bearer mobile-token")
                .header(EnvelopeMessage.REQUEST_HEADER, "not-base64!!"),
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.errorCode", equalTo(EnvelopeErrorCodes.ENVELOPE_INVALID)))

        mockMvc.perform(
            get("/profile")
                .header(HttpHeaders.AUTHORIZATION, "Bearer mobile-token")
                .header(EnvelopeMessage.REQUEST_HEADER, TestEnvelopeClient.headerValue(sealed.message.copy(x25519PublicKey = "AAAA"), objectMapper)),
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.errorCode", equalTo(EnvelopeErrorCodes.ENVELOPE_INVALID)))

        mockMvc.perform(
            post("/pix/transfers")
                .header(HttpHeaders.AUTHORIZATION, "Bearer mobile-token")
                .contentType(EnvelopeMessage.MEDIA_TYPE)
                .content("{not json"),
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.errorCode", equalTo(EnvelopeErrorCodes.ENVELOPE_INVALID)))
    }

    @Test
    fun bootstrapPathsAreNotEnveloped() {
        val request = MockHttpServletRequest("POST", "/auth/csr")
        assertThat(filter.shouldNotFilter(request)).isTrue()
        assertThat(filter.shouldNotFilter(MockHttpServletRequest("GET", "/profile"))).isFalse()
        assertThat(filter.readMessage(MockHttpServletRequest("GET", "/profile"))).isNull()
    }

    @Test
    fun envelopedRequestExposesThePlaintextToSpringMvc() {
        val original = MockHttpServletRequest("POST", "/pix/transfers").apply { contentType = EnvelopeMessage.MEDIA_TYPE }
        val wrapped = EnvelopedRequest(original, "{\"a\":1}".toByteArray(), "application/json")

        assertThat(wrapped.contentType).isEqualTo("application/json")
        assertThat(wrapped.getHeader("Content-Type")).isEqualTo("application/json")
        assertThat(wrapped.getHeader("X-Other")).isNull()
        assertThat(wrapped.contentLength).isEqualTo(7)
        assertThat(wrapped.contentLengthLong).isEqualTo(7L)
        assertThat(wrapped.reader.readText()).isEqualTo("{\"a\":1}")
        val stream = wrapped.inputStream
        assertThat(stream.isReady).isTrue()
        assertThat(stream.isFinished).isFalse()
        assertThat(stream.readAllBytes()).hasSize(7)
        assertThat(stream.isFinished).isTrue()
        assertThatThrownBy { stream.setReadListener(object : ReadListener {
            override fun onDataAvailable() = Unit
            override fun onAllDataRead() = Unit
            override fun onError(t: Throwable) = Unit
        }) }.isInstanceOf(UnsupportedOperationException::class.java)

        val bodiless = EnvelopedRequest(MockHttpServletRequest("GET", "/statements"), null, "application/json")
        assertThat(bodiless.contentType).isNull()
        assertThat(bodiless.contentLength).isZero()
    }

    @TestConfiguration
    class TestJwtConfiguration {
        @Bean
        @Primary
        fun testJwtDecoder(): JwtDecoder =
            JwtDecoder { token ->
                when (token) {
                    "mobile-token" -> jwt(token, clientId = "quantum-bank-mobile")
                    "service-token" -> jwt(token, clientId = "quantum-bank-test")
                    else -> throw BadJwtException("unknown token")
                }
            }

        private fun jwt(token: String, clientId: String): Jwt {
            val now = Instant.now()
            return Jwt.withTokenValue(token)
                .header("alg", "RS256")
                .issuer("http://localhost:8180/realms/quantum-bank-local")
                .subject("alice@quantumbank.local")
                .audience(listOf("quantum-bank-api"))
                .issuedAt(now.minusSeconds(30))
                .expiresAt(now.plusSeconds(300))
                .claim("azp", clientId)
                .claim("scope", "pix:write statements:read profile:read profile:write")
                .build()
        }
    }
}

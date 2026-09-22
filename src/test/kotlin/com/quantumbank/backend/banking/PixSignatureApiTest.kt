package com.quantumbank.backend.banking

import com.quantumbank.backend.bootstrap.DeviceSigningKeyRepository
import com.quantumbank.backend.bootstrap.MlDsa65
import com.quantumbank.backend.envelope.EnvelopeErrorCodes
import com.quantumbank.backend.envelope.EnvelopeFixture
import com.quantumbank.backend.envelope.EnvelopeMessage
import com.quantumbank.backend.envelope.HybridEnvelopeKeyService
import com.quantumbank.backend.envelope.TestEnvelopeClient
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
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
import tools.jackson.databind.ObjectMapper
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64

/**
 * The Pix order and signature come from the Dart fixture, so the canonical
 * message and the ML-DSA-65 verification are proven across implementations.
 * Service clients (strict TLS tier) stay exempt; the envelope filter is
 * exercised separately, so these requests use the service client for the
 * transport and the mobile client where the signature policy is under test.
 */
@SpringBootTest(properties = ["quantum-bank.envelope.required-for-clients=quantum-bank-mobile,quantum-bank-signer-test"])
@AutoConfigureMockMvc
@ActiveProfiles("test")
class PixSignatureApiTest {

    @Autowired
    private lateinit var mockMvc: MockMvc

    @Autowired
    private lateinit var signingKeys: DeviceSigningKeyRepository

    @Autowired
    private lateinit var signatures: TransactionSignatureRepository

    @Autowired
    private lateinit var objectMapper: ObjectMapper

    @Autowired
    private lateinit var keyService: HybridEnvelopeKeyService

    @Suppress("UNCHECKED_CAST")
    private val order: Map<String, Any?> by lazy { objectMapper.readValue(EnvelopeFixture.plaintext, Map::class.java) as Map<String, Any?> }

    @BeforeEach
    fun registerFixtureKey() {
        signingKeys.register(
            EnvelopeFixture.subject,
            EnvelopeFixture.deviceId,
            MlDsa65.ALGORITHM,
            Base64.getDecoder().decode(EnvelopeFixture.signingKeyRegistration.getValue("publicKey")),
        )
    }

    private fun body(vararg overrides: Pair<String, Any?>, signature: Map<String, Any?>? = order["signature"] as Map<String, Any?>?): String =
        objectMapper.writeValueAsString(order + mapOf("signature" to signature) + overrides.toMap())

    /**
     * App-edge clients must envelope every banking request, so the signer
     * client sends the order sealed and the assertions read the opened
     * response; the service client sends plain JSON.
     */
    private fun postPix(content: String, token: String = "signer-token"): Exchange {
        if (token == "service-token") {
            val result = mockMvc.perform(
                post("/pix/transfers")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer $token")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(content),
            ).andReturn()
            return Exchange(result.response.status, result.response.contentAsString)
        }
        val client = TestEnvelopeClient(keyService.signedKeySet().keySet)
        val sealed = client.seal("POST /pix/transfers", content.toByteArray())
        val result = mockMvc.perform(
            post("/pix/transfers")
                .header(HttpHeaders.AUTHORIZATION, "Bearer $token")
                .contentType(EnvelopeMessage.MEDIA_TYPE)
                .content(objectMapper.writeValueAsBytes(sealed.message)),
        ).andReturn()
        assertThat(result.response.contentType).startsWith(EnvelopeMessage.MEDIA_TYPE)
        val response = objectMapper.readValue(result.response.contentAsByteArray, EnvelopeMessage::class.java)
        return Exchange(result.response.status, String(client.open(response, sealed.responseKey, "POST /pix/transfers")))
    }

    private inner class Exchange(val status: Int, val body: String) {
        @Suppress("UNCHECKED_CAST")
        val json: Map<String, Any?> = objectMapper.readValue(body, Map::class.java) as Map<String, Any?>

        fun expectStatus(expected: Int): Exchange = also { assertThat(status).`as`(body).isEqualTo(expected) }
        fun expectErrorCode(expected: String): Exchange = also { assertThat(json["errorCode"]).isEqualTo(expected) }
    }

    @Test
    fun acceptsTheSignedOrderFromTheDartFixtureOnceAndStoresTheSignature() {
        val nonce = EnvelopeFixture.pixSignature.getValue("nonce")

        val accepted = postPix(body()).expectStatus(200)
        assertThat(accepted.json["status"]).isEqualTo("COMPLETED")
        assertThat(accepted.json["transactionId"]).isNotNull()

        val stored = signatures.findByNonce(nonce)
        assertThat(stored).isNotNull()
        assertThat(stored!!["TRANSACTION_ID"] ?: stored["transaction_id"]).isEqualTo(accepted.json["transactionId"])

        postPix(body()).expectStatus(409).expectErrorCode(EnvelopeErrorCodes.TRANSACTION_SIGNATURE_REPLAYED)
    }

    @Test
    fun rejectsTamperedStaleUnknownAndMalformedSignatures() {
        val signature = order["signature"] as Map<String, Any?>
        fun expectInvalid(content: String) =
            postPix(content).expectStatus(400).expectErrorCode(EnvelopeErrorCodes.TRANSACTION_SIGNATURE_INVALID)

        expectInvalid(body("amount" to 26.30))
        expectInvalid(body("description" to "changed"))
        expectInvalid(body(signature = signature + ("alg" to "ML-DSA-87")))
        expectInvalid(body(signature = signature + ("issuedAt" to "not-a-time")))
        expectInvalid(body(signature = signature + ("issuedAt" to "2026-09-19T11:00:00.000Z")))
        expectInvalid(body(signature = signature + ("deviceId" to "device-unknown")))
        expectInvalid(body(signature = signature + ("value" to "***")))
        expectInvalid(body(signature = signature + ("value" to Base64.getEncoder().encodeToString(ByteArray(3309)))))
    }

    @Test
    fun requiresTheSignatureOnlyForAppEdgeClients() {
        postPix(body(signature = null)).expectStatus(400).expectErrorCode(EnvelopeErrorCodes.TRANSACTION_SIGNATURE_REQUIRED)

        val plain = postPix(body(signature = null), token = "service-token").expectStatus(200)
        assertThat(plain.json["status"]).isEqualTo("COMPLETED")
    }

    @Test
    fun aSignedOrderInTheErrorScenarioIsStillBoundToTheAttempt() {
        val signature = (order["signature"] as Map<String, Any?>) + ("nonce" to "11111111-2222-4333-8444-555555555555")
        // Re-sign is not possible here (no private key); the canonical message
        // changed with the nonce, so this order must be rejected as invalid,
        // proving the nonce is covered by the signature.
        postPix(body("scenario" to "ERROR", signature = signature))
            .expectStatus(400)
            .expectErrorCode(EnvelopeErrorCodes.TRANSACTION_SIGNATURE_INVALID)
    }

    @Test
    fun canonicalAmountUsesTwoDecimalsAndTheContextIsDomainSeparated() {
        assertThat(PixSignatureVerifier.canonicalAmount(java.math.BigDecimal("25.3"))).isEqualTo("25.30")
        assertThat(PixSignatureVerifier.canonicalAmount(java.math.BigDecimal("1"))).isEqualTo("1.00")
        assertThat(String(PixSignatureVerifier.CONTEXT)).isEqualTo("quantum-bank-pix-v1")
    }

    @TestConfiguration
    class TestConfigurationBeans {
        /** Frozen at the fixture's `issuedAt` so the skew check accepts it. */
        @Bean
        @Primary
        fun fixtureClock(): Clock = Clock.fixed(Instant.parse("2026-09-19T12:00:30Z"), ZoneOffset.UTC)

        @Bean
        @Primary
        fun testJwtDecoder(): JwtDecoder =
            JwtDecoder { token ->
                when (token) {
                    "signer-token" -> jwt(token, clientId = "quantum-bank-signer-test")
                    "service-token" -> jwt(token, clientId = "quantum-bank-test")
                    else -> throw BadJwtException("unknown token")
                }
            }

        private fun jwt(token: String, clientId: String): Jwt {
            val now = Instant.now()
            return Jwt.withTokenValue(token)
                .header("alg", "RS256")
                .issuer("http://localhost:8180/realms/quantum-bank-local")
                .subject(EnvelopeFixture.subject)
                .audience(listOf("quantum-bank-api"))
                .issuedAt(now.minusSeconds(30))
                .expiresAt(now.plusSeconds(300))
                .claim("azp", clientId)
                .claim("scope", "pix:write")
                .build()
        }
    }
}

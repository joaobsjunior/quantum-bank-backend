package com.quantumbank.backend.envelope

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.util.Base64

class HybridEnvelopeCodecTest {

    private val codec = HybridEnvelopeCodec()

    @Test
    fun opensTheEnvelopeSealedByTheDartApp() {
        val opened = codec.open(EnvelopeFixture.request, EnvelopeFixture.keyPair, EnvelopeFixture.aad)

        assertThat(String(opened.plaintext!!, Charsets.UTF_8)).isEqualTo(EnvelopeFixture.plaintext)
        assertThat(opened.kid).isEqualTo(EnvelopeFixture.keySet.kid)
        assertThat(opened.responseKey).hasSize(32)
    }

    @Test
    fun sharedSecretsMatchTheDartImplementationByteForByte() {
        val request = EnvelopeFixture.request
        val keyPair = EnvelopeFixture.keyPair

        val mlkem = codec.decapsulate(keyPair.mlkemPrivateKey, Base64.getDecoder().decode(request.mlkemCiphertext))
        val x25519 = codec.agree(keyPair.x25519PrivateKey, Base64.getDecoder().decode(request.x25519PublicKey))

        assertThat(mlkem).isEqualTo(EnvelopeFixture.mlkemSharedSecret)
        assertThat(x25519).isEqualTo(EnvelopeFixture.x25519SharedSecret)
        val (requestKey, responseKey) = HybridEnvelopeCodec.deriveKeys(mlkem, x25519, request.kid, EnvelopeFixture.aad)
        assertThat(requestKey).isEqualTo(EnvelopeFixture.requestKey)
        assertThat(responseKey).isNotEqualTo(requestKey)
    }

    @Test
    fun opensAHeaderOnlyRequestWithoutPlaintext() {
        val (aad, header) = EnvelopeFixture.headerRequest
        val message = tools.jackson.databind.ObjectMapper().readValue(Base64.getUrlDecoder().decode(header), EnvelopeMessage::class.java)

        val opened = codec.open(message, EnvelopeFixture.keyPair, aad)

        assertThat(opened.plaintext).isNull()
        assertThat(opened.responseKey).hasSize(32)
    }

    @Test
    fun sealsResponsesTheClientCanOpenAndBindsThemToTheAad() {
        val client = TestEnvelopeClient(EnvelopeFixture.keySet)
        val sealed = client.seal("GET /profile")
        val opened = codec.open(sealed.message, EnvelopeFixture.keyPair, "GET /profile")

        val response = codec.seal(opened.responseKey, opened.kid, "GET /profile", """{"ok":true}""".toByteArray(), "application/json")

        assertThat(response.kid).isEqualTo(EnvelopeFixture.keySet.kid)
        assertThat(response.contentType).isEqualTo("application/json")
        assertThat(response.mlkemCiphertext).isNull()
        assertThat(String(client.open(response, sealed.responseKey, "GET /profile"))).isEqualTo("""{"ok":true}""")
        assertThatThrownBy { client.open(response, sealed.responseKey, "GET /statements") }
            .isInstanceOf(javax.crypto.AEADBadTagException::class.java)
    }

    @Test
    fun roundTripsARequestBodyFromTheKotlinClient() {
        val client = TestEnvelopeClient(EnvelopeFixture.keySet)
        val sealed = client.seal("POST /pix/transfers", """{"amount":1}""".toByteArray())

        val opened = codec.open(sealed.message, EnvelopeFixture.keyPair, "POST /pix/transfers")

        assertThat(String(opened.plaintext!!)).isEqualTo("""{"amount":1}""")
    }

    @Test
    fun rejectsMalformedEnvelopes() {
        val request = EnvelopeFixture.request
        val keyPair = EnvelopeFixture.keyPair
        fun expectInvalid(message: EnvelopeMessage, detail: String, aad: String = EnvelopeFixture.aad) {
            assertThatThrownBy { codec.open(message, keyPair, aad) }
                .isInstanceOf(EnvelopeException::class.java)
                .hasMessageContaining(detail)
                .extracting("errorCode").isEqualTo(EnvelopeErrorCodes.ENVELOPE_INVALID)
        }

        expectInvalid(request.copy(v = 2), "unsupported envelope version")
        expectInvalid(request.copy(mlkemCiphertext = null), "missing envelope field mlkemCiphertext")
        expectInvalid(request.copy(mlkemCiphertext = "***"), "invalid base64")
        expectInvalid(request.copy(mlkemCiphertext = Base64.getEncoder().encodeToString(ByteArray(10))), "invalid length")
        expectInvalid(request.copy(x25519PublicKey = Base64.getEncoder().encodeToString(ByteArray(31))), "invalid length")
        expectInvalid(request.copy(nonce = Base64.getEncoder().encodeToString(ByteArray(11))), "invalid length")
        expectInvalid(request.copy(nonce = null), "missing envelope field nonce")
        expectInvalid(request, "authentication failed", aad = "GET /statements")
        val tampered = Base64.getDecoder().decode(request.ciphertext).also { it[0] = (it[0].toInt() xor 1).toByte() }
        expectInvalid(request.copy(ciphertext = Base64.getEncoder().encodeToString(tampered)), "authentication failed")
    }
}

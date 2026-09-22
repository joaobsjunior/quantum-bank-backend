package com.quantumbank.backend.bootstrap

import com.quantumbank.backend.envelope.EnvelopeErrorCodes
import com.quantumbank.backend.envelope.EnvelopeFixture
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles
import java.util.Base64

@SpringBootTest
@ActiveProfiles("test")
class DeviceSigningKeysTest {

    @Autowired
    private lateinit var repository: DeviceSigningKeyRepository

    private val validator = SigningKeyValidator()

    /** The fixture proof covers the raw bytes `fixture-csr-der`, wrapped here as a PEM body. */
    private val fixtureCsrPem = "-----BEGIN CERTIFICATE REQUEST-----\n" +
        Base64.getEncoder().encodeToString(EnvelopeFixture.csrDer) + "\n-----END CERTIFICATE REQUEST-----\n"

    private fun registration(
        alg: String = EnvelopeFixture.signingKeyRegistration.getValue("alg"),
        publicKey: String = EnvelopeFixture.signingKeyRegistration.getValue("publicKey"),
        proof: String = EnvelopeFixture.signingKeyRegistration.getValue("proof"),
    ) = SigningKeyRegistration(alg, publicKey, proof)

    @Test
    fun acceptsTheRegistrationEmittedByTheDartApp() {
        val raw = validator.validate(registration(), fixtureCsrPem)

        assertThat(raw).hasSize(MlDsa65.PUBLIC_KEY_LENGTH)
        assertThat(validator.csrDer(fixtureCsrPem)).isEqualTo(EnvelopeFixture.csrDer)
    }

    @Test
    fun rejectsInvalidRegistrations() {
        fun expectInvalid(registration: SigningKeyRegistration, csr: String = fixtureCsrPem, detail: String) {
            assertThatThrownBy { validator.validate(registration, csr) }
                .isInstanceOf(SigningKeyException::class.java)
                .hasMessageContaining(detail)
                .extracting("errorCode").isEqualTo(EnvelopeErrorCodes.SIGNING_KEY_INVALID)
        }

        expectInvalid(registration(alg = "ML-DSA-44"), detail = "unsupported signing key algorithm")
        expectInvalid(registration(publicKey = "***"), detail = "not base64")
        expectInvalid(registration(publicKey = Base64.getEncoder().encodeToString(ByteArray(10))), detail = "not a valid ML-DSA-65 key")
        expectInvalid(registration(publicKey = Base64.getEncoder().encodeToString(ByteArray(MlDsa65.PUBLIC_KEY_LENGTH))), detail = "does not verify")
        expectInvalid(registration(proof = Base64.getEncoder().encodeToString(ByteArray(3309))), detail = "does not verify")
        expectInvalid(registration(), csr = "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n", detail = "does not verify")
    }

    @Test
    fun registersAndReplacesTheKeyOfADevice() {
        val first = repository.register("alice@quantumbank.local", "device-test-001", MlDsa65.ALGORITHM, ByteArray(4) { 1 })
        assertThat(repository.find("alice@quantumbank.local", "device-test-001")?.publicKey).isEqualTo(first.publicKey)

        repository.register("alice@quantumbank.local", "device-test-001", MlDsa65.ALGORITHM, ByteArray(4) { 2 })
        val replaced = repository.find("alice@quantumbank.local", "device-test-001")
        assertThat(replaced?.publicKey).isEqualTo(ByteArray(4) { 2 })
        assertThat(replaced?.algorithm).isEqualTo(MlDsa65.ALGORITHM)
        assertThat(replaced?.registeredAt).isNotNull()
        assertThat(repository.find("alice@quantumbank.local", "device-none")).isNull()
    }

    @Test
    fun mlDsa65RejectsMalformedKeysAndSignatures() {
        assertThatThrownBy { MlDsa65.publicKey(ByteArray(3)) }.isInstanceOf(Exception::class.java)
        assertThat(MlDsa65.publicKeyOrNull(ByteArray(3))).isNull()
        assertThat(MlDsa65.publicKeyOrNull(Base64.getDecoder().decode(EnvelopeFixture.signingKeyRegistration.getValue("publicKey")))).isNotNull()
        val key = MlDsa65.publicKey(Base64.getDecoder().decode(EnvelopeFixture.signingKeyRegistration.getValue("publicKey")))
        assertThat(MlDsa65.verify(key, ByteArray(1), ByteArray(1), ByteArray(0))).isFalse()
    }
}

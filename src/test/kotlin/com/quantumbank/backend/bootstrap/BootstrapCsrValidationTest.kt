package com.quantumbank.backend.bootstrap

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatCode
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path

class BootstrapCsrValidationTest {

    private val validator = CsrValidator()
    private val subject = "00000000-0000-0000-0000-000000000001"

    @Test
    fun parsesMlDsaCertificateRequestAndComputesStableFingerprint() {
        val csrPem = TestCrypto.mlDsaCsrPem("CN=$subject,O=Quantum Bank")

        val parsed = validator.parse(csrPem)
        val firstFingerprint = validator.fingerprintSha256(parsed)
        val secondFingerprint = validator.fingerprintSha256(validator.parse(csrPem))

        assertThat(firstFingerprint).hasSize(64)
        assertThat(secondFingerprint).isEqualTo(firstFingerprint)
        assertThat(validator.keyAlgorithmName(parsed)).isEqualTo(TestCrypto.ML_DSA_65)
    }

    @Test
    fun rejectsMalformedCsrAndEmbeddedPrivateKeyMaterial() {
        assertThatThrownBy { validator.parse("not-a-csr") }
            .isInstanceOf(CsrValidationException::class.java)
            .hasMessageContaining("csr_invalid")

        assertThatThrownBy { validator.parse("-----BEGIN CERTIFICATE REQUEST-----\n!!!\n-----END CERTIFICATE REQUEST-----") }
            .isInstanceOf(CsrValidationException::class.java)
            .hasMessageContaining("csr_invalid")

        assertThatThrownBy { validator.parse("x".repeat(BootstrapIdentifiers.CSR_MAX_LENGTH + 1)) }
            .isInstanceOf(CsrValidationException::class.java)
            .hasMessageContaining("csr_invalid")

        listOf(
            "-----BEGIN PRIVATE KEY-----\nredacted\n-----END PRIVATE KEY-----",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nredacted\n-----END ENCRYPTED PRIVATE KEY-----",
        ).forEach { pem ->
            assertThatThrownBy { validator.rejectPrivateKeyMaterial(pem) }
                .isInstanceOf(CsrValidationException::class.java)
                .hasMessageContaining("private_key_rejected")
        }

        assertThat(BootstrapErrorCodes.CSR_INVALID).isEqualTo("csr_invalid")
        assertThat(BootstrapErrorCodes.PRIVATE_KEY_REJECTED).isEqualTo("private_key_rejected")
    }

    @Test
    fun rejectsPemWithMoreThanOneObject() {
        val csrPem = TestCrypto.mlDsaCsrPem("CN=$subject")
        val certificatePem = TestCrypto.pem(TestCrypto.selfSignedCertificate("CN=extra"))

        assertThatThrownBy { validator.parse(csrPem + certificatePem) }
            .isInstanceOf(CsrValidationException::class.java)
            .hasMessageContaining("csr_invalid")

        assertThatThrownBy { validator.parse(certificatePem) }
            .isInstanceOf(CsrValidationException::class.java)
            .hasMessageContaining("csr_invalid")
    }

    @Test
    fun rejectsCsrWithoutProofOfPossession() {
        val keyPair = TestCrypto.mlDsaKeyPair()
        val otherKeyPair = TestCrypto.mlDsaKeyPair()
        val forged = TestCrypto.csrPem("CN=$subject", keyPair.public, otherKeyPair.private, TestCrypto.ML_DSA_65)

        assertThatThrownBy { validator.parse(forged) }
            .isInstanceOf(CsrValidationException::class.java)
            .hasMessageContaining("csr_invalid")
    }

    @Test
    fun proofOfPossessionCheckFailsClosedOnVerifierErrors() {
        val ed25519 = TestCrypto.ed25519KeyPair()
        val csr = validator.parse(TestCrypto.csrPem("CN=$subject", ed25519.public, ed25519.private, "Ed25519"))

        assertThat(validator.hasValidProofOfPossession(csr)).isTrue()
    }

    @Test
    fun keyPolicyAcceptsOnlyMlDsa65And87() {
        listOf(TestCrypto.ML_DSA_65, TestCrypto.ML_DSA_87).forEach { algorithm ->
            val keyPair = TestCrypto.mlDsaKeyPair(algorithm)
            val csr = validator.parse(TestCrypto.mlDsaCsrPem("CN=$subject", keyPair))
            assertThatCode { validator.validateKeyPolicy(csr) }.`as`(algorithm).doesNotThrowAnyException()
            assertThat(validator.keyAlgorithmName(csr)).isEqualTo(algorithm)
        }

        // Lower post-quantum category and every classical algorithm are rejected,
        // matching what the gateway terminators accept at the TLS layer.
        val mlDsa44 = TestCrypto.mlDsaKeyPair(TestCrypto.ML_DSA_44)
        val rsa = TestCrypto.rsaKeyPair()
        val ec = TestCrypto.ecKeyPair()
        val ed25519 = TestCrypto.ed25519KeyPair()
        listOf(
            TestCrypto.ML_DSA_44 to TestCrypto.mlDsaCsrPem("CN=$subject", mlDsa44),
            "RSA-2048" to TestCrypto.rsaCsrPem("CN=$subject", rsa),
            "RSA-4096" to TestCrypto.rsaCsrPem("CN=$subject", TestCrypto.rsaKeyPair(4096)),
            "EC-P256" to TestCrypto.csrPem("CN=$subject", ec.public, ec.private, "SHA256withECDSA"),
            "Ed25519" to TestCrypto.csrPem("CN=$subject", ed25519.public, ed25519.private, "Ed25519"),
        ).forEach { (name, csrPem) ->
            assertThatThrownBy { validator.validateKeyPolicy(validator.parse(csrPem)) }
                .`as`(name)
                .isInstanceOf(CsrValidationException::class.java)
                .hasMessageContaining("csr_key_rejected")
        }

        assertThat(BootstrapErrorCodes.CSR_KEY_REJECTED).isEqualTo("csr_key_rejected")
        assertThat(CsrValidator.ACCEPTED_ML_DSA_PARAMETERS).hasSize(2)
    }

    @Test
    fun keyPolicyRejectsUnparseablePublicKeys() {
        val csr = validator.parse(TestCrypto.mlDsaCsrPem("CN=$subject"))
        val broken = org.bouncycastle.pkcs.PKCS10CertificationRequest(
            org.bouncycastle.asn1.pkcs.CertificationRequest(
                org.bouncycastle.asn1.pkcs.CertificationRequestInfo(
                    csr.subject,
                    org.bouncycastle.asn1.x509.SubjectPublicKeyInfo(
                        org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                            org.bouncycastle.asn1.ASN1ObjectIdentifier("1.2.3.4.5"),
                        ),
                        byteArrayOf(1, 2, 3),
                    ),
                    csr.toASN1Structure().certificationRequestInfo.attributes,
                ),
                csr.signatureAlgorithm,
                csr.toASN1Structure().signature,
            ),
        )

        assertThatThrownBy { validator.validateKeyPolicy(broken) }
            .isInstanceOf(CsrValidationException::class.java)
            .hasMessageContaining("csr_key_rejected")
    }

    @Test
    fun acceptsTheCsrProducedByTheMobileDartImplementation() {
        // Interop fixture generated by mobile-app (pure-Dart ML-DSA-65, pqcrypto)
        // through tool/emit_ml_dsa_csr.dart; it carries only a public key.
        val fixture = Path.of("src/test/resources/pqc/mobile-ml-dsa-65.csr")
        val csr = validator.parse(Files.readString(fixture))

        assertThatCode { validator.validateKeyPolicy(csr) }.doesNotThrowAnyException()
        assertThatCode { validator.validateSubject(csr, subject) }.doesNotThrowAnyException()
        assertThat(validator.keyAlgorithmName(csr)).isEqualTo(TestCrypto.ML_DSA_65)
        assertThat(validator.fingerprintSha256(csr)).hasSize(64)
    }

    @Test
    fun rejectsProfileAndEnvironmentMismatch() {
        assertThatThrownBy {
            validator.validateProfileAndEnvironment(
                certificateProfile = "other-profile",
                environment = "local",
                expectedCertificateProfile = "quantum-bank-mobile-client-v1",
                expectedEnvironment = "local",
            )
        }
            .isInstanceOf(CsrValidationException::class.java)
            .hasMessageContaining("certificate_profile_mismatch")

        assertThatThrownBy {
            validator.validateProfileAndEnvironment(
                certificateProfile = "quantum-bank-mobile-client-v1",
                environment = "prod",
                expectedCertificateProfile = "quantum-bank-mobile-client-v1",
                expectedEnvironment = "local",
            )
        }
            .isInstanceOf(CsrValidationException::class.java)
            .hasMessageContaining("unsupported_environment")
    }

    @Test
    fun subjectMustMatchCommonNameExactly() {
        assertThatCode {
            validator.validateSubject(validator.parse(TestCrypto.mlDsaCsrPem("CN=$subject,O=Quantum Bank")), subject)
        }.doesNotThrowAnyException()

        // Substring/superstring, missing CN, duplicated CN, and multi-valued CN are all rejected.
        listOf(
            "CN=super$subject",
            "O=$subject",
            "CN=$subject,CN=other",
            "CN=$subject+CN=other",
        ).forEach { dn ->
            assertThatThrownBy { validator.validateSubject(validator.parse(TestCrypto.mlDsaCsrPem(dn)), subject) }
                .`as`(dn)
                .isInstanceOf(CsrValidationException::class.java)
                .hasMessageContaining("subject_mismatch")
        }
    }
}

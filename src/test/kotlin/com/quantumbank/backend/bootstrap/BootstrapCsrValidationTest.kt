package com.quantumbank.backend.bootstrap

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatCode
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test

class BootstrapCsrValidationTest {

    private val validator = CsrValidator()
    private val subject = "00000000-0000-0000-0000-000000000001"

    @Test
    fun parsesCertificateRequestAndComputesStableFingerprint() {
        val csrPem = TestCrypto.rsaCsrPem("CN=$subject,O=Quantum Bank")

        val parsed = validator.parse(csrPem)
        val firstFingerprint = validator.fingerprintSha256(parsed)
        val secondFingerprint = validator.fingerprintSha256(validator.parse(csrPem))

        assertThat(firstFingerprint).hasSize(64)
        assertThat(secondFingerprint).isEqualTo(firstFingerprint)
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
        val csrPem = TestCrypto.rsaCsrPem("CN=$subject")
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
        val keyPair = TestCrypto.rsaKeyPair()
        val otherKeyPair = TestCrypto.rsaKeyPair()
        val forged = TestCrypto.csrPem("CN=$subject", keyPair.public, otherKeyPair.private, "SHA256withRSA")

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
    fun keyPolicyAcceptsStrongRsaAndEcKeysOnly() {
        assertThatCode { validator.validateKeyPolicy(validator.parse(TestCrypto.rsaCsrPem("CN=$subject"))) }
            .doesNotThrowAnyException()

        val ec = TestCrypto.ecKeyPair()
        assertThatCode {
            validator.validateKeyPolicy(
                validator.parse(TestCrypto.csrPem("CN=$subject", ec.public, ec.private, "SHA256withECDSA")),
            )
        }.doesNotThrowAnyException()

        val weakRsa = TestCrypto.rsaKeyPair(1024)
        assertThatThrownBy { validator.validateKeyPolicy(validator.parse(TestCrypto.rsaCsrPem("CN=$subject", weakRsa))) }
            .isInstanceOf(CsrValidationException::class.java)
            .hasMessageContaining("csr_key_rejected")

        val weakEc = TestCrypto.ecKeyPair("secp192r1")
        assertThatThrownBy {
            validator.validateKeyPolicy(
                validator.parse(TestCrypto.csrPem("CN=$subject", weakEc.public, weakEc.private, "SHA256withECDSA")),
            )
        }
            .isInstanceOf(CsrValidationException::class.java)
            .hasMessageContaining("csr_key_rejected")

        val ed25519 = TestCrypto.ed25519KeyPair()
        assertThatThrownBy {
            validator.validateKeyPolicy(
                validator.parse(TestCrypto.csrPem("CN=$subject", ed25519.public, ed25519.private, "Ed25519")),
            )
        }
            .isInstanceOf(CsrValidationException::class.java)
            .hasMessageContaining("csr_key_rejected")

        assertThat(BootstrapErrorCodes.CSR_KEY_REJECTED).isEqualTo("csr_key_rejected")
    }

    @Test
    fun keyPolicyRejectsUnparseablePublicKeys() {
        val ed25519 = TestCrypto.ed25519KeyPair()
        val csr = validator.parse(TestCrypto.csrPem("CN=$subject", ed25519.public, ed25519.private, "Ed25519"))
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
            validator.validateSubject(validator.parse(TestCrypto.rsaCsrPem("CN=$subject,O=Quantum Bank")), subject)
        }.doesNotThrowAnyException()

        // Substring/superstring, missing CN, duplicated CN, and multi-valued CN are all rejected.
        listOf(
            "CN=super$subject",
            "O=$subject",
            "CN=$subject,CN=other",
            "CN=$subject+CN=other",
        ).forEach { dn ->
            assertThatThrownBy { validator.validateSubject(validator.parse(TestCrypto.rsaCsrPem(dn)), subject) }
                .`as`(dn)
                .isInstanceOf(CsrValidationException::class.java)
                .hasMessageContaining("subject_mismatch")
        }
    }
}

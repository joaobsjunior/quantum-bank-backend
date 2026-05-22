package com.quantumbank.backend.bootstrap

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test

class BootstrapCsrValidationTest {

    private val validator = CsrValidator()

    @Test
    fun parsesCertificateRequestAndComputesStableFingerprint() {
        val parsed = validator.parse(VALID_CSR)
        val firstFingerprint = validator.fingerprintSha256(parsed)
        val secondFingerprint = validator.fingerprintSha256(validator.parse(VALID_CSR))

        assertThat(firstFingerprint).hasSize(64)
        assertThat(secondFingerprint).isEqualTo(firstFingerprint)
    }

    @Test
    fun rejectsMalformedCsrAndEmbeddedPrivateKeyMaterial() {
        assertThatThrownBy { validator.parse("not-a-csr") }
            .isInstanceOf(CsrValidationException::class.java)
            .hasMessageContaining("csr_invalid")

        assertThatThrownBy {
            validator.rejectPrivateKeyMaterial(
                """
                -----BEGIN PRIVATE KEY-----
                redacted
                -----END PRIVATE KEY-----
                """.trimIndent(),
            )
        }
            .isInstanceOf(CsrValidationException::class.java)
            .hasMessageContaining("private_key_rejected")

        assertThat(BootstrapErrorCodes.CSR_INVALID).isEqualTo("csr_invalid")
        assertThat(BootstrapErrorCodes.PRIVATE_KEY_REJECTED).isEqualTo("private_key_rejected")
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

    private companion object {
        const val VALID_CSR = """
-----BEGIN CERTIFICATE REQUEST-----
MIICjzCCAXcCAQAwSjEgMB4GA1UEAwwXYWxpY2VAcXVhbnR1bWJhbmsubG9jYWwx
FTATBgNVBAoMDFF1YW50dW0gQmFuazEPMA0GA1UECwwGTW9iaWxlMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzQr0h5BDvHgVA4qHtO6XI5YUxOLDJ+Xu
egrQntEpjPPRIla2AKmnIGBdylVxVxt4bEXjsNGAhxnpb2AIrL4NiDZtQcjnnheo
9F3kiHfpx60ONC53foaG4J1k1N0/6/5cpM7bO2v+MGHqZTaMF0Fx307ai/2LzgAP
0pbdp4Q+/TkP2TQ8oJs7qzE/8GKz0Ed8fdSZV/3BixC8gdLfAD/oDiXa9yXKz8Zw
SAA/5pWcLDejZJaGjgy6OQtGJA6p/E0v7Q7TtOpXl1Sv+JY4O5k092Cd7BFXeogm
HMR+kgUIVtmV/PRB/kE2uKZdTvZYQbHqlME4za8xie0S1Z4viuovuQIDAQABoAAw
DQYJKoZIhvcNAQELBQADggEBAEdPV1Q/3RwwxfcJerSchT9XyZK36RVOWLJ+Znpw
iemPAmOFyENkjJ5L0kv363H6OaWzUER4JsV6GHbePvdN1YYcG9iLGe0Ne/oq6p4+
AqeT02S75uZlnNIoehmQ26YnMl/oSb+sGqxFuG6KU3Bu43IGkTmn+K4++SDiCMB1
qrs2V+2TPmd/GvAUT7Ouo8nNuqRlO0oB8ph/SnV821djkTiE0Rx7uej71g2exyT6
zlTwLJW4P4lnlEQJEyj787ndkc3BTfcF805nrXP0zUA/EYp9RXmIH58lceecNtSh
eJo9cn++UcwyIZ1B8XEcXILeGKWReRChZtXY4/vXwItEuls=
-----END CERTIFICATE REQUEST-----
"""
    }
}

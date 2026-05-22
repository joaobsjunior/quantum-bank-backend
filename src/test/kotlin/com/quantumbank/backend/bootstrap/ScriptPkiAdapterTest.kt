package com.quantumbank.backend.bootstrap

import com.quantumbank.backend.security.SecurityProperties
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.time.Instant

class ScriptPkiAdapterTest {

    @Test
    fun includesConfiguredIssuingCertificateInResponseChain() {
        val tempDir = Files.createTempDirectory("script-pki-adapter-test-")
        val script = tempDir.resolve("sign-csr.sh")
        val issuingCertificate = tempDir.resolve("issuing-ca.crt")
        val leafPem = """
            -----BEGIN CERTIFICATE-----
            leaf
            -----END CERTIFICATE-----
        """.trimIndent() + "\n"
        val issuingPem = """
            -----BEGIN CERTIFICATE-----
            issuing
            -----END CERTIFICATE-----
        """.trimIndent() + "\n"

        try {
            Files.writeString(
                script,
                "#!/bin/sh\n" +
                    "cat > \"${'$'}2\" <<'EOF'\n" +
                    leafPem +
                    "EOF\n",
            )
            script.toFile().setExecutable(true)
            Files.writeString(issuingCertificate, issuingPem)

            val adapter = ScriptPkiAdapter(
                SecurityProperties(
                    pki = SecurityProperties.PkiProperties(
                        signCommand = script.toString(),
                        issuingCert = issuingCertificate.toString(),
                    ),
                ),
            )

            val result = adapter.sign(
                PkiSignRequest(
                    csrPem = "csr",
                    oauth2Subject = "00000000-0000-0000-0000-000000000001",
                    appInstanceId = "app-local-001",
                    deviceId = "device-local-001",
                    certificateProfile = "quantum-bank-mobile-client-v1",
                    environment = "local",
                    csrFingerprint = "fingerprint",
                    correlationId = "corr-test",
                ),
            )

            assertThat(result.certificate).isEqualTo(leafPem)
            assertThat(result.certificateChain).containsExactly(leafPem, issuingPem)
            assertThat(result.expiresAt).isAfter(Instant.now())
        } finally {
            Files.deleteIfExists(issuingCertificate)
            Files.deleteIfExists(script)
            Files.deleteIfExists(tempDir)
        }
    }
}

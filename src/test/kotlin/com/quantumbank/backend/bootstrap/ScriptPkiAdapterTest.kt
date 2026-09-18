package com.quantumbank.backend.bootstrap

import com.quantumbank.backend.security.SecurityProperties
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.time.Duration
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

    @Test
    fun prefersTheIssuerCertificateWrittenByTheSignScript() {
        // sign-csr.sh writes `<leaf>.issuer` with the issuing CA of the chain it
        // selected (post-quantum or compatibility); the configured issuing
        // certificate is only a fallback for scripts that do not emit it.
        val tempDir = Files.createTempDirectory("script-pki-adapter-test-")
        val script = tempDir.resolve("sign-csr.sh")
        val configuredIssuing = tempDir.resolve("issuing-ca.crt")
        val leafPem = "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n"
        val compatIssuingPem = "-----BEGIN CERTIFICATE-----\ncompat-issuing\n-----END CERTIFICATE-----\n"

        try {
            Files.writeString(
                script,
                "#!/bin/sh\n" +
                    "cat > \"${'$'}2\" <<'EOF'\n" + leafPem + "EOF\n" +
                    "cat > \"${'$'}2.issuer\" <<'EOF'\n" + compatIssuingPem + "EOF\n",
            )
            script.toFile().setExecutable(true)
            Files.writeString(configuredIssuing, "-----BEGIN CERTIFICATE-----\nconfigured\n-----END CERTIFICATE-----\n")

            val adapter = ScriptPkiAdapter(
                SecurityProperties(
                    pki = SecurityProperties.PkiProperties(
                        signCommand = script.toString(),
                        issuingCert = configuredIssuing.toString(),
                    ),
                ),
            )

            val result = adapter.sign(signRequest())

            assertThat(result.certificateChain).containsExactly(leafPem, compatIssuingPem)
        } finally {
            Files.deleteIfExists(configuredIssuing)
            Files.deleteIfExists(script)
            Files.deleteIfExists(tempDir)
        }
    }

    @Test
    fun returnsSingleElementChainWhenIssuingCertificateIsAbsent() {
        val tempDir = Files.createTempDirectory("script-pki-adapter-test-")
        val script = tempDir.resolve("sign-csr.sh")
        val leafPem = "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n"

        try {
            Files.writeString(script, "#!/bin/sh\ncat > \"${'$'}2\" <<'EOF'\n" + leafPem + "EOF\n")
            script.toFile().setExecutable(true)

            val adapter = ScriptPkiAdapter(
                SecurityProperties(
                    pki = SecurityProperties.PkiProperties(
                        signCommand = script.toString(),
                        issuingCert = tempDir.resolve("missing-issuing.crt").toString(),
                    ),
                ),
            )

            val result = adapter.sign(signRequest())

            assertThat(result.certificateChain).containsExactly(leafPem)
        } finally {
            Files.deleteIfExists(script)
            Files.deleteIfExists(tempDir)
        }
    }

    @Test
    fun throwsPkiHandoffWhenSignScriptExitsNonZero() {
        val tempDir = Files.createTempDirectory("script-pki-adapter-test-")
        val script = tempDir.resolve("sign-csr.sh")

        try {
            Files.writeString(script, "#!/bin/sh\necho failure\nexit 1\n")
            script.toFile().setExecutable(true)

            val adapter = ScriptPkiAdapter(
                SecurityProperties(pki = SecurityProperties.PkiProperties(signCommand = script.toString())),
            )

            assertThatThrownBy { adapter.sign(signRequest()) }
                .isInstanceOf(PkiHandoffException::class.java)
        } finally {
            Files.deleteIfExists(script)
            Files.deleteIfExists(tempDir)
        }
    }

    @Test
    fun throwsPkiHandoffWhenSignScriptTimesOut() {
        val tempDir = Files.createTempDirectory("script-pki-adapter-test-")
        val script = tempDir.resolve("sign-csr.sh")

        try {
            Files.writeString(script, "#!/bin/sh\nsleep 5\n")
            script.toFile().setExecutable(true)

            val adapter = ScriptPkiAdapter(
                SecurityProperties(
                    pki = SecurityProperties.PkiProperties(
                        signCommand = script.toString(),
                        signTimeout = Duration.ofMillis(200),
                    ),
                ),
            )

            assertThatThrownBy { adapter.sign(signRequest()) }
                .isInstanceOf(PkiHandoffException::class.java)
                .hasMessageContaining("timed out")
        } finally {
            Files.deleteIfExists(script)
            Files.deleteIfExists(tempDir)
        }
    }

    @Test
    fun refusesToSpawnTheSignScriptWithUnsafeIdentifiers() {
        val adapter = ScriptPkiAdapter(SecurityProperties())

        listOf(
            signRequest().copy(deviceId = "device\n[v3_client]\nbasicConstraints=CA:TRUE"),
            signRequest().copy(appInstanceId = "app \${ENV::HOME}"),
            signRequest().copy(oauth2Subject = "alice\nmallory"),
            signRequest().copy(environment = "local # comment"),
            signRequest().copy(certificateProfile = "Profile With Spaces"),
        ).forEach { request ->
            assertThatThrownBy { adapter.sign(request) }
                .isInstanceOf(PkiHandoffException::class.java)
                .hasMessageContaining("unsafe identifier")
        }
    }

    @Test
    fun usesTheIssuedCertificateValidityWhenItParses() {
        val tempDir = Files.createTempDirectory("script-pki-adapter-test-")
        val script = tempDir.resolve("sign-csr.sh")
        val notAfter = Instant.ofEpochSecond(Instant.now().plusSeconds(600).epochSecond)
        val certificatePem = TestCrypto.pem(TestCrypto.selfSignedCertificate("CN=alice", notAfter = notAfter))

        try {
            Files.writeString(script, "#!/bin/sh\ncat > \"${'$'}2\" <<'EOF'\n" + certificatePem + "EOF\n")
            script.toFile().setExecutable(true)
            val adapter = ScriptPkiAdapter(
                SecurityProperties(pki = SecurityProperties.PkiProperties(signCommand = script.toString())),
            )

            val result = adapter.sign(signRequest())

            assertThat(result.expiresAt).isEqualTo(notAfter)
            assertThat(adapter.certificateNotAfter("garbage")).isNull()
        } finally {
            Files.deleteIfExists(script)
            Files.deleteIfExists(tempDir)
        }
    }

    private fun signRequest(): PkiSignRequest =
        PkiSignRequest(
            csrPem = "csr",
            oauth2Subject = "alice@quantumbank.local",
            appInstanceId = "app-local-001",
            deviceId = "device-local-001",
            certificateProfile = "quantum-bank-mobile-client-v1",
            environment = "local",
            csrFingerprint = "fingerprint",
            correlationId = "corr-test",
        )
}

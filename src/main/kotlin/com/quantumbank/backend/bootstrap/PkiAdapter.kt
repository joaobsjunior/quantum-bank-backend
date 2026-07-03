package com.quantumbank.backend.bootstrap

import com.quantumbank.backend.security.SecurityProperties
import org.springframework.stereotype.Component
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import java.util.concurrent.TimeUnit

interface PkiAdapter {
    fun sign(request: PkiSignRequest): PkiSignResult
}

data class PkiSignRequest(
    val csrPem: String,
    val oauth2Subject: String,
    val appInstanceId: String,
    val deviceId: String,
    val certificateProfile: String,
    val environment: String,
    val csrFingerprint: String,
    val correlationId: String,
)

data class PkiSignResult(
    val certificate: String,
    val certificateChain: List<String>,
    val expiresAt: Instant,
)

class PkiHandoffException(
    message: String,
) : RuntimeException(message)

@Component
class ScriptPkiAdapter(
    private val securityProperties: SecurityProperties,
) : PkiAdapter {

    override fun sign(request: PkiSignRequest): PkiSignResult {
        val tempDir = Files.createTempDirectory("quantum-bank-csr-")
        val csrPath = tempDir.resolve("request.csr")
        val certificatePath = tempDir.resolve("client.crt")

        try {
            Files.writeString(csrPath, request.csrPem)

            val process = ProcessBuilder(
                securityProperties.pki.signCommand,
                csrPath.toString(),
                certificatePath.toString(),
                request.oauth2Subject,
                request.appInstanceId,
                request.deviceId,
                request.environment,
                request.certificateProfile,
            )
                .redirectErrorStream(true)
                .start()

            val completed = process.waitFor(securityProperties.pki.signTimeout.toMillis(), TimeUnit.MILLISECONDS)
            val output = process.inputStream.bufferedReader().readText().trim()
            if (!completed) {
                process.destroyForcibly()
                throw PkiHandoffException("sign-csr.sh timed out")
            }
            if (process.exitValue() != 0) {
                throw PkiHandoffException("sign-csr.sh failed: $output")
            }

            val certificate = Files.readString(certificatePath)
            val issuingCertificatePath = Path.of(securityProperties.pki.issuingCert)
            val certificateChain =
                if (Files.exists(issuingCertificatePath)) {
                    listOf(certificate, Files.readString(issuingCertificatePath))
                } else {
                    listOf(certificate)
                }
            return PkiSignResult(
                certificate = certificate,
                certificateChain = certificateChain,
                expiresAt = Instant.now().plusSeconds(86_400),
            )
        } finally {
            Files.deleteIfExists(certificatePath)
            Files.deleteIfExists(csrPath)
            Files.deleteIfExists(tempDir)
        }
    }
}

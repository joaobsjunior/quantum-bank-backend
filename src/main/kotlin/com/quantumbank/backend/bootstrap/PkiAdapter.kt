package com.quantumbank.backend.bootstrap

import com.quantumbank.backend.security.SecurityProperties
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.openssl.PEMParser
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Component
import java.io.StringReader
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
    private val logger = LoggerFactory.getLogger(ScriptPkiAdapter::class.java)

    override fun sign(request: PkiSignRequest): PkiSignResult {
        // Last line of defence before values reach the OpenSSL configuration
        // written by the sign script: never spawn the process with anything
        // outside the canonical identifier formats.
        requireSafeArguments(request)

        val tempDir = Files.createTempDirectory("quantum-bank-csr-")
        val csrPath = tempDir.resolve("request.csr")
        val certificatePath = tempDir.resolve("client.crt")
        val outputPath = tempDir.resolve("sign.log")

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
                // Redirect to a file instead of a pipe so a chatty script can
                // never block on a full stdout buffer and hang the request.
                .redirectOutput(outputPath.toFile())
                .start()

            val completed = process.waitFor(securityProperties.pki.signTimeout.toMillis(), TimeUnit.MILLISECONDS)
            if (!completed) {
                process.destroyForcibly()
                process.waitFor()
                throw PkiHandoffException("sign-csr.sh timed out")
            }
            if (process.exitValue() != 0) {
                val output = Files.readString(outputPath).trim()
                logger.warn("event=pki.sign_failed correlationId={} exit={} output={}", request.correlationId, process.exitValue(), output)
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
                expiresAt = certificateNotAfter(certificate) ?: Instant.now().plusSeconds(DEFAULT_VALIDITY_SECONDS),
            )
        } finally {
            Files.deleteIfExists(outputPath)
            Files.deleteIfExists(certificatePath)
            Files.deleteIfExists(csrPath)
            Files.deleteIfExists(tempDir)
        }
    }

    internal fun requireSafeArguments(request: PkiSignRequest) {
        val safe = BootstrapIdentifiers.isSubject(request.oauth2Subject) &&
            BootstrapIdentifiers.isClientIdentifier(request.appInstanceId) &&
            BootstrapIdentifiers.isClientIdentifier(request.deviceId) &&
            BootstrapIdentifiers.isEnvironment(request.environment) &&
            BootstrapIdentifiers.isCertificateProfile(request.certificateProfile)
        if (!safe) {
            throw PkiHandoffException("refusing PKI handoff with unsafe identifier values")
        }
    }

    /** Reads the real validity end from the issued certificate when it parses. */
    internal fun certificateNotAfter(certificatePem: String): Instant? =
        try {
            PEMParser(StringReader(certificatePem)).use { parser ->
                (parser.readObject() as? X509CertificateHolder)?.notAfter?.toInstant()
            }
        } catch (_: Exception) {
            null
        }

    private companion object {
        const val DEFAULT_VALIDITY_SECONDS = 86_400L
    }
}

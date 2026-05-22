package com.quantumbank.backend.bootstrap

import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.springframework.stereotype.Component
import java.io.StringReader
import java.security.MessageDigest

class CsrValidationException(
    val errorCode: String,
) : RuntimeException(errorCode)

@Component
class CsrValidator {

    fun rejectPrivateKeyMaterial(value: String) {
        if (PRIVATE_KEY_MARKERS.any { marker -> value.contains(marker, ignoreCase = true) }) {
            throw CsrValidationException(BootstrapErrorCodes.PRIVATE_KEY_REJECTED)
        }
    }

    fun parse(value: String): PKCS10CertificationRequest {
        rejectPrivateKeyMaterial(value)

        return try {
            PEMParser(StringReader(value.trim())).use { parser ->
                val parsed = parser.readObject()
                parsed as? PKCS10CertificationRequest
                    ?: throw CsrValidationException(BootstrapErrorCodes.CSR_INVALID)
            }
        } catch (exception: CsrValidationException) {
            throw exception
        } catch (_: Exception) {
            throw CsrValidationException(BootstrapErrorCodes.CSR_INVALID)
        }
    }

    fun fingerprintSha256(csr: PKCS10CertificationRequest): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(csr.encoded)
        return digest.joinToString(separator = "") { byte -> "%02x".format(byte) }
    }

    fun validateProfileAndEnvironment(
        certificateProfile: String,
        environment: String,
        expectedCertificateProfile: String,
        expectedEnvironment: String,
    ) {
        if (certificateProfile != expectedCertificateProfile) {
            throw CsrValidationException(BootstrapErrorCodes.CERTIFICATE_PROFILE_MISMATCH)
        }
        if (environment != expectedEnvironment) {
            throw CsrValidationException(BootstrapErrorCodes.UNSUPPORTED_ENVIRONMENT)
        }
    }

    fun validateSubject(csr: PKCS10CertificationRequest, oauth2Subject: String) {
        if (!csr.subject.toString().contains(oauth2Subject)) {
            throw CsrValidationException(BootstrapErrorCodes.SUBJECT_MISMATCH)
        }
    }

    private companion object {
        val PRIVATE_KEY_MARKERS = listOf(
            "BEGIN PRIVATE KEY",
            "BEGIN RSA PRIVATE KEY",
            "BEGIN EC PRIVATE KEY",
        )
    }
}

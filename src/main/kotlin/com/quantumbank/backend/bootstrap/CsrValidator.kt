package com.quantumbank.backend.bootstrap

import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x500.style.IETFUtils
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.crypto.util.PublicKeyFactory
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.springframework.stereotype.Component
import java.io.StringReader
import java.security.MessageDigest
import java.security.Security

class CsrValidationException(
    val errorCode: String,
) : RuntimeException(errorCode)

@Component
class CsrValidator {

    init {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    private val privateKeyMarkers = listOf(
        "BEGIN PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
        "BEGIN EC PRIVATE KEY",
        "BEGIN ENCRYPTED PRIVATE KEY",
        "BEGIN OPENSSH PRIVATE KEY",
    )

    fun rejectPrivateKeyMaterial(value: String) {
        if (privateKeyMarkers.any { marker -> value.contains(marker, ignoreCase = true) }) {
            throw CsrValidationException(BootstrapErrorCodes.PRIVATE_KEY_REJECTED)
        }
    }

    /**
     * Parses exactly one PEM-encoded PKCS#10 request and verifies its
     * self-signature, which is the proof that the requester holds the private
     * key for the public key it wants certified. Without this check the CA
     * would certify arbitrary public keys.
     */
    fun parse(value: String): PKCS10CertificationRequest {
        rejectPrivateKeyMaterial(value)
        if (value.length > BootstrapIdentifiers.CSR_MAX_LENGTH) {
            throw CsrValidationException(BootstrapErrorCodes.CSR_INVALID)
        }

        val csr = try {
            PEMParser(StringReader(value.trim())).use { parser ->
                val parsed = parser.readObject() as? PKCS10CertificationRequest
                    ?: throw CsrValidationException(BootstrapErrorCodes.CSR_INVALID)
                if (parser.readObject() != null) {
                    throw CsrValidationException(BootstrapErrorCodes.CSR_INVALID)
                }
                parsed
            }
        } catch (exception: CsrValidationException) {
            throw exception
        } catch (_: Exception) {
            throw CsrValidationException(BootstrapErrorCodes.CSR_INVALID)
        }

        if (!hasValidProofOfPossession(csr)) {
            throw CsrValidationException(BootstrapErrorCodes.CSR_INVALID)
        }
        return csr
    }

    internal fun hasValidProofOfPossession(csr: PKCS10CertificationRequest): Boolean =
        try {
            csr.isSignatureValid(
                JcaContentVerifierProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(csr.subjectPublicKeyInfo),
            )
        } catch (_: Exception) {
            false
        }

    /**
     * Only keys the mobile profile is allowed to enroll: RSA >= 2048 bits or
     * EC curves with a field size >= 256 bits.
     */
    fun validateKeyPolicy(csr: PKCS10CertificationRequest) {
        val key = try {
            PublicKeyFactory.createKey(csr.subjectPublicKeyInfo)
        } catch (_: Exception) {
            throw CsrValidationException(BootstrapErrorCodes.CSR_KEY_REJECTED)
        }
        val acceptable = when (key) {
            is RSAKeyParameters -> key.modulus.bitLength() >= MIN_RSA_BITS
            is ECPublicKeyParameters -> key.parameters.curve.fieldSize >= MIN_EC_FIELD_BITS
            else -> false
        }
        if (!acceptable) {
            throw CsrValidationException(BootstrapErrorCodes.CSR_KEY_REJECTED)
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

    /**
     * The CSR subject must carry exactly one CN and it must equal the OAuth2
     * subject byte for byte. A substring match would let `user` enroll a
     * certificate for `superuser`.
     */
    fun validateSubject(csr: PKCS10CertificationRequest, oauth2Subject: String) {
        val commonNames = csr.subject.getRDNs(BCStyle.CN)
        if (commonNames.size != 1 || commonNames[0].isMultiValued) {
            throw CsrValidationException(BootstrapErrorCodes.SUBJECT_MISMATCH)
        }
        val commonName = IETFUtils.valueToString(commonNames[0].first.value)
        if (commonName != oauth2Subject) {
            throw CsrValidationException(BootstrapErrorCodes.SUBJECT_MISMATCH)
        }
    }

    private companion object {
        const val MIN_RSA_BITS = 2048
        const val MIN_EC_FIELD_BITS = 256
    }
}

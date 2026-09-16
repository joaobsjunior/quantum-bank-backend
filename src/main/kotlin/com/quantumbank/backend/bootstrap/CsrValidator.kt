package com.quantumbank.backend.bootstrap

import com.quantumbank.backend.security.PostQuantumTls

import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x500.style.IETFUtils
import org.bouncycastle.crypto.params.MLDSAParameters
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters
import org.bouncycastle.crypto.util.PublicKeyFactory
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.springframework.stereotype.Component
import java.io.StringReader
import java.security.MessageDigest

class CsrValidationException(
    val errorCode: String,
) : RuntimeException(errorCode)

@Component
class CsrValidator {

    init {
        // ML-DSA parsing, proof-of-possession verification and the TLS policy
        // share one installer (idempotent).
        PostQuantumTls.install()
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
     * Only post-quantum keys the mobile profile is allowed to enroll: ML-DSA-65
     * (NIST category 3) or ML-DSA-87 (category 5), FIPS 204. Every classical
     * key (RSA, EC, EdDSA) and the lower ML-DSA-44 category are rejected so no
     * certificate that the gateway would refuse at the TLS layer is ever
     * issued.
     */
    fun validateKeyPolicy(csr: PKCS10CertificationRequest) {
        val key = try {
            PublicKeyFactory.createKey(csr.subjectPublicKeyInfo)
        } catch (_: Exception) {
            throw CsrValidationException(BootstrapErrorCodes.CSR_KEY_REJECTED)
        }
        val acceptable = key is MLDSAPublicKeyParameters && key.parameters in ACCEPTED_ML_DSA_PARAMETERS
        if (!acceptable) {
            throw CsrValidationException(BootstrapErrorCodes.CSR_KEY_REJECTED)
        }
    }

    /** Canonical name of the accepted post-quantum algorithm carried by the CSR. */
    fun keyAlgorithmName(csr: PKCS10CertificationRequest): String {
        val key = PublicKeyFactory.createKey(csr.subjectPublicKeyInfo) as MLDSAPublicKeyParameters
        return key.parameters.name.uppercase()
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

    companion object {
        /** FIPS 204 parameter sets accepted for `quantum-bank-mobile-client-v1`. */
        val ACCEPTED_ML_DSA_PARAMETERS: Set<MLDSAParameters> = setOf(MLDSAParameters.ml_dsa_65, MLDSAParameters.ml_dsa_87)
    }
}

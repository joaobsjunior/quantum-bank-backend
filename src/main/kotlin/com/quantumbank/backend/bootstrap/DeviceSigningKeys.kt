package com.quantumbank.backend.bootstrap

import com.quantumbank.backend.envelope.EnvelopeErrorCodes
import com.quantumbank.backend.security.PostQuantumTls
import org.bouncycastle.jcajce.spec.ContextParameterSpec
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec
import org.bouncycastle.jcajce.spec.MLDSAPublicKeySpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Component
import org.springframework.stereotype.Repository
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.sql.Timestamp
import java.time.Clock
import java.time.Instant
import java.util.Base64

/** The device's post-quantum signing key registered at enrollment (feature 012). */
data class DeviceSigningKey(
    val subject: String,
    val deviceId: String,
    val algorithm: String,
    val publicKey: ByteArray,
    val registeredAt: Instant,
)

/** `signingKey` object of the CSR submission. */
data class SigningKeyRegistration(
    val alg: String,
    val publicKey: String,
    val proof: String,
)

class SigningKeyException(
    val errorCode: String,
    message: String,
) : RuntimeException(message)

/** ML-DSA-65 verification shared by the registration proof and the Pix signature. */
object MlDsa65 {
    const val ALGORITHM = "ML-DSA-65"
    const val PUBLIC_KEY_LENGTH = 1952

    init {
        PostQuantumTls.install()
    }

    fun publicKey(raw: ByteArray): PublicKey =
        KeyFactory.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME)
            .generatePublic(MLDSAPublicKeySpec(MLDSAParameterSpec.ml_dsa_65, raw))

    /** Null when [raw] is not a well-formed FIPS 204 ML-DSA-65 public key. */
    fun publicKeyOrNull(raw: ByteArray): PublicKey? =
        try {
            publicKey(raw)
        } catch (_: Exception) {
            null
        }

    fun verify(publicKey: PublicKey, message: ByteArray, signature: ByteArray, context: ByteArray): Boolean =
        try {
            val verifier = Signature.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME)
            verifier.setParameter(ContextParameterSpec(context))
            verifier.initVerify(publicKey)
            verifier.update(message)
            verifier.verify(signature)
        } catch (_: Exception) {
            false
        }
}

/**
 * Validates a signing-key registration: the algorithm must be ML-DSA-65, the
 * public key a well-formed FIPS 204 key, and the proof an ML-DSA-65 signature
 * over the DER of the very CSR being submitted (context
 * `quantum-bank-signing-key-v1`), which binds the key to the OTK, subject and
 * device that authorize the certificate.
 */
@Component
class SigningKeyValidator {

    /** Returns the raw public key of a valid registration. */
    fun validate(registration: SigningKeyRegistration, csrPem: String): ByteArray {
        if (registration.alg != MlDsa65.ALGORITHM) {
            throw SigningKeyException(EnvelopeErrorCodes.SIGNING_KEY_INVALID, "unsupported signing key algorithm ${registration.alg}")
        }
        val raw = decode(registration.publicKey)
        val proof = decode(registration.proof)
        // A malformed or wrong-length key never reaches the verifier: the key
        // factory validates the FIPS 204 encoding.
        val publicKey = MlDsa65.publicKeyOrNull(raw)
            ?: throw SigningKeyException(EnvelopeErrorCodes.SIGNING_KEY_INVALID, "signing key is not a valid ML-DSA-65 key")
        if (!MlDsa65.verify(publicKey, csrDer(csrPem), proof, REGISTRATION_CONTEXT)) {
            throw SigningKeyException(EnvelopeErrorCodes.SIGNING_KEY_INVALID, "signing key proof of possession does not verify")
        }
        return raw
    }

    /** The DER bytes exactly as the app signed them: the PEM body, never a re-encoding. */
    internal fun csrDer(csrPem: String): ByteArray {
        val body = csrPem.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("-----") }
            .joinToString("")
        return decode(body)
    }

    private fun decode(value: String): ByteArray =
        try {
            Base64.getDecoder().decode(value)
        } catch (_: IllegalArgumentException) {
            throw SigningKeyException(EnvelopeErrorCodes.SIGNING_KEY_INVALID, "signing key registration is not base64")
        }

    companion object {
        val REGISTRATION_CONTEXT: ByteArray = "quantum-bank-signing-key-v1".toByteArray(Charsets.UTF_8)
    }
}

@Repository
class DeviceSigningKeyRepository(
    private val jdbcTemplate: JdbcTemplate,
    private val clock: Clock,
) {
    /** Registers or replaces the key of (subject, deviceId): a re-enrollment rotates it. */
    fun register(subject: String, deviceId: String, algorithm: String, publicKey: ByteArray): DeviceSigningKey {
        val now = clock.instant()
        jdbcTemplate.update(
            """
            MERGE INTO device_signing_keys (subject, device_id, algorithm, public_key, registered_at)
            KEY (subject, device_id)
            VALUES (?, ?, ?, ?, ?)
            """.trimIndent(),
            subject,
            deviceId,
            algorithm,
            publicKey,
            Timestamp.from(now),
        )
        return DeviceSigningKey(subject, deviceId, algorithm, publicKey, now)
    }

    fun find(subject: String, deviceId: String): DeviceSigningKey? =
        jdbcTemplate.query(
            """
            SELECT subject, device_id, algorithm, public_key, registered_at
            FROM device_signing_keys
            WHERE subject = ? AND device_id = ?
            """.trimIndent(),
            { rs, _ ->
                DeviceSigningKey(
                    subject = rs.getString("subject"),
                    deviceId = rs.getString("device_id"),
                    algorithm = rs.getString("algorithm"),
                    publicKey = rs.getBytes("public_key"),
                    registeredAt = rs.getTimestamp("registered_at").toInstant(),
                )
            },
            subject,
            deviceId,
        ).firstOrNull()
}

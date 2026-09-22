package com.quantumbank.backend.banking

import com.quantumbank.backend.bootstrap.DeviceSigningKeyRepository
import com.quantumbank.backend.bootstrap.MlDsa65
import com.quantumbank.backend.envelope.EnvelopeErrorCodes
import com.quantumbank.backend.envelope.EnvelopeProperties
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Pattern
import jakarta.validation.constraints.Size
import org.springframework.dao.DuplicateKeyException
import org.springframework.http.HttpStatus
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Component
import org.springframework.stereotype.Repository
import java.math.BigDecimal
import java.math.RoundingMode
import java.sql.Timestamp
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.format.DateTimeParseException
import java.util.Base64

/** `signature` object of a Pix order (contract `envelope-v1`). */
data class TransactionSignatureRequest(
    @field:NotBlank
    @field:Size(max = 20)
    val alg: String,
    @field:NotBlank
    @field:Pattern(regexp = "^[A-Za-z0-9._-]{1,160}$")
    val deviceId: String,
    @field:NotBlank
    @field:Pattern(regexp = "^[0-9a-fA-F-]{36}$")
    val nonce: String,
    @field:NotBlank
    @field:Size(max = 40)
    val issuedAt: String,
    @field:NotBlank
    @field:Size(max = 8192)
    val value: String,
)

/** A verified signature, stored with the attempt for audit and non-repudiation. */
data class VerifiedTransactionSignature(
    val algorithm: String,
    val deviceId: String,
    val nonce: String,
    val issuedAt: Instant,
    val signature: ByteArray,
)

/**
 * Verifies the ML-DSA-65 signature of a Pix order with the device key
 * registered at enrollment, rejects replays (nonce) and stale orders
 * (`issuedAt` skew), and records the verified signature. Required for the
 * OAuth2 clients on the dual TLS tier; strict-tier service clients are
 * exempt, like the envelope.
 */
@Component
class PixSignatureVerifier(
    private val properties: EnvelopeProperties,
    private val signingKeys: DeviceSigningKeyRepository,
    private val signatures: TransactionSignatureRepository,
    private val clock: Clock,
) {
    fun verify(subject: String, clientId: String?, request: PixTransferRequest): VerifiedTransactionSignature? {
        val signature = request.signature
        if (signature == null) {
            if (properties.requiresEnvelope(clientId)) {
                throw invalid(EnvelopeErrorCodes.TRANSACTION_SIGNATURE_REQUIRED, "Pix order is not signed")
            }
            return null
        }
        if (signature.alg != MlDsa65.ALGORITHM) {
            throw invalid(EnvelopeErrorCodes.TRANSACTION_SIGNATURE_INVALID, "unsupported signature algorithm")
        }
        val issuedAt = try {
            Instant.parse(signature.issuedAt)
        } catch (_: DateTimeParseException) {
            throw invalid(EnvelopeErrorCodes.TRANSACTION_SIGNATURE_INVALID, "invalid issuedAt")
        }
        val skew = Duration.between(issuedAt, clock.instant()).abs()
        if (skew > properties.signatureMaxSkew) {
            throw invalid(EnvelopeErrorCodes.TRANSACTION_SIGNATURE_INVALID, "signature issued outside the accepted window")
        }
        val deviceKey = signingKeys.find(subject, signature.deviceId)
            ?: throw invalid(EnvelopeErrorCodes.TRANSACTION_SIGNATURE_INVALID, "no signing key registered for this device")
        val value = try {
            Base64.getDecoder().decode(signature.value)
        } catch (_: IllegalArgumentException) {
            throw invalid(EnvelopeErrorCodes.TRANSACTION_SIGNATURE_INVALID, "signature is not base64")
        }
        val message = canonicalMessage(subject, request, signature)
        if (!MlDsa65.verify(MlDsa65.publicKey(deviceKey.publicKey), message, value, CONTEXT)) {
            throw invalid(EnvelopeErrorCodes.TRANSACTION_SIGNATURE_INVALID, "signature does not verify")
        }
        val verified = VerifiedTransactionSignature(
            algorithm = signature.alg,
            deviceId = signature.deviceId,
            nonce = signature.nonce,
            issuedAt = issuedAt,
            signature = value,
        )
        if (!signatures.recordOnce(subject, verified)) {
            throw BankingProblemException(
                errorCode = EnvelopeErrorCodes.TRANSACTION_SIGNATURE_REPLAYED,
                status = HttpStatus.CONFLICT,
                problemTitle = "Pix order replayed",
                detail = "A Pix order with this nonce was already processed.",
            )
        }
        return verified
    }

    private fun invalid(errorCode: String, detail: String) =
        BankingProblemException(
            errorCode = errorCode,
            status = HttpStatus.BAD_REQUEST,
            problemTitle = "Pix signature rejected",
            detail = detail,
        )

    companion object {
        val CONTEXT: ByteArray = "quantum-bank-pix-v1".toByteArray(Charsets.UTF_8)

        /** Canonical message of contract `envelope-v1`, identical to the app's `PixTransactionSigner.canonicalMessage`. */
        fun canonicalMessage(subject: String, request: PixTransferRequest, signature: TransactionSignatureRequest): ByteArray =
            buildString {
                append("quantum-bank-pix-v1\n")
                append(subject).append('\n')
                append(signature.deviceId).append('\n')
                append(canonicalAmount(request.amount)).append('\n')
                append(request.recipientKey).append('\n')
                append(request.description ?: "").append('\n')
                append(request.scenario.name).append('\n')
                append(signature.nonce).append('\n')
                append(signature.issuedAt).append('\n')
            }.toByteArray(Charsets.UTF_8)

        fun canonicalAmount(amount: BigDecimal): String = amount.setScale(2, RoundingMode.HALF_UP).toPlainString()
    }
}

@Repository
class TransactionSignatureRepository(
    private val jdbcTemplate: JdbcTemplate,
    private val clock: Clock,
) {
    /** Inserts the nonce row; false when the nonce was already used (replay). */
    fun recordOnce(subject: String, signature: VerifiedTransactionSignature): Boolean =
        try {
            jdbcTemplate.update(
                """
                INSERT INTO pix_transaction_signatures (nonce, subject, device_id, algorithm, signature, issued_at, verified_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """.trimIndent(),
                signature.nonce,
                subject,
                signature.deviceId,
                signature.algorithm,
                signature.signature,
                Timestamp.from(signature.issuedAt),
                Timestamp.from(clock.instant()),
            )
            true
        } catch (_: DuplicateKeyException) {
            false
        }

    fun attachTransaction(nonce: String, transactionId: String) {
        jdbcTemplate.update(
            "UPDATE pix_transaction_signatures SET transaction_id = ? WHERE nonce = ?",
            transactionId,
            nonce,
        )
    }

    fun findByNonce(nonce: String): Map<String, Any?>? =
        jdbcTemplate.queryForList(
            "SELECT nonce, subject, device_id, transaction_id, algorithm FROM pix_transaction_signatures WHERE nonce = ?",
            nonce,
        ).firstOrNull()
}

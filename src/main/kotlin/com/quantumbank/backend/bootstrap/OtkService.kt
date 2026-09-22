package com.quantumbank.backend.bootstrap

import com.quantumbank.backend.audit.BootstrapAuditEvents
import com.quantumbank.backend.envelope.EnvelopeErrorCodes
import com.quantumbank.backend.envelope.EnvelopeProperties
import com.quantumbank.backend.envelope.HybridEnvelopeKeyService
import com.quantumbank.backend.envelope.SignedEnvelopeKeySet
import com.quantumbank.backend.security.SecurityProperties
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Service
import java.security.SecureRandom
import java.time.Clock
import java.time.Instant
import java.util.Base64

data class OtkIssueRequest(
    val appInstanceId: String,
    val deviceId: String,
    val certificateProfile: String? = null,
)

data class OtkIssueResponse(
    val otk: String,
    val expiresAt: Instant,
    val correlationId: String,
)

data class CsrSubmitRequest(
    val otk: String,
    val csr: String,
    val appInstanceId: String,
    val deviceId: String,
    val certificateProfile: String? = null,
    val environment: String? = null,
    val signingKey: SigningKeyRegistration? = null,
)

data class CsrSubmitResponse(
    val certificate: String,
    val certificateChain: List<String>,
    val expiresAt: Instant,
    val correlationId: String,
    /** The backend's signed envelope key set (feature 012), verified by the app against the ML-DSA-87 root. */
    val envelopeKeys: SignedEnvelopeKeySet,
)

class BootstrapProblemException(
    val errorCode: String,
    val status: HttpStatus,
    val problemTitle: String,
) : RuntimeException(errorCode)

@Service
class OtkService(
    private val repository: InMemoryOtkRepository,
    private val csrValidator: CsrValidator,
    private val pkiAdapter: PkiAdapter,
    private val securityProperties: SecurityProperties,
    private val auditEvents: BootstrapAuditEvents,
    private val clock: Clock,
    private val envelopeProperties: EnvelopeProperties,
    private val envelopeKeyService: HybridEnvelopeKeyService,
    private val signingKeyValidator: SigningKeyValidator,
    private val deviceSigningKeys: DeviceSigningKeyRepository,
) {
    private val secureRandom = SecureRandom()

    fun issue(
        oauth2Subject: String,
        request: OtkIssueRequest,
        correlationId: String,
    ): OtkIssueResponse {
        val profile = request.certificateProfile ?: securityProperties.certificateProfile
        csrValidator.validateProfileAndEnvironment(
            certificateProfile = profile,
            environment = securityProperties.environment,
            expectedCertificateProfile = securityProperties.certificateProfile,
            expectedEnvironment = securityProperties.environment,
        )

        val record = OtkRecord(
            token = nextToken(),
            oauth2Subject = oauth2Subject,
            appInstanceId = request.appInstanceId,
            deviceId = request.deviceId,
            certificateProfile = profile,
            environment = securityProperties.environment,
            expiresAt = clock.instant().plus(securityProperties.otkTtl),
            updatedAt = clock.instant(),
        )
        try {
            repository.save(record)
        } catch (_: OtkCapacityExceededException) {
            throw problem(
                BootstrapErrorCodes.OTK_CAPACITY_EXCEEDED,
                HttpStatus.SERVICE_UNAVAILABLE,
                "OTK issuance temporarily unavailable",
            )
        }
        auditEvents.otkIssued(record, correlationId)

        return OtkIssueResponse(
            otk = record.token,
            expiresAt = record.expiresAt,
            correlationId = correlationId,
        )
    }

    fun submitCsr(
        oauth2Subject: String,
        request: CsrSubmitRequest,
        correlationId: String,
        clientId: String? = null,
    ): CsrSubmitResponse {
        try {
            csrValidator.rejectPrivateKeyMaterial(request.csr)
        } catch (exception: CsrValidationException) {
            auditEvents.csrRejectedPrivateKeyMaterial(correlationId, oauth2Subject)
            throw problem(exception.errorCode, HttpStatus.BAD_REQUEST, "CSR rejected")
        }

        // The signing key is validated before the OTK is consumed, so a bad
        // registration never burns a one-time key.
        val signingPublicKey = validateSigningKey(request, clientId)

        val profile = request.certificateProfile ?: securityProperties.certificateProfile
        val environment = request.environment ?: securityProperties.environment
        validateCsrPolicy(profile, environment)

        val csr = try {
            csrValidator.parse(request.csr)
        } catch (exception: CsrValidationException) {
            throw problem(exception.errorCode, HttpStatus.BAD_REQUEST, "CSR invalid")
        }

        try {
            csrValidator.validateKeyPolicy(csr)
        } catch (exception: CsrValidationException) {
            throw problem(exception.errorCode, HttpStatus.BAD_REQUEST, "CSR key rejected")
        }

        try {
            csrValidator.validateSubject(csr, oauth2Subject)
        } catch (exception: CsrValidationException) {
            throw problem(exception.errorCode, HttpStatus.BAD_REQUEST, "CSR subject mismatch")
        }

        val csrFingerprint = csrValidator.fingerprintSha256(csr)
        val consumedRecord = when (
            val outcome = repository.consumeOnce(
                token = request.otk,
                oauth2Subject = oauth2Subject,
                appInstanceId = request.appInstanceId,
                deviceId = request.deviceId,
                certificateProfile = profile,
                csrFingerprint = csrFingerprint,
            )
        ) {
            is OtkConsumeOutcome.Consumed -> {
                auditEvents.otkConsumed(outcome.record, correlationId)
                outcome.record
            }
            OtkConsumeOutcome.NotFound ->
                throw problem(BootstrapErrorCodes.OTK_NOT_FOUND, HttpStatus.NOT_FOUND, "OTK not found")
            is OtkConsumeOutcome.Expired -> {
                auditEvents.otkExpired(outcome.record, correlationId)
                throw problem(BootstrapErrorCodes.OTK_EXPIRED, HttpStatus.CONFLICT, "OTK expired")
            }
            is OtkConsumeOutcome.Replayed -> {
                auditEvents.otkReplayed(outcome.record, correlationId)
                throw problem(BootstrapErrorCodes.OTK_REPLAYED, HttpStatus.CONFLICT, "OTK replayed")
            }
            is OtkConsumeOutcome.Revoked -> {
                auditEvents.otkRevoked(outcome.record, correlationId)
                throw problem(BootstrapErrorCodes.OTK_REVOKED, HttpStatus.CONFLICT, "OTK revoked")
            }
            is OtkConsumeOutcome.SubjectMismatch -> {
                auditEvents.otkRejectedSubjectMismatch(outcome.record, correlationId)
                throw problem(BootstrapErrorCodes.SUBJECT_MISMATCH, HttpStatus.BAD_REQUEST, "Subject mismatch")
            }
            is OtkConsumeOutcome.DeviceMismatch -> {
                auditEvents.otkRejectedDeviceMismatch(outcome.record, correlationId)
                throw problem(BootstrapErrorCodes.DEVICE_MISMATCH, HttpStatus.BAD_REQUEST, "Device mismatch")
            }
            is OtkConsumeOutcome.CertificateProfileMismatch -> {
                auditEvents.otkRejectedProfileMismatch(outcome.record, correlationId)
                throw problem(
                    BootstrapErrorCodes.CERTIFICATE_PROFILE_MISMATCH,
                    HttpStatus.BAD_REQUEST,
                    "Certificate profile mismatch",
                )
            }
        }

        val pkiResult = try {
            auditEvents.csrAcceptedForPkiHandoff(consumedRecord, correlationId)
            pkiAdapter.sign(
                PkiSignRequest(
                    csrPem = request.csr,
                    oauth2Subject = oauth2Subject,
                    appInstanceId = request.appInstanceId,
                    deviceId = request.deviceId,
                    certificateProfile = profile,
                    environment = environment,
                    csrFingerprint = csrFingerprint,
                    correlationId = correlationId,
                ),
            )
        } catch (_: PkiHandoffException) {
            auditEvents.pkiHandoffFailed(consumedRecord, correlationId)
            throw problem(BootstrapErrorCodes.PKI_HANDOFF_FAILED, HttpStatus.BAD_GATEWAY, "PKI handoff failed")
        }

        if (signingPublicKey != null) {
            deviceSigningKeys.register(oauth2Subject, request.deviceId, MlDsa65.ALGORITHM, signingPublicKey)
            auditEvents.signingKeyRegistered(consumedRecord, correlationId)
        }

        return CsrSubmitResponse(
            certificate = pkiResult.certificate,
            certificateChain = pkiResult.certificateChain,
            expiresAt = pkiResult.expiresAt,
            correlationId = correlationId,
            envelopeKeys = envelopeKeyService.signedKeySet(),
        )
    }

    private fun validateSigningKey(request: CsrSubmitRequest, clientId: String?): ByteArray? {
        val registration = request.signingKey
        if (registration == null) {
            if (envelopeProperties.requiresEnvelope(clientId)) {
                throw problem(EnvelopeErrorCodes.SIGNING_KEY_REQUIRED, HttpStatus.BAD_REQUEST, "Signing key required")
            }
            return null
        }
        return try {
            signingKeyValidator.validate(registration, request.csr)
        } catch (exception: SigningKeyException) {
            throw problem(exception.errorCode, HttpStatus.BAD_REQUEST, "Signing key rejected")
        }
    }

    private fun validateCsrPolicy(certificateProfile: String, environment: String) {
        try {
            csrValidator.validateProfileAndEnvironment(
                certificateProfile = certificateProfile,
                environment = environment,
                expectedCertificateProfile = securityProperties.certificateProfile,
                expectedEnvironment = securityProperties.environment,
            )
        } catch (exception: CsrValidationException) {
            throw problem(exception.errorCode, HttpStatus.BAD_REQUEST, "CSR policy mismatch")
        }
    }

    private fun problem(errorCode: String, status: HttpStatus, title: String): BootstrapProblemException =
        BootstrapProblemException(errorCode, status, title)

    private fun nextToken(): String {
        val bytes = ByteArray(32)
        secureRandom.nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }
}

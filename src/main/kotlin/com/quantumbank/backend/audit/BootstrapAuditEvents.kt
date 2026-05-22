package com.quantumbank.backend.audit

import com.quantumbank.backend.bootstrap.OtkRecord
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Component
import java.security.MessageDigest
import java.time.Instant

@Component
class BootstrapAuditEvents {
    private val logger = LoggerFactory.getLogger(BootstrapAuditEvents::class.java)

    fun otkIssued(record: OtkRecord, correlationId: String) =
        emit("otk.issued", record, correlationId)

    fun otkConsumed(record: OtkRecord, correlationId: String) =
        emit("otk.consumed", record, correlationId)

    fun otkExpired(record: OtkRecord, correlationId: String) =
        emit("otk.expired", record, correlationId)

    fun otkReplayed(record: OtkRecord, correlationId: String) =
        emit("otk.replayed", record, correlationId)

    fun otkRevoked(record: OtkRecord, correlationId: String) =
        emit("otk.revoked", record, correlationId)

    fun otkRejectedSubjectMismatch(record: OtkRecord, correlationId: String) =
        emit("otk.rejected_subject_mismatch", record, correlationId)

    fun otkRejectedDeviceMismatch(record: OtkRecord, correlationId: String) =
        emit("otk.rejected_device_mismatch", record, correlationId)

    fun otkRejectedProfileMismatch(record: OtkRecord, correlationId: String) =
        emit("otk.rejected_certificate_profile_mismatch", record, correlationId)

    fun csrRejectedPrivateKeyMaterial(correlationId: String, oauth2Subject: String) {
        logger.warn(
            "event=csr.rejected_private_key_material oauth2Subject={} correlationId={} timestamp={}",
            oauth2Subject,
            correlationId,
            Instant.now(),
        )
    }

    fun csrAcceptedForPkiHandoff(record: OtkRecord, correlationId: String) =
        emit("csr.accepted_for_pki_handoff", record, correlationId)

    fun pkiHandoffFailed(record: OtkRecord, correlationId: String) =
        emit("csr.pki_handoff_failed", record, correlationId)

    private fun emit(eventName: String, record: OtkRecord, correlationId: String) {
        logger.info(
            "event={} otkId={} oauth2Subject={} appInstanceId={} deviceId={} certificateProfile={} state={} correlationId={} timestamp={}",
            eventName,
            record.token.safeHash(),
            record.oauth2Subject,
            record.appInstanceId,
            record.deviceId,
            record.certificateProfile,
            record.state,
            correlationId,
            Instant.now(),
        )
    }

    private fun String.safeHash(): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(toByteArray())
        return digest.joinToString(separator = "") { byte -> "%02x".format(byte) }.take(16)
    }
}

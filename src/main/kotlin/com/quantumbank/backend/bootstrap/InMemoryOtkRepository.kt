package com.quantumbank.backend.bootstrap

import org.springframework.stereotype.Component
import java.time.Clock
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicReference

enum class OtkState {
    ISSUED,
    CONSUMED,
    EXPIRED,
    REPLAYED,
    REVOKED,
    REJECTED_SUBJECT_MISMATCH,
    REJECTED_DEVICE_MISMATCH,
    REJECTED_CERTIFICATE_PROFILE_MISMATCH,
}

data class OtkRecord(
    val token: String,
    val oauth2Subject: String,
    val appInstanceId: String,
    val deviceId: String,
    val certificateProfile: String,
    val environment: String,
    val expiresAt: Instant,
    val state: OtkState = OtkState.ISSUED,
    val csrFingerprint: String? = null,
    val consumedAt: Instant? = null,
    val updatedAt: Instant? = null,
)

sealed interface OtkConsumeOutcome {
    data class Consumed(val record: OtkRecord) : OtkConsumeOutcome
    data object NotFound : OtkConsumeOutcome
    data class Expired(val record: OtkRecord) : OtkConsumeOutcome
    data class Replayed(val record: OtkRecord) : OtkConsumeOutcome
    data class Revoked(val record: OtkRecord) : OtkConsumeOutcome
    data class SubjectMismatch(val record: OtkRecord) : OtkConsumeOutcome
    data class DeviceMismatch(val record: OtkRecord) : OtkConsumeOutcome
    data class CertificateProfileMismatch(val record: OtkRecord) : OtkConsumeOutcome
}

@Component
class InMemoryOtkRepository(
    private val clock: Clock,
) {
    private val records = ConcurrentHashMap<String, OtkRecord>()

    fun save(record: OtkRecord): OtkRecord {
        records[record.token] = record
        return record
    }

    fun find(token: String): OtkRecord? = records[token]

    fun consumeOnce(
        token: String,
        oauth2Subject: String,
        appInstanceId: String,
        deviceId: String,
        certificateProfile: String,
        csrFingerprint: String,
    ): OtkConsumeOutcome {
        val outcome = AtomicReference<OtkConsumeOutcome>()

        records.computeIfPresent(token) { _, current ->
            val now = clock.instant()
            val next = when {
                current.state == OtkState.REVOKED -> {
                    val replayed = current.copy(state = OtkState.REPLAYED, updatedAt = now)
                    outcome.set(OtkConsumeOutcome.Replayed(replayed))
                    replayed
                }
                current.state != OtkState.ISSUED -> {
                    val replayed = current.copy(state = OtkState.REPLAYED, updatedAt = now)
                    outcome.set(OtkConsumeOutcome.Replayed(replayed))
                    replayed
                }
                !current.expiresAt.isAfter(now) -> {
                    val expired = current.copy(state = OtkState.EXPIRED, updatedAt = now)
                    outcome.set(OtkConsumeOutcome.Expired(expired))
                    expired
                }
                current.oauth2Subject != oauth2Subject -> {
                    val rejected = current.copy(state = OtkState.REJECTED_SUBJECT_MISMATCH, updatedAt = now)
                    outcome.set(OtkConsumeOutcome.SubjectMismatch(rejected))
                    rejected
                }
                current.appInstanceId != appInstanceId || current.deviceId != deviceId -> {
                    val rejected = current.copy(state = OtkState.REJECTED_DEVICE_MISMATCH, updatedAt = now)
                    outcome.set(OtkConsumeOutcome.DeviceMismatch(rejected))
                    rejected
                }
                current.certificateProfile != certificateProfile -> {
                    val rejected = current.copy(state = OtkState.REJECTED_CERTIFICATE_PROFILE_MISMATCH, updatedAt = now)
                    outcome.set(OtkConsumeOutcome.CertificateProfileMismatch(rejected))
                    rejected
                }
                else -> {
                    val consumed = current.copy(
                        state = OtkState.CONSUMED,
                        csrFingerprint = csrFingerprint,
                        consumedAt = now,
                        updatedAt = now,
                    )
                    outcome.set(OtkConsumeOutcome.Consumed(consumed))
                    consumed
                }
            }

            next
        }

        return outcome.get() ?: OtkConsumeOutcome.NotFound
    }
}

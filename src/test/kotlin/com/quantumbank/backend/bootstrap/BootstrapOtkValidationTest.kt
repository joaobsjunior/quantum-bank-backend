package com.quantumbank.backend.bootstrap

import com.quantumbank.backend.security.SecurityProperties
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset

class BootstrapOtkValidationTest {

    private val now = Instant.parse("2026-05-21T10:00:00Z")
    private val repository = InMemoryOtkRepository(Clock.fixed(now, ZoneOffset.UTC), SecurityProperties())

    @Test
    fun unknownOtkReturnsNotFoundOutcome() {
        val outcome = repository.consumeOnce(
            token = "missing",
            oauth2Subject = "alice@quantumbank.local",
            appInstanceId = "app-local-001",
            deviceId = "device-local-001",
            certificateProfile = "quantum-bank-mobile-client-v1",
            csrFingerprint = "csr-fingerprint",
        )

        assertThat(outcome).isInstanceOf(OtkConsumeOutcome.NotFound::class.java)
        assertThat(BootstrapErrorCodes.OTK_NOT_FOUND).isEqualTo("otk_not_found")
    }

    @Test
    fun expiredOtkReturnsExpiredOutcome() {
        repository.save(record(expiresAt = now.minus(Duration.ofSeconds(1))))

        val outcome = repository.consumeOnce(
            token = "otk-token",
            oauth2Subject = "alice@quantumbank.local",
            appInstanceId = "app-local-001",
            deviceId = "device-local-001",
            certificateProfile = "quantum-bank-mobile-client-v1",
            csrFingerprint = "csr-fingerprint",
        )

        assertThat(outcome).isInstanceOf(OtkConsumeOutcome.Expired::class.java)
        assertThat(repository.find("otk-token")?.state).isEqualTo(OtkState.EXPIRED)
        assertThat(BootstrapErrorCodes.OTK_EXPIRED).isEqualTo("otk_expired")
    }

    @Test
    fun consumeRejectsSubjectDeviceAndCertificateProfileMismatch() {
        repository.save(record())

        assertThat(
            repository.consumeOnce(
                token = "otk-token",
                oauth2Subject = "mallory@quantumbank.local",
                appInstanceId = "app-local-001",
                deviceId = "device-local-001",
                certificateProfile = "quantum-bank-mobile-client-v1",
                csrFingerprint = "csr-fingerprint",
            ),
        ).isInstanceOf(OtkConsumeOutcome.SubjectMismatch::class.java)

        repository.save(record(token = "otk-token-2"))
        assertThat(
            repository.consumeOnce(
                token = "otk-token-2",
                oauth2Subject = "alice@quantumbank.local",
                appInstanceId = "other-app",
                deviceId = "other-device",
                certificateProfile = "quantum-bank-mobile-client-v1",
                csrFingerprint = "csr-fingerprint",
            ),
        ).isInstanceOf(OtkConsumeOutcome.DeviceMismatch::class.java)

        repository.save(record(token = "otk-token-3"))
        assertThat(
            repository.consumeOnce(
                token = "otk-token-3",
                oauth2Subject = "alice@quantumbank.local",
                appInstanceId = "app-local-001",
                deviceId = "device-local-001",
                certificateProfile = "other-profile",
                csrFingerprint = "csr-fingerprint",
            ),
        ).isInstanceOf(OtkConsumeOutcome.CertificateProfileMismatch::class.java)

        assertThat(BootstrapErrorCodes.SUBJECT_MISMATCH).isEqualTo("subject_mismatch")
        assertThat(BootstrapErrorCodes.DEVICE_MISMATCH).isEqualTo("device_mismatch")
        assertThat(BootstrapErrorCodes.CERTIFICATE_PROFILE_MISMATCH).isEqualTo("certificate_profile_mismatch")
    }

    @Test
    fun issuingANewOtkRevokesTheEarlierIssuedOneForTheSameClient() {
        repository.save(record(token = "first"))
        repository.save(record(token = "other-device", deviceId = "device-local-002"))
        repository.save(record(token = "second"))

        assertThat(repository.find("first")?.state).isEqualTo(OtkState.REVOKED)
        assertThat(repository.find("other-device")?.state).isEqualTo(OtkState.ISSUED)
        assertThat(repository.find("second")?.state).isEqualTo(OtkState.ISSUED)

        val outcome = repository.consumeOnce(
            token = "first",
            oauth2Subject = "alice@quantumbank.local",
            appInstanceId = "app-local-001",
            deviceId = "device-local-001",
            certificateProfile = "quantum-bank-mobile-client-v1",
            csrFingerprint = "csr-fingerprint",
        )
        assertThat(outcome).isInstanceOf(OtkConsumeOutcome.Replayed::class.java)
    }

    @Test
    fun purgesRecordsOlderThanTheRetentionWindow() {
        val retention = SecurityProperties().otkRetention
        repository.save(record(token = "stale", expiresAt = now.minus(retention).minusSeconds(1)))
        repository.save(record(token = "recent", expiresAt = now.minusSeconds(1), deviceId = "device-local-002"))

        repository.save(record(token = "fresh", deviceId = "device-local-003"))

        assertThat(repository.find("stale")).isNull()
        assertThat(repository.find("recent")).isNotNull()
        assertThat(repository.size()).isEqualTo(2)
    }

    @Test
    fun failsClosedWhenTheStoreIsFull() {
        val bounded = InMemoryOtkRepository(
            Clock.fixed(now, ZoneOffset.UTC),
            SecurityProperties(otkMaxRecords = 2),
        )
        bounded.save(record(token = "one"))
        bounded.save(record(token = "two", deviceId = "device-local-002"))

        assertThatThrownBy { bounded.save(record(token = "three", deviceId = "device-local-003")) }
            .isInstanceOf(OtkCapacityExceededException::class.java)
        assertThat(bounded.size()).isEqualTo(2)
        assertThat(BootstrapErrorCodes.OTK_CAPACITY_EXCEEDED).isEqualTo("otk_capacity_exceeded")
    }

    private fun record(
        token: String = "otk-token",
        expiresAt: Instant = now.plus(Duration.ofMinutes(5)),
        deviceId: String = "device-local-001",
    ): OtkRecord =
        OtkRecord(
            token = token,
            oauth2Subject = "alice@quantumbank.local",
            appInstanceId = "app-local-001",
            deviceId = deviceId,
            certificateProfile = "quantum-bank-mobile-client-v1",
            environment = "local",
            expiresAt = expiresAt,
        )
}

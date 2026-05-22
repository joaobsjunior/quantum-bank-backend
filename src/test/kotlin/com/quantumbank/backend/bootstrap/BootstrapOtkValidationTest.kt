package com.quantumbank.backend.bootstrap

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset

class BootstrapOtkValidationTest {

    private val now = Instant.parse("2026-05-21T10:00:00Z")
    private val repository = InMemoryOtkRepository(Clock.fixed(now, ZoneOffset.UTC))

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

    private fun record(
        token: String = "otk-token",
        expiresAt: Instant = now.plus(Duration.ofMinutes(5)),
    ): OtkRecord =
        OtkRecord(
            token = token,
            oauth2Subject = "alice@quantumbank.local",
            appInstanceId = "app-local-001",
            deviceId = "device-local-001",
            certificateProfile = "quantum-bank-mobile-client-v1",
            environment = "local",
            expiresAt = expiresAt,
        )
}

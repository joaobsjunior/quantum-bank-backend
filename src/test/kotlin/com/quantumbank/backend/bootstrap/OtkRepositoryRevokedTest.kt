package com.quantumbank.backend.bootstrap

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset

class OtkRepositoryRevokedTest {

    private val now = Instant.parse("2026-05-21T10:00:00Z")
    private val repository = InMemoryOtkRepository(Clock.fixed(now, ZoneOffset.UTC))

    @Test
    fun consumingRevokedRecordReportsReplayed() {
        repository.save(
            OtkRecord(
                token = "revoked-token",
                oauth2Subject = "alice@quantumbank.local",
                appInstanceId = "app-local-001",
                deviceId = "device-local-001",
                certificateProfile = "quantum-bank-mobile-client-v1",
                environment = "local",
                expiresAt = now.plus(Duration.ofMinutes(5)),
                state = OtkState.REVOKED,
            ),
        )

        val outcome = repository.consumeOnce(
            token = "revoked-token",
            oauth2Subject = "alice@quantumbank.local",
            appInstanceId = "app-local-001",
            deviceId = "device-local-001",
            certificateProfile = "quantum-bank-mobile-client-v1",
            csrFingerprint = "csr-fingerprint",
        )

        assertThat(outcome).isInstanceOf(OtkConsumeOutcome.Replayed::class.java)
        assertThat(repository.find("revoked-token")?.state).isEqualTo(OtkState.REPLAYED)
    }
}

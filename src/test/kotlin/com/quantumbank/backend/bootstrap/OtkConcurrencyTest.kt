package com.quantumbank.backend.bootstrap

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.Callable
import java.util.concurrent.Executors

class OtkConcurrencyTest {

    @Test
    fun consumeOnceAllowsOnlyOneWinnerAndMarksReplay() {
        val now = Instant.parse("2026-05-21T10:00:00Z")
        val repository = InMemoryOtkRepository(Clock.fixed(now, ZoneOffset.UTC))
        val record = OtkRecord(
            token = "otk-token",
            oauth2Subject = "alice@quantumbank.local",
            appInstanceId = "app-local-001",
            deviceId = "device-local-001",
            certificateProfile = "quantum-bank-mobile-client-v1",
            environment = "local",
            expiresAt = now.plusSeconds(300),
        )

        repository.save(record)

        val executor = Executors.newFixedThreadPool(8)
        val attempts = (1..20).map {
            Callable {
                repository.consumeOnce(
                    token = "otk-token",
                    oauth2Subject = "alice@quantumbank.local",
                    appInstanceId = "app-local-001",
                    deviceId = "device-local-001",
                    certificateProfile = "quantum-bank-mobile-client-v1",
                    csrFingerprint = "csr-fingerprint-$it",
                )
            }
        }

        val outcomes = executor.invokeAll(attempts).map { it.get() }
        executor.shutdown()

        assertThat(outcomes.filterIsInstance<OtkConsumeOutcome.Consumed>()).hasSize(1)
        assertThat(outcomes.filterIsInstance<OtkConsumeOutcome.Replayed>()).hasSize(19)
        assertThat(repository.find("otk-token")?.state).isEqualTo(OtkState.REPLAYED)
        assertThat(BootstrapErrorCodes.OTK_REPLAYED).isEqualTo("otk_replayed")
    }
}

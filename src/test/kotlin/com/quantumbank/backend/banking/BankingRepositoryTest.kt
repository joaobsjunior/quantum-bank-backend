package com.quantumbank.backend.banking

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles
import java.math.BigDecimal
import java.time.Instant

@SpringBootTest
@ActiveProfiles("test")
class BankingRepositoryTest {

    @Autowired
    private lateinit var profileRepository: ProfileRepository

    @Autowired
    private lateinit var statementRepository: StatementRepository

    @Autowired
    private lateinit var pixTransferRepository: PixTransferRepository

    @Test
    fun loadsH2FixturesForAuthenticatedSubject() {
        val profile = profileRepository.findBySubject("alice@quantumbank.local")
        val statements = statementRepository.findBySubject("alice@quantumbank.local")

        assertThat(profile?.fullName).isEqualTo("Alice Quantum")
        assertThat(statements).hasSize(2)
        assertThat(statements.map { it.type }).contains(StatementEntryType.CREDIT, StatementEntryType.DEBIT)
    }

    @Test
    fun loadsH2FixturesForLocalServiceAccountSmokeSubject() {
        val subject = "service-account-quantum-bank-test"
        val profile = profileRepository.findBySubject(subject)
        val statements = statementRepository.findBySubject(subject)

        assertThat(profile?.fullName).isEqualTo("Quantum Bank Smoke Runner")
        assertThat(statements).hasSize(1)
        assertThat(statements.first().description).contains("Smoke")
    }

    @Test
    fun loadsH2FixturesForLocalKeycloakUserSubject() {
        val subject = "00000000-0000-0000-0000-000000000001"
        val profile = profileRepository.findBySubject(subject)
        val statements = statementRepository.findBySubject(subject)

        assertThat(profile?.email).isEqualTo("alice@quantumbank.local")
        assertThat(statements).hasSize(1)
        assertThat(statements.first().description).contains("Alice")
    }

    @Test
    fun loadsH2FixturesForLocalTestClientFallbackSubject() {
        val subject = "quantum-bank-test"
        val profile = profileRepository.findBySubject(subject)
        val statements = statementRepository.findBySubject(subject)

        assertThat(profile?.fullName).isEqualTo("Quantum Bank Local Test Client")
        assertThat(statements).hasSize(1)
    }

    @Test
    fun persistsPixSimulationAttempts() {
        val attempt = PixTransferAttempt(
            transactionId = "pix-test-001",
            subject = "alice@quantumbank.local",
            amount = BigDecimal("50.25"),
            recipientKey = "recipient@example.com",
            description = "Repository test",
            scenario = PixScenario.SUCCESS,
            status = PixTransferStatus.COMPLETED,
            errorCode = null,
            correlationId = "corr-repository-test",
            createdAt = Instant.parse("2026-05-22T12:00:00Z"),
        )

        pixTransferRepository.save(attempt)

        assertThat(pixTransferRepository.findByTransactionId("pix-test-001")).isEqualTo(attempt)
    }
}

package com.quantumbank.backend.banking

import org.springframework.http.HttpStatus
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.math.BigDecimal
import java.time.Clock
import java.util.UUID

data class PixTransferCommand(
    val subject: String,
    val amount: BigDecimal,
    val recipientKey: String,
    val description: String?,
    val scenario: PixScenario,
    val correlationId: String,
)

data class PixTransferSuccessResponse(
    val transactionId: String,
    val status: PixTransferStatus,
    val amount: BigDecimal,
    val createdAt: String,
    val correlationId: String,
)

@Service
class PixService(
    private val pixTransferRepository: PixTransferRepository,
    private val statementRepository: StatementRepository,
    private val clock: Clock,
) {
    @Transactional
    fun simulate(command: PixTransferCommand): PixTransferSuccessResponse {
        val transactionId = UUID.randomUUID().toString()
        val now = clock.instant()

        if (command.scenario == PixScenario.ERROR) {
            pixTransferRepository.save(
                PixTransferAttempt(
                    transactionId = transactionId,
                    subject = command.subject,
                    amount = command.amount,
                    recipientKey = command.recipientKey,
                    description = command.description,
                    scenario = command.scenario,
                    status = PixTransferStatus.FAILED,
                    errorCode = PIX_SIMULATED_ERROR,
                    correlationId = command.correlationId,
                    createdAt = now,
                ),
            )
            throw BankingProblemException(
                errorCode = PIX_SIMULATED_ERROR,
                status = HttpStatus.UNPROCESSABLE_ENTITY,
                problemTitle = "Pix simulation failed",
                detail = "Pix transfer was rejected by the selected local simulation scenario.",
            )
        }

        val attempt = pixTransferRepository.save(
            PixTransferAttempt(
                transactionId = transactionId,
                subject = command.subject,
                amount = command.amount,
                recipientKey = command.recipientKey,
                description = command.description,
                scenario = command.scenario,
                status = PixTransferStatus.COMPLETED,
                errorCode = null,
                correlationId = command.correlationId,
                createdAt = now,
            ),
        )
        statementRepository.save(
            NewStatementEntry(
                subject = command.subject,
                postedAt = now,
                description = command.description?.takeIf { it.isNotBlank() } ?: "Pix enviado - ${command.recipientKey}",
                amount = command.amount.negate(),
                type = StatementEntryType.DEBIT,
            ),
        )

        return PixTransferSuccessResponse(
            transactionId = attempt.transactionId,
            status = attempt.status,
            amount = attempt.amount,
            createdAt = attempt.createdAt.toString(),
            correlationId = attempt.correlationId,
        )
    }

    companion object {
        const val PIX_SIMULATED_ERROR = "pix_simulated_error"
    }
}

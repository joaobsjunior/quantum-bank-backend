package com.quantumbank.backend.banking

import java.math.BigDecimal
import java.time.Instant

data class CustomerProfile(
    val subject: String,
    val fullName: String,
    val email: String,
    val phone: String,
    val documentNumber: String,
    val address: String,
    val updatedAt: Instant,
)

data class ProfileUpdate(
    val fullName: String,
    val email: String,
    val phone: String,
    val address: String,
)

data class StatementEntry(
    val id: Long,
    val subject: String,
    val postedAt: Instant,
    val description: String,
    val amount: BigDecimal,
    val type: StatementEntryType,
)

enum class StatementEntryType {
    CREDIT,
    DEBIT,
}

data class PixTransferAttempt(
    val transactionId: String,
    val subject: String,
    val amount: BigDecimal,
    val recipientKey: String,
    val description: String?,
    val scenario: PixScenario,
    val status: PixTransferStatus,
    val errorCode: String?,
    val correlationId: String,
    val createdAt: Instant,
)

enum class PixScenario {
    SUCCESS,
    ERROR,
}

enum class PixTransferStatus {
    COMPLETED,
    FAILED,
}

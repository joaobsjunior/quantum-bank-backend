package com.quantumbank.backend.banking

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.core.RowMapper
import org.springframework.stereotype.Repository
import java.sql.Timestamp
import java.time.Clock
import java.time.Instant

@Repository
class ProfileRepository(
    private val jdbcTemplate: JdbcTemplate,
    private val clock: Clock,
) {
    fun findBySubject(subject: String): CustomerProfile? =
        jdbcTemplate.query(
            """
            SELECT subject, full_name, email, phone, document_number, address, updated_at
            FROM profiles
            WHERE subject = ?
            """.trimIndent(),
            profileMapper,
            subject,
        ).firstOrNull()

    fun update(subject: String, update: ProfileUpdate): CustomerProfile? {
        jdbcTemplate.update(
            """
            UPDATE profiles
            SET full_name = ?, email = ?, phone = ?, address = ?, updated_at = ?
            WHERE subject = ?
            """.trimIndent(),
            update.fullName,
            update.email,
            update.phone,
            update.address,
            Timestamp.from(clock.instant()),
            subject,
        )
        return findBySubject(subject)
    }

    private val profileMapper = RowMapper { rs, _ ->
        CustomerProfile(
            subject = rs.getString("subject"),
            fullName = rs.getString("full_name"),
            email = rs.getString("email"),
            phone = rs.getString("phone"),
            documentNumber = rs.getString("document_number"),
            address = rs.getString("address"),
            updatedAt = rs.getTimestamp("updated_at").toInstant(),
        )
    }
}

@Repository
class StatementRepository(
    private val jdbcTemplate: JdbcTemplate,
) {
    fun findBySubject(subject: String): List<StatementEntry> =
        jdbcTemplate.query(
            """
            SELECT id, subject, posted_at, description, amount, entry_type
            FROM statement_entries
            WHERE subject = ?
            ORDER BY posted_at DESC, id DESC
            """.trimIndent(),
            statementMapper,
            subject,
        )

    private val statementMapper = RowMapper { rs, _ ->
        StatementEntry(
            id = rs.getLong("id"),
            subject = rs.getString("subject"),
            postedAt = rs.getTimestamp("posted_at").toInstant(),
            description = rs.getString("description"),
            amount = rs.getBigDecimal("amount"),
            type = StatementEntryType.valueOf(rs.getString("entry_type")),
        )
    }
}

@Repository
class PixTransferRepository(
    private val jdbcTemplate: JdbcTemplate,
) {
    fun save(attempt: PixTransferAttempt): PixTransferAttempt {
        jdbcTemplate.update(
            """
            INSERT INTO pix_transfers (
                transaction_id, subject, amount, recipient_key, description, scenario,
                status, error_code, correlation_id, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """.trimIndent(),
            attempt.transactionId,
            attempt.subject,
            attempt.amount,
            attempt.recipientKey,
            attempt.description,
            attempt.scenario.name,
            attempt.status.name,
            attempt.errorCode,
            attempt.correlationId,
            Timestamp.from(attempt.createdAt),
        )
        return attempt
    }

    fun findByTransactionId(transactionId: String): PixTransferAttempt? =
        jdbcTemplate.query(
            """
            SELECT transaction_id, subject, amount, recipient_key, description, scenario,
                   status, error_code, correlation_id, created_at
            FROM pix_transfers
            WHERE transaction_id = ?
            """.trimIndent(),
            pixMapper,
            transactionId,
        ).firstOrNull()

    private val pixMapper = RowMapper { rs, _ ->
        PixTransferAttempt(
            transactionId = rs.getString("transaction_id"),
            subject = rs.getString("subject"),
            amount = rs.getBigDecimal("amount"),
            recipientKey = rs.getString("recipient_key"),
            description = rs.getString("description"),
            scenario = PixScenario.valueOf(rs.getString("scenario")),
            status = PixTransferStatus.valueOf(rs.getString("status")),
            errorCode = rs.getString("error_code"),
            correlationId = rs.getString("correlation_id"),
            createdAt = rs.getTimestamp("created_at").toInstant(),
        )
    }
}

package com.quantumbank.backend.banking

import com.quantumbank.backend.security.quantumBankSubject
import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import java.math.BigDecimal

@RestController
class StatementController(
    private val statementRepository: StatementRepository,
) {

    @GetMapping("/statements")
    fun getStatements(
        @AuthenticationPrincipal jwt: Jwt,
        servletRequest: HttpServletRequest,
    ): StatementResponse =
        StatementResponse(
            entries = statementRepository.findBySubject(jwt.quantumBankSubject()).map { it.toResponse() },
            correlationId = servletRequest.correlationId(),
        )
}

data class StatementResponse(
    val entries: List<StatementEntryResponse>,
    val correlationId: String,
)

data class StatementEntryResponse(
    val id: Long,
    val postedAt: String,
    val description: String,
    val amount: BigDecimal,
    val type: StatementEntryType,
)

private fun StatementEntry.toResponse(): StatementEntryResponse =
    StatementEntryResponse(
        id = id,
        postedAt = postedAt.toString(),
        description = description,
        amount = amount,
        type = type,
    )

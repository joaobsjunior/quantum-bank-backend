package com.quantumbank.backend.banking

import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice
import java.util.UUID

class BankingProblemException(
    val errorCode: String,
    val status: HttpStatus,
    val problemTitle: String,
    val detail: String,
) : RuntimeException(errorCode)

@RestControllerAdvice
class BankingProblemDetails {

    @ExceptionHandler(BankingProblemException::class)
    fun bankingProblem(
        exception: BankingProblemException,
        request: HttpServletRequest,
    ): ResponseEntity<Map<String, Any>> {
        val correlationId = request.correlationId()
        return ResponseEntity
            .status(exception.status)
            .contentType(MediaType.APPLICATION_PROBLEM_JSON)
            .header(CORRELATION_ID_HEADER, correlationId)
            .body(
                mapOf(
                    "type" to "https://quantum-bank.local/problems/banking",
                    "title" to exception.problemTitle,
                    "status" to exception.status.value(),
                    "detail" to exception.detail,
                    "errorCode" to exception.errorCode,
                    "correlationId" to correlationId,
                    "instance" to request.requestURI,
                ),
            )
    }
}

internal const val CORRELATION_ID_HEADER = "X-Correlation-Id"

internal fun HttpServletRequest.correlationId(): String =
    getHeader(CORRELATION_ID_HEADER)
        ?.takeIf { it.isNotBlank() }
        ?: UUID.randomUUID().toString()

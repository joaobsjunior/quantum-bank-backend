package com.quantumbank.backend.bootstrap

import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.http.converter.HttpMessageNotReadableException
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice
import java.util.UUID

@RestControllerAdvice
class BootstrapProblemDetails {

    @ExceptionHandler(BootstrapProblemException::class)
    fun bootstrapProblem(
        exception: BootstrapProblemException,
        request: HttpServletRequest,
    ): ResponseEntity<Map<String, Any>> =
        problem(
            status = exception.status,
            title = exception.problemTitle,
            errorCode = exception.errorCode,
            request = request,
        )

    @ExceptionHandler(MethodArgumentNotValidException::class, HttpMessageNotReadableException::class)
    fun invalidRequest(
        request: HttpServletRequest,
    ): ResponseEntity<Map<String, Any>> =
        problem(
            status = HttpStatus.BAD_REQUEST,
            title = "Invalid request",
            errorCode = BootstrapErrorCodes.REQUEST_INVALID,
            request = request,
        )

    private fun problem(
        status: HttpStatus,
        title: String,
        errorCode: String,
        request: HttpServletRequest,
    ): ResponseEntity<Map<String, Any>> {
        val correlationId = request.bootstrapCorrelationId()
        return ResponseEntity
            .status(status)
            .contentType(MediaType.APPLICATION_PROBLEM_JSON)
            .header(CORRELATION_ID_HEADER, correlationId)
            .body(
                mapOf(
                    "type" to "https://quantum-bank.local/problems/bootstrap",
                    "title" to title,
                    "status" to status.value(),
                    "errorCode" to errorCode,
                    "correlationId" to correlationId,
                    "instance" to request.requestURI,
                ),
            )
    }
}

internal const val CORRELATION_ID_HEADER = "X-Correlation-Id"

internal fun HttpServletRequest.bootstrapCorrelationId(): String =
    getHeader(CORRELATION_ID_HEADER)
        ?.takeIf { it.isNotBlank() }
        ?: UUID.randomUUID().toString()

package com.quantumbank.backend.security

import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice

/**
 * Maps identity failures detected after token validation (for example a JWT
 * without a usable `sub`) to the same problem vocabulary the entry point uses,
 * instead of leaking a generic 500.
 */
@RestControllerAdvice
class SecurityProblemDetails {

    @ExceptionHandler(InvalidJwtSubjectException::class)
    fun invalidSubject(request: HttpServletRequest): ResponseEntity<Map<String, Any>> {
        val correlationId = request.safeCorrelationId()
        val status = HttpStatus.UNAUTHORIZED
        return ResponseEntity
            .status(status)
            .contentType(MediaType.APPLICATION_PROBLEM_JSON)
            .header(CORRELATION_ID_HEADER, correlationId)
            .body(
                mapOf(
                    "type" to "https://quantum-bank.local/problems/authentication",
                    "title" to "Unauthorized",
                    "status" to status.value(),
                    "errorCode" to "auth_invalid_token",
                    "correlationId" to correlationId,
                    "instance" to request.requestURI,
                ),
            )
    }
}

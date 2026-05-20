package com.quantumbank.backend.security

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.HttpStatus
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.web.access.AccessDeniedHandler
import org.springframework.stereotype.Component
import tools.jackson.databind.ObjectMapper
import java.util.UUID

@Component
class ProblemDetailsAccessDeniedHandler(
    private val objectMapper: ObjectMapper,
) : AccessDeniedHandler {

    override fun handle(
        request: HttpServletRequest,
        response: HttpServletResponse,
        accessDeniedException: AccessDeniedException,
    ) {
        val correlationId = correlationId(request)
        val status = HttpStatus.FORBIDDEN

        response.status = status.value()
        response.contentType = PROBLEM_JSON
        response.setHeader(CORRELATION_ID_HEADER, correlationId)

        objectMapper.writeValue(
            response.outputStream,
            mapOf(
                "type" to "https://quantum-bank.local/problems/authorization",
                "title" to "Forbidden",
                "status" to status.value(),
                "errorCode" to "auth_missing_scope",
                "correlationId" to correlationId,
                "instance" to request.requestURI,
            ),
        )
    }

    private fun correlationId(request: HttpServletRequest): String =
        request.getHeader(CORRELATION_ID_HEADER)
            ?.takeIf { it.isNotBlank() }
            ?: UUID.randomUUID().toString()

    private companion object {
        const val CORRELATION_ID_HEADER = "X-Correlation-Id"
        const val PROBLEM_JSON = "application/problem+json"
    }
}

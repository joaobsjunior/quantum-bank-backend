package com.quantumbank.backend.security

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.HttpStatus
import tools.jackson.databind.ObjectMapper

const val PROBLEM_JSON = "application/problem+json"

/**
 * Writes an RFC 9457 problem document directly to the servlet response. Used by
 * the security layer, which runs before Spring MVC exception handling.
 */
fun writeProblem(
    objectMapper: ObjectMapper,
    request: HttpServletRequest,
    response: HttpServletResponse,
    status: HttpStatus,
    type: String,
    title: String,
    errorCode: String,
) {
    val correlationId = request.safeCorrelationId()

    response.status = status.value()
    response.contentType = PROBLEM_JSON
    response.setHeader(CORRELATION_ID_HEADER, correlationId)

    objectMapper.writeValue(
        response.outputStream,
        mapOf(
            "type" to type,
            "title" to title,
            "status" to status.value(),
            "errorCode" to errorCode,
            "correlationId" to correlationId,
            "instance" to request.requestURI,
        ),
    )
}

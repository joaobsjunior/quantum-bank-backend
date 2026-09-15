package com.quantumbank.backend.security

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.HttpStatus
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.web.access.AccessDeniedHandler
import org.springframework.stereotype.Component
import tools.jackson.databind.ObjectMapper

@Component
class ProblemDetailsAccessDeniedHandler(
    private val objectMapper: ObjectMapper,
) : AccessDeniedHandler {

    override fun handle(
        request: HttpServletRequest,
        response: HttpServletResponse,
        accessDeniedException: AccessDeniedException,
    ) {
        writeProblem(
            objectMapper = objectMapper,
            request = request,
            response = response,
            status = HttpStatus.FORBIDDEN,
            type = "https://quantum-bank.local/problems/authorization",
            title = "Forbidden",
            errorCode = "auth_missing_scope",
        )
    }
}

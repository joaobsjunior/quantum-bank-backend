package com.quantumbank.backend.security

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.HttpStatus
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.stereotype.Component
import tools.jackson.databind.ObjectMapper

@Component
class ProblemDetailsAuthenticationEntryPoint(
    private val objectMapper: ObjectMapper,
) : AuthenticationEntryPoint {

    override fun commence(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authException: AuthenticationException,
    ) {
        writeProblem(
            objectMapper = objectMapper,
            request = request,
            response = response,
            status = HttpStatus.UNAUTHORIZED,
            type = "https://quantum-bank.local/problems/authentication",
            title = "Unauthorized",
            errorCode = "auth_invalid_token",
        )
    }
}

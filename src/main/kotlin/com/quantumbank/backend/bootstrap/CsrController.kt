package com.quantumbank.backend.bootstrap

import jakarta.servlet.http.HttpServletRequest
import jakarta.validation.Valid
import jakarta.validation.constraints.NotBlank
import org.springframework.http.HttpStatus
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/auth")
class CsrController(
    private val otkService: OtkService,
) {

    @PostMapping("/csr")
    @ResponseStatus(HttpStatus.ACCEPTED)
    fun submitCsr(
        @Valid @RequestBody request: CsrSubmitHttpRequest,
        @AuthenticationPrincipal jwt: Jwt,
        servletRequest: HttpServletRequest,
    ): CsrSubmitResponse =
        otkService.submitCsr(
            oauth2Subject = jwt.subject,
            request = CsrSubmitRequest(
                otk = request.otk,
                csr = request.csr,
                appInstanceId = request.appInstanceId,
                deviceId = request.deviceId,
                certificateProfile = request.certificateProfile,
                environment = request.environment,
            ),
            correlationId = servletRequest.bootstrapCorrelationId(),
        )
}

data class CsrSubmitHttpRequest(
    @field:NotBlank
    val otk: String,
    @field:NotBlank
    val csr: String,
    @field:NotBlank
    val appInstanceId: String,
    @field:NotBlank
    val deviceId: String,
    val certificateProfile: String? = null,
    val environment: String? = null,
)

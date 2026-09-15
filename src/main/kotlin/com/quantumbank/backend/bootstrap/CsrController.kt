package com.quantumbank.backend.bootstrap

import com.quantumbank.backend.security.quantumBankSubject
import com.quantumbank.backend.security.safeCorrelationId
import jakarta.servlet.http.HttpServletRequest
import jakarta.validation.Valid
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Pattern
import jakarta.validation.constraints.Size
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
            oauth2Subject = jwt.quantumBankSubject(),
            request = CsrSubmitRequest(
                otk = request.otk,
                csr = request.csr,
                appInstanceId = request.appInstanceId,
                deviceId = request.deviceId,
                certificateProfile = request.certificateProfile,
                environment = request.environment,
            ),
            correlationId = servletRequest.safeCorrelationId(),
        )
}

data class CsrSubmitHttpRequest(
    @field:NotBlank
    @field:Pattern(regexp = BootstrapIdentifiers.OTK_PATTERN)
    val otk: String,
    @field:NotBlank
    @field:Size(max = BootstrapIdentifiers.CSR_MAX_LENGTH)
    val csr: String,
    @field:NotBlank
    @field:Pattern(regexp = BootstrapIdentifiers.CLIENT_IDENTIFIER_PATTERN)
    val appInstanceId: String,
    @field:NotBlank
    @field:Pattern(regexp = BootstrapIdentifiers.CLIENT_IDENTIFIER_PATTERN)
    val deviceId: String,
    @field:Pattern(regexp = BootstrapIdentifiers.CERTIFICATE_PROFILE_PATTERN)
    val certificateProfile: String? = null,
    @field:Pattern(regexp = BootstrapIdentifiers.ENVIRONMENT_PATTERN)
    val environment: String? = null,
)

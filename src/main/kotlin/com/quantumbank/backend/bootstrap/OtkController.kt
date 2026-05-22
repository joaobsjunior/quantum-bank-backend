package com.quantumbank.backend.bootstrap

import com.quantumbank.backend.security.quantumBankSubject
import jakarta.servlet.http.HttpServletRequest
import jakarta.validation.Valid
import jakarta.validation.constraints.NotBlank
import org.springframework.http.HttpStatus
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/auth")
class OtkController(
    private val otkService: OtkService,
) {

    @PostMapping("/otk")
    @ResponseStatus(HttpStatus.ACCEPTED)
    fun issueOtk(
        @Valid @RequestBody request: OtkIssueHttpRequest,
        @AuthenticationPrincipal jwt: Jwt,
        servletRequest: HttpServletRequest,
    ): OtkIssueResponse =
        otkService.issue(
            oauth2Subject = jwt.quantumBankSubject(),
            request = OtkIssueRequest(
                appInstanceId = request.appInstanceId,
                deviceId = request.deviceId,
                certificateProfile = request.certificateProfile,
            ),
            correlationId = servletRequest.bootstrapCorrelationId(),
        )
}

data class OtkIssueHttpRequest(
    @field:NotBlank
    val appInstanceId: String,
    @field:NotBlank
    val deviceId: String,
    val certificateProfile: String? = null,
)

package com.quantumbank.backend.banking

import com.quantumbank.backend.security.quantumBankSubject
import jakarta.servlet.http.HttpServletRequest
import jakarta.validation.Valid
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Positive
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import java.math.BigDecimal

@RestController
class PixController(
    private val pixService: PixService,
) {

    @PostMapping("/pix/transfers")
    fun createPixTransfer(
        @Valid @RequestBody request: PixTransferRequest,
        @AuthenticationPrincipal jwt: Jwt,
        servletRequest: HttpServletRequest,
    ): PixTransferSuccessResponse =
        pixService.simulate(
            PixTransferCommand(
                subject = jwt.quantumBankSubject(),
                amount = request.amount,
                recipientKey = request.recipientKey,
                description = request.description,
                scenario = request.scenario,
                correlationId = servletRequest.correlationId(),
            ),
        )
}

data class PixTransferRequest(
    @field:Positive
    val amount: BigDecimal,
    @field:NotBlank
    val recipientKey: String,
    val description: String? = null,
    val scenario: PixScenario,
)

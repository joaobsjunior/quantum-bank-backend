package com.quantumbank.backend.banking

import com.quantumbank.backend.security.quantumBankClientId
import com.quantumbank.backend.security.quantumBankSubject
import com.quantumbank.backend.security.safeCorrelationId
import jakarta.servlet.http.HttpServletRequest
import jakarta.validation.Valid
import jakarta.validation.constraints.DecimalMax
import jakarta.validation.constraints.Digits
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Positive
import jakarta.validation.constraints.Size
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import java.math.BigDecimal

@RestController
class PixController(
    private val pixService: PixService,
    private val signatureVerifier: PixSignatureVerifier,
) {

    @PostMapping("/pix/transfers")
    fun createPixTransfer(
        @Valid @RequestBody request: PixTransferRequest,
        @AuthenticationPrincipal jwt: Jwt,
        servletRequest: HttpServletRequest,
    ): PixTransferSuccessResponse {
        val subject = jwt.quantumBankSubject()
        // The post-quantum signature is checked before anything is simulated or
        // stored: an unsigned or tampered order from a mobile client never
        // reaches the simulation.
        val signature = signatureVerifier.verify(subject, jwt.quantumBankClientId(), request)
        return pixService.simulate(
            PixTransferCommand(
                subject = subject,
                amount = request.amount,
                recipientKey = request.recipientKey,
                description = request.description,
                scenario = request.scenario,
                correlationId = servletRequest.safeCorrelationId(),
                signature = signature,
            ),
        )
    }
}

data class PixTransferRequest(
    @field:Positive
    @field:Digits(integer = 17, fraction = 2)
    @field:DecimalMax(value = "1000000.00")
    val amount: BigDecimal,
    @field:NotBlank
    @field:Size(max = 160)
    val recipientKey: String,
    @field:Size(max = 240)
    val description: String? = null,
    val scenario: PixScenario,
    /** ML-DSA-65 device signature (feature 012); required for app-edge clients. */
    @field:Valid
    val signature: TransactionSignatureRequest? = null,
)

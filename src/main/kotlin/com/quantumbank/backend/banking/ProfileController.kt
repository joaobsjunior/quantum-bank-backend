package com.quantumbank.backend.banking

import com.quantumbank.backend.security.quantumBankSubject
import com.quantumbank.backend.security.safeCorrelationId
import jakarta.servlet.http.HttpServletRequest
import jakarta.validation.Valid
import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size
import org.springframework.http.HttpStatus
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController

@RestController
class ProfileController(
    private val profileRepository: ProfileRepository,
) {

    @GetMapping("/profile")
    fun getProfile(
        @AuthenticationPrincipal jwt: Jwt,
        servletRequest: HttpServletRequest,
    ): ProfileResponse =
        profileRepository.findBySubject(jwt.quantumBankSubject())
            ?.toResponse(servletRequest.safeCorrelationId())
            ?: throw profileNotFound()

    @PutMapping("/profile")
    fun updateProfile(
        @Valid @RequestBody request: ProfileUpdateRequest,
        @AuthenticationPrincipal jwt: Jwt,
        servletRequest: HttpServletRequest,
    ): ProfileResponse =
        profileRepository.update(
            subject = jwt.quantumBankSubject(),
            update = ProfileUpdate(
                fullName = request.fullName,
                email = request.email,
                phone = request.phone,
                address = request.address,
            ),
        )
            ?.toResponse(servletRequest.safeCorrelationId())
            ?: throw profileNotFound()

    private fun profileNotFound(): BankingProblemException =
        BankingProblemException(
            errorCode = "profile_not_found",
            status = HttpStatus.NOT_FOUND,
            problemTitle = "Profile not found",
            detail = "No local v1 profile fixture exists for the authenticated subject.",
        )
}

data class ProfileUpdateRequest(
    @field:NotBlank
    @field:Size(max = 160)
    val fullName: String,
    @field:Email
    @field:NotBlank
    @field:Size(max = 180)
    val email: String,
    @field:NotBlank
    @field:Size(max = 40)
    val phone: String,
    @field:NotBlank
    @field:Size(max = 240)
    val address: String,
)

data class ProfileResponse(
    val subject: String,
    val fullName: String,
    val email: String,
    val phone: String,
    val documentNumber: String,
    val address: String,
    val updatedAt: String,
    val correlationId: String,
)

private fun CustomerProfile.toResponse(correlationId: String): ProfileResponse =
    ProfileResponse(
        subject = subject,
        fullName = fullName,
        email = email,
        phone = phone,
        documentNumber = documentNumber,
        address = address,
        updatedAt = updatedAt.toString(),
        correlationId = correlationId,
    )

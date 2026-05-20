package com.quantumbank.backend.api

import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController

@RestController
class ProtectedRouteStubController {

    @PostMapping("/auth/otk")
    @ResponseStatus(HttpStatus.ACCEPTED)
    fun issueOtk(): Map<String, String> =
        stub("otk-bootstrap")

    @PostMapping("/auth/csr")
    @ResponseStatus(HttpStatus.ACCEPTED)
    fun submitCsr(): Map<String, String> =
        stub("csr-bootstrap")

    @PostMapping("/pix/transfers")
    @ResponseStatus(HttpStatus.ACCEPTED)
    fun createPixTransfer(): Map<String, String> =
        stub("pix-transfer-placeholder")

    @GetMapping("/statements")
    fun getStatements(): Map<String, String> =
        stub("statements-placeholder")

    @GetMapping("/profile")
    fun getProfile(): Map<String, String> =
        stub("profile-placeholder")

    private fun stub(operation: String): Map<String, String> =
        mapOf(
            "status" to "secured-stub",
            "operation" to operation,
        )
}

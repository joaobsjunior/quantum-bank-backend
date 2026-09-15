package com.quantumbank.backend.security

import org.springframework.security.oauth2.jwt.Jwt

/**
 * Raised when an otherwise valid JWT does not carry a usable `sub` claim.
 * Mapped to an `application/problem+json` 401 by [SecurityProblemDetails].
 */
class InvalidJwtSubjectException(message: String) : RuntimeException(message)

private val SUBJECT_PATTERN = Regex("^[A-Za-z0-9][A-Za-z0-9._@-]{0,159}$")

/**
 * The only identity claim the backend trusts is `sub`.
 *
 * Falling back to `preferred_username` or `azp` (the OAuth2 client id) would
 * collapse every user authenticating through the same client into a single
 * banking subject, so those fallbacks are deliberately not supported. The value
 * is also constrained to a conservative charset because it is used as a
 * database key, a certificate CN, a PKI script argument, and an audit field.
 */
fun Jwt.quantumBankSubject(): String {
    val subject = getClaimAsString("sub")
        ?: throw InvalidJwtSubjectException("JWT has no sub claim")
    if (!SUBJECT_PATTERN.matches(subject)) {
        throw InvalidJwtSubjectException("JWT sub claim has an unsupported format")
    }
    return subject
}

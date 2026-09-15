package com.quantumbank.backend.security

import jakarta.servlet.http.HttpServletRequest
import java.util.UUID

const val CORRELATION_ID_HEADER = "X-Correlation-Id"

private val CORRELATION_ID_PATTERN = Regex("^[A-Za-z0-9._-]{1,80}$")

/**
 * Returns the caller-supplied correlation id only when it is safe to echo back
 * in headers, persist in the database, and write to audit logs. Anything else
 * (blank, too long, control characters, log-injection payloads) is replaced by
 * a fresh UUID so the request still stays traceable.
 */
fun HttpServletRequest.safeCorrelationId(): String =
    getHeader(CORRELATION_ID_HEADER)
        ?.takeIf { CORRELATION_ID_PATTERN.matches(it) }
        ?: UUID.randomUUID().toString()

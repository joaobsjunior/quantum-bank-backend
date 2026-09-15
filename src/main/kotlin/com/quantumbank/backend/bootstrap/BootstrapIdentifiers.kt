package com.quantumbank.backend.bootstrap

/**
 * Canonical formats for every client-supplied identifier that flows into the
 * OTK store, audit logs, and the PKI sign script.
 *
 * The PKI handoff writes these values into an OpenSSL extension file and the
 * certificate SAN, so anything outside a conservative charset (newlines, `#`,
 * `$`, quotes, spaces) is rejected at the HTTP boundary and again right before
 * the process is spawned. These are also the limits that keep audit log lines
 * free of injected records.
 */
object BootstrapIdentifiers {
    const val CLIENT_IDENTIFIER_PATTERN = "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
    const val CERTIFICATE_PROFILE_PATTERN = "^[a-z0-9][a-z0-9.-]{0,63}$"
    const val ENVIRONMENT_PATTERN = "^[a-z0-9][a-z0-9-]{0,31}$"
    const val OTK_PATTERN = "^[A-Za-z0-9_-]{16,128}$"
    const val SUBJECT_PATTERN = "^[A-Za-z0-9][A-Za-z0-9._@-]{0,159}$"
    const val CSR_MAX_LENGTH = 16_384

    private val clientIdentifier = Regex(CLIENT_IDENTIFIER_PATTERN)
    private val certificateProfile = Regex(CERTIFICATE_PROFILE_PATTERN)
    private val environment = Regex(ENVIRONMENT_PATTERN)
    private val subject = Regex(SUBJECT_PATTERN)

    fun isClientIdentifier(value: String): Boolean = clientIdentifier.matches(value)

    fun isCertificateProfile(value: String): Boolean = certificateProfile.matches(value)

    fun isEnvironment(value: String): Boolean = environment.matches(value)

    fun isSubject(value: String): Boolean = subject.matches(value)
}

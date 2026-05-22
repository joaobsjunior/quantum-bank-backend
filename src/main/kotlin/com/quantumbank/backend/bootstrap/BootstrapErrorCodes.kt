package com.quantumbank.backend.bootstrap

object BootstrapErrorCodes {
    const val OTK_NOT_FOUND = "otk_not_found"
    const val OTK_EXPIRED = "otk_expired"
    const val OTK_REPLAYED = "otk_replayed"
    const val OTK_REVOKED = "otk_revoked"
    const val SUBJECT_MISMATCH = "subject_mismatch"
    const val DEVICE_MISMATCH = "device_mismatch"
    const val CERTIFICATE_PROFILE_MISMATCH = "certificate_profile_mismatch"
    const val UNSUPPORTED_ENVIRONMENT = "unsupported_environment"
    const val CSR_INVALID = "csr_invalid"
    const val PRIVATE_KEY_REJECTED = "private_key_rejected"
    const val PKI_HANDOFF_FAILED = "pki_handoff_failed"
    const val REQUEST_INVALID = "request_invalid"
}

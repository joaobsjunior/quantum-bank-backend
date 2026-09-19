package com.quantumbank.backend.envelope

object EnvelopeErrorCodes {
    const val ENVELOPE_REQUIRED = "envelope_required"
    const val ENVELOPE_INVALID = "envelope_invalid"
    const val ENVELOPE_KEY_UNKNOWN = "envelope_key_unknown"
    const val SIGNING_KEY_REQUIRED = "signing_key_required"
    const val SIGNING_KEY_INVALID = "signing_key_invalid"
    const val TRANSACTION_SIGNATURE_REQUIRED = "transaction_signature_required"
    const val TRANSACTION_SIGNATURE_INVALID = "transaction_signature_invalid"
    const val TRANSACTION_SIGNATURE_REPLAYED = "transaction_signature_replayed"
}

/** Envelope processing failure mapped to a problem document by the filter. */
class EnvelopeException(
    val errorCode: String,
    message: String,
) : RuntimeException(message)

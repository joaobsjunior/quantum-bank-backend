package com.quantumbank.backend.envelope

import org.springframework.boot.context.properties.ConfigurationProperties
import java.time.Duration

/**
 * Application-layer post-quantum envelope policy (feature 012).
 *
 * The envelope and the transaction signature are required for the OAuth2
 * clients that reach the backend through the dual (app-edge) TLS tier, where
 * the client TLS stack may negotiate classical key exchange. Strict-tier
 * service clients already have post-quantum TLS end to end and are exempt.
 */
@ConfigurationProperties(prefix = "quantum-bank.envelope")
data class EnvelopeProperties(
    /** OAuth2 client ids (`azp` / `client_id` claim) that must use the envelope and sign Pix orders. */
    val requiredForClients: List<String> = listOf("quantum-bank-mobile"),
    /** PKCS#12 store with the ML-DSA-65 identity that signs the envelope key set; the TLS store by default. */
    val signerKeyStore: String = "../pki/local-ca/runtime/backend-server.p12",
    val signerKeyStorePassword: String = "changeit",
    /** Generate a self-signed ML-DSA-65 signer when the store is absent; only honoured in the local environment. */
    val allowEphemeralSigner: Boolean = false,
    /** How long a published key set may be encrypted to. */
    val keySetValidity: Duration = Duration.ofHours(24),
    /** How long the previous key set is still accepted after rotation. */
    val keySetGrace: Duration = Duration.ofHours(1),
    /** Accepted difference between a Pix signature's `issuedAt` and the backend clock. */
    val signatureMaxSkew: Duration = Duration.ofMinutes(2),
    /** Request paths the envelope applies to (prefix match). */
    val paths: List<String> = listOf("/pix/", "/statements", "/profile"),
) {
    init {
        require(!keySetValidity.isNegative && !keySetValidity.isZero) { "quantum-bank.envelope.key-set-validity must be positive" }
        require(!keySetGrace.isNegative) { "quantum-bank.envelope.key-set-grace must not be negative" }
        require(!signatureMaxSkew.isNegative) { "quantum-bank.envelope.signature-max-skew must not be negative" }
    }

    fun requiresEnvelope(clientId: String?): Boolean = clientId != null && clientId in requiredForClients

    fun appliesTo(path: String): Boolean = paths.any { prefix -> path.startsWith(prefix) }
}

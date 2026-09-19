package com.quantumbank.backend.envelope

import org.bouncycastle.jcajce.interfaces.MLKEMPublicKey
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit
import java.util.Base64

/** Public half of a key set, as published to the app. */
data class EnvelopeKeySet(
    val kid: String,
    val alg: String = ALGORITHM,
    val mlkemPublicKey: String,
    val x25519PublicKey: String,
    val notAfter: String,
) {
    /** Canonical bytes the signature covers (contract `envelope-v1`). */
    fun canonicalBytes(): ByteArray =
        "$kid\n$alg\n$mlkemPublicKey\n$x25519PublicKey\n$notAfter\n".toByteArray(Charsets.UTF_8)

    companion object {
        const val ALGORITHM = "X25519MLKEM768-HKDF-SHA256-AES256GCM"
    }
}

data class SignedEnvelopeKeySet(
    val keySet: EnvelopeKeySet,
    val signature: String,
    val signerChain: List<String>,
)

internal data class EnvelopeKeySetRecord(
    val keySet: EnvelopeKeySet,
    val keyPair: EnvelopeKeyPair,
    val notAfter: Instant,
    val signed: SignedEnvelopeKeySet,
)

/**
 * Generates, signs and rotates the envelope key sets (ML-KEM-768 + X25519).
 * The current set is published in the CSR response; the previous set stays
 * usable for [EnvelopeProperties.keySetGrace] after rotation so devices that
 * enrolled just before it are not cut off. Keys live in memory per instance
 * (v1); a shared store is a deployment concern for multi-instance runs.
 */
@Service
class HybridEnvelopeKeyService(
    private val properties: EnvelopeProperties,
    signerFactory: EnvelopeSignerFactory,
    private val clock: Clock,
) {
    private val logger = LoggerFactory.getLogger(HybridEnvelopeKeyService::class.java)
    private val signer: EnvelopeSigner = signerFactory.create()

    @Volatile
    private var current: EnvelopeKeySetRecord = generate()

    @Volatile
    private var previous: EnvelopeKeySetRecord? = null

    /** The signed key set to hand to a device at enrollment. */
    fun signedKeySet(): SignedEnvelopeKeySet = rotateIfNeeded().signed

    /** The private keys for [kid], or null when the id is unknown or past its grace. */
    fun keyPairFor(kid: String): EnvelopeKeyPair? {
        val now = clock.instant()
        val candidate = listOfNotNull(rotateIfNeeded(), previous).firstOrNull { it.keyPair.kid == kid } ?: return null
        return candidate.keyPair.takeIf { now.isBefore(candidate.notAfter.plus(properties.keySetGrace)) }
    }

    @Synchronized
    internal fun rotateIfNeeded(): EnvelopeKeySetRecord {
        if (!clock.instant().isBefore(current.notAfter)) {
            previous = current
            current = generate()
        }
        return current
    }

    private fun generate(): EnvelopeKeySetRecord {
        val mlkem: KeyPair = KeyPairGenerator.getInstance("ML-KEM-768", BouncyCastleProvider.PROVIDER_NAME).generateKeyPair()
        val x25519: KeyPair = KeyPairGenerator.getInstance("X25519").generateKeyPair()
        val mlkemPublic = (mlkem.public as MLKEMPublicKey).publicData
        val x25519Public = x25519.public.encoded.takeLast(HybridEnvelopeCodec.X25519_PUBLIC_KEY_LENGTH).toByteArray()
        val digest = MessageDigest.getInstance("SHA-256").digest(mlkemPublic + x25519Public)
        val kid = Base64.getUrlEncoder().withoutPadding().encodeToString(digest).take(KID_LENGTH)
        val notAfter = clock.instant().plus(properties.keySetValidity).truncatedTo(ChronoUnit.SECONDS)
        val keySet = EnvelopeKeySet(
            kid = kid,
            mlkemPublicKey = Base64.getEncoder().encodeToString(mlkemPublic),
            x25519PublicKey = Base64.getEncoder().encodeToString(x25519Public),
            notAfter = DateTimeFormatter.ISO_INSTANT.format(notAfter),
        )
        val signed = SignedEnvelopeKeySet(
            keySet = keySet,
            signature = Base64.getEncoder().encodeToString(signer.sign(keySet.canonicalBytes(), SIGNATURE_CONTEXT)),
            signerChain = signer.certificateChainPem,
        )
        logger.info("event=envelope.key_set_generated kid={} notAfter={}", kid, keySet.notAfter)
        return EnvelopeKeySetRecord(
            keySet = keySet,
            keyPair = EnvelopeKeyPair(kid = kid, mlkemPrivateKey = mlkem.private, x25519PrivateKey = x25519.private),
            notAfter = notAfter,
            signed = signed,
        )
    }

    companion object {
        const val KID_LENGTH = 22
        val SIGNATURE_CONTEXT: ByteArray = "quantum-bank-envelope-keys-v1".toByteArray(Charsets.UTF_8)
    }
}

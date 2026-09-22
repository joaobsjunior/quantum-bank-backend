package com.quantumbank.backend.envelope

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation
import org.bouncycastle.jcajce.spec.KEMExtractSpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.springframework.stereotype.Component
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * One envelope on the wire (contract `envelope-v1`). Requests carry the
 * encapsulation; responses only the AEAD output, because the response key is
 * derived from the request secret.
 */
data class EnvelopeMessage(
    val v: Int = VERSION,
    val kid: String,
    val mlkemCiphertext: String? = null,
    val x25519PublicKey: String? = null,
    val nonce: String? = null,
    val ciphertext: String? = null,
    val contentType: String? = null,
) {
    companion object {
        const val VERSION = 1
        const val MEDIA_TYPE = "application/vnd.quantum-bank.envelope+json"
        const val REQUEST_HEADER = "X-Quantum-Envelope"
        const val CONTENT_TYPE_HEADER = "X-Quantum-Envelope-Content-Type"
        const val MLKEM_CIPHERTEXT_LENGTH = 1088
        const val X25519_PUBLIC_KEY_LENGTH = 32
        const val NONCE_LENGTH = 12
    }
}

/** The private half of a published key set. */
data class EnvelopeKeyPair(
    val kid: String,
    val mlkemPrivateKey: PrivateKey,
    val x25519PrivateKey: PrivateKey,
)

data class OpenedEnvelope(
    val kid: String,
    /** Decrypted request body, or null for a header-only (bodiless) request. */
    val plaintext: ByteArray?,
    val responseKey: ByteArray,
)

/**
 * Hybrid application-layer envelope (contract `envelope-v1`):
 *
 * ```
 * ss     = ML-KEM-768.Decaps(dk, ct) || X25519(sk, pk_eph)
 * prk    = HKDF-Extract(SHA-256, salt = "quantum-bank-envelope-v1", ikm = ss)
 * k_req  = HKDF-Expand(prk, "request\0"  || kid || "\0" || aad, 32)
 * k_resp = HKDF-Expand(prk, "response\0" || kid || "\0" || aad, 32)
 * body   = AES-256-GCM(k, nonce, plaintext, aad)   aad = METHOD + " " + PATH
 * ```
 *
 * The construction mirrors the `X25519MLKEM768` TLS key exchange (secrets
 * concatenated, post-quantum half first), so the strict transport tier and
 * the application layer rest on the same argument. ML-KEM is decapsulated
 * with BouncyCastle's raw shared secret (no KDF) to match the app's FIPS 203
 * implementation byte for byte.
 */
@Component
class HybridEnvelopeCodec {
    private val secureRandom = SecureRandom()

    fun open(message: EnvelopeMessage, keyPair: EnvelopeKeyPair, aad: String): OpenedEnvelope {
        if (message.v != EnvelopeMessage.VERSION) {
            throw EnvelopeException(EnvelopeErrorCodes.ENVELOPE_INVALID, "unsupported envelope version ${message.v}")
        }
        val mlkemCiphertext = decode(message.mlkemCiphertext, EnvelopeMessage.MLKEM_CIPHERTEXT_LENGTH, "mlkemCiphertext")
        val ephemeralPublicKey = decode(message.x25519PublicKey, EnvelopeMessage.X25519_PUBLIC_KEY_LENGTH, "x25519PublicKey")

        val mlkemSecret = decapsulate(keyPair.mlkemPrivateKey, mlkemCiphertext)
        val x25519Secret = agree(keyPair.x25519PrivateKey, ephemeralPublicKey)
        val (requestKey, responseKey) = deriveKeys(mlkemSecret, x25519Secret, message.kid, aad)

        val plaintext = if (message.ciphertext == null && message.nonce == null) {
            null
        } else {
            val nonce = decode(message.nonce, EnvelopeMessage.NONCE_LENGTH, "nonce")
            val ciphertext = decode(message.ciphertext, null, "ciphertext")
            aesGcm(Cipher.DECRYPT_MODE, requestKey, nonce, aad, ciphertext)
        }
        return OpenedEnvelope(kid = message.kid, plaintext = plaintext, responseKey = responseKey)
    }

    fun seal(responseKey: ByteArray, kid: String, aad: String, plaintext: ByteArray, contentType: String): EnvelopeMessage {
        val nonce = ByteArray(EnvelopeMessage.NONCE_LENGTH).also(secureRandom::nextBytes)
        val ciphertext = aesGcm(Cipher.ENCRYPT_MODE, responseKey, nonce, aad, plaintext)
        return EnvelopeMessage(
            kid = kid,
            nonce = Base64.getEncoder().encodeToString(nonce),
            ciphertext = Base64.getEncoder().encodeToString(ciphertext),
            contentType = contentType,
        )
    }

    internal fun decapsulate(privateKey: PrivateKey, ciphertext: ByteArray): ByteArray {
        val generator = KeyGenerator.getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME)
        generator.init(KEMExtractSpec.Builder(privateKey, ciphertext, "AES", SHARED_SECRET_BITS).withNoKdf().build(), secureRandom)
        val secret = generator.generateKey() as SecretKeyWithEncapsulation
        return secret.encoded
    }

    internal fun agree(privateKey: PrivateKey, ephemeralPublicKey: ByteArray): ByteArray {
        val publicKey = KeyFactory.getInstance("X25519").generatePublic(X509EncodedKeySpec(X25519_SPKI_PREFIX + ephemeralPublicKey))
        val agreement = KeyAgreement.getInstance("X25519")
        agreement.init(privateKey)
        agreement.doPhase(publicKey, true)
        return agreement.generateSecret()
    }

    private fun decode(value: String?, expectedLength: Int?, field: String): ByteArray {
        if (value == null) {
            throw EnvelopeException(EnvelopeErrorCodes.ENVELOPE_INVALID, "missing envelope field $field")
        }
        val bytes = try {
            Base64.getDecoder().decode(value)
        } catch (_: IllegalArgumentException) {
            throw EnvelopeException(EnvelopeErrorCodes.ENVELOPE_INVALID, "invalid base64 in envelope field $field")
        }
        if (expectedLength != null && bytes.size != expectedLength) {
            throw EnvelopeException(EnvelopeErrorCodes.ENVELOPE_INVALID, "envelope field $field has an invalid length")
        }
        return bytes
    }

    private fun aesGcm(mode: Int, key: ByteArray, nonce: ByteArray, aad: String, input: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
        cipher.updateAAD(aad.toByteArray(Charsets.UTF_8))
        return try {
            cipher.doFinal(input)
        } catch (_: javax.crypto.AEADBadTagException) {
            throw EnvelopeException(EnvelopeErrorCodes.ENVELOPE_INVALID, "envelope authentication failed")
        }
    }

    companion object {
        const val SHARED_SECRET_BITS = 256
        const val TAG_BITS = 128
        const val KEY_LENGTH = 32
        const val X25519_PUBLIC_KEY_LENGTH = 32
        val SALT: ByteArray = "quantum-bank-envelope-v1".toByteArray(Charsets.UTF_8)

        /** RFC 8410 `SubjectPublicKeyInfo` prefix for a raw 32-byte X25519 key. */
        val X25519_SPKI_PREFIX: ByteArray = byteArrayOf(
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
        )

        /** HKDF-SHA-256 key schedule shared with the app (`HybridEnvelope.deriveKeys`). */
        fun deriveKeys(mlkemSecret: ByteArray, x25519Secret: ByteArray, kid: String, aad: String): Pair<ByteArray, ByteArray> {
            val ikm = mlkemSecret + x25519Secret
            fun expand(direction: String): ByteArray {
                val info = direction.toByteArray(Charsets.UTF_8) + byteArrayOf(0) +
                    kid.toByteArray(Charsets.UTF_8) + byteArrayOf(0) + aad.toByteArray(Charsets.UTF_8)
                val generator = HKDFBytesGenerator(SHA256Digest())
                generator.init(HKDFParameters(ikm, SALT, info))
                val out = ByteArray(KEY_LENGTH)
                generator.generateBytes(out, 0, KEY_LENGTH)
                return out
            }
            return expand("request") to expand("response")
        }
    }
}

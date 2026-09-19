package com.quantumbank.backend.envelope

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation
import org.bouncycastle.jcajce.spec.KEMGenerateSpec
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec
import org.bouncycastle.jcajce.spec.MLKEMPublicKeySpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * App-side half of the envelope in Kotlin (BouncyCastle): encapsulates to a
 * published key set and opens responses, with the codec's key schedule. Used
 * by the MockMvc tests; the Dart fixture covers the real client.
 */
class TestEnvelopeClient(private val keySet: EnvelopeKeySet) {
    private val random = SecureRandom()

    data class Sealed(val message: EnvelopeMessage, val responseKey: ByteArray)

    fun seal(aad: String, plaintext: ByteArray? = null): Sealed {
        val mlkemPublic = KeyFactory.getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME)
            .generatePublic(MLKEMPublicKeySpec(MLKEMParameterSpec.ml_kem_768, Base64.getDecoder().decode(keySet.mlkemPublicKey)))
        val generator = KeyGenerator.getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME)
        generator.init(KEMGenerateSpec.Builder(mlkemPublic, "AES", 256).withNoKdf().build(), random)
        val encapsulated = generator.generateKey() as SecretKeyWithEncapsulation

        val ephemeral = KeyPairGenerator.getInstance("X25519").generateKeyPair()
        val backendX25519 = KeyFactory.getInstance("X25519").generatePublic(
            X509EncodedKeySpec(HybridEnvelopeCodec.X25519_SPKI_PREFIX + Base64.getDecoder().decode(keySet.x25519PublicKey)),
        )
        val agreement = KeyAgreement.getInstance("X25519")
        agreement.init(ephemeral.private)
        agreement.doPhase(backendX25519, true)
        val x25519Secret = agreement.generateSecret()

        val (requestKey, responseKey) = HybridEnvelopeCodec.deriveKeys(encapsulated.encoded, x25519Secret, keySet.kid, aad)
        var nonce: ByteArray? = null
        var ciphertext: ByteArray? = null
        if (plaintext != null) {
            nonce = ByteArray(12).also(random::nextBytes)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(requestKey, "AES"), GCMParameterSpec(128, nonce))
            cipher.updateAAD(aad.toByteArray())
            ciphertext = cipher.doFinal(plaintext)
        }
        return Sealed(
            EnvelopeMessage(
                kid = keySet.kid,
                mlkemCiphertext = Base64.getEncoder().encodeToString(encapsulated.encapsulation),
                x25519PublicKey = Base64.getEncoder().encodeToString(ephemeral.public.encoded.takeLast(32).toByteArray()),
                nonce = nonce?.let { Base64.getEncoder().encodeToString(it) },
                ciphertext = ciphertext?.let { Base64.getEncoder().encodeToString(it) },
            ),
            responseKey,
        )
    }

    fun open(message: EnvelopeMessage, responseKey: ByteArray, aad: String): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(responseKey, "AES"), GCMParameterSpec(128, Base64.getDecoder().decode(message.nonce)))
        cipher.updateAAD(aad.toByteArray())
        return cipher.doFinal(Base64.getDecoder().decode(message.ciphertext))
    }

    companion object {
        fun headerValue(message: EnvelopeMessage, objectMapper: tools.jackson.databind.ObjectMapper): String =
            Base64.getUrlEncoder().withoutPadding().encodeToString(objectMapper.writeValueAsBytes(message))
    }
}

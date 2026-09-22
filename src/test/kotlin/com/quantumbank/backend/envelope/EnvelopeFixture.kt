package com.quantumbank.backend.envelope

import com.quantumbank.backend.security.PostQuantumTls
import org.bouncycastle.jce.provider.BouncyCastleProvider
import tools.jackson.databind.ObjectMapper
import tools.jackson.module.kotlin.readValue
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64

/**
 * The cross-implementation fixture emitted by the mobile app
 * (`tool/emit_envelope_fixture.dart`): a request envelope sealed by the Dart
 * code (pqcrypto ML-KEM-768, package:cryptography X25519, pointycastle HKDF
 * and AES-GCM) plus the backend private keys it was sealed to.
 */
object EnvelopeFixture {
    private val objectMapper = ObjectMapper()

    val json: Map<String, Any?> by lazy {
        val stream = checkNotNull(EnvelopeFixture::class.java.getResourceAsStream("/pqc/envelope-fixture.json"))
        objectMapper.readValue<Map<String, Any?>>(stream)
    }

    @Suppress("UNCHECKED_CAST")
    private fun section(name: String): Map<String, Any?> = json[name] as Map<String, Any?>

    val aad: String get() = json["aad"] as String
    val plaintext: String get() = json["plaintext"] as String
    val subject: String get() = json["subject"] as String
    val deviceId: String get() = json["deviceId"] as String
    val requestKey: ByteArray get() = Base64.getDecoder().decode(json["requestKey"] as String)
    val csrDer: ByteArray get() = Base64.getDecoder().decode(json["csrDer"] as String)
    val mlkemSharedSecret: ByteArray get() = Base64.getDecoder().decode(section("sharedSecrets")["mlkem"] as String)
    val x25519SharedSecret: ByteArray get() = Base64.getDecoder().decode(section("sharedSecrets")["x25519"] as String)

    val keySet: EnvelopeKeySet
        get() = objectMapper.convertValue(section("keySet"), EnvelopeKeySet::class.java)

    val request: EnvelopeMessage
        get() = objectMapper.convertValue(section("request"), EnvelopeMessage::class.java)

    val headerRequest: Pair<String, String>
        get() = section("requestHeader").let { it["aad"] as String to it["value"] as String }

    val signingKeyRegistration: Map<String, String>
        @Suppress("UNCHECKED_CAST")
        get() = section("signingKeyRegistration") as Map<String, String>

    val pixSignature: Map<String, String>
        @Suppress("UNCHECKED_CAST")
        get() = section("pixSignature") as Map<String, String>

    val keyPair: EnvelopeKeyPair
        get() {
            PostQuantumTls.install()
            val keys = section("backendPrivateKeys")
            return EnvelopeKeyPair(
                kid = keySet.kid,
                mlkemPrivateKey = privateKey("ML-KEM", keys["mlkemPkcs8"] as String, BouncyCastleProvider.PROVIDER_NAME),
                x25519PrivateKey = privateKey("X25519", keys["x25519Pkcs8"] as String, null),
            )
        }

    private fun privateKey(algorithm: String, base64: String, provider: String?): PrivateKey {
        val factory = if (provider == null) KeyFactory.getInstance(algorithm) else KeyFactory.getInstance(algorithm, provider)
        return factory.generatePrivate(PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64)))
    }
}

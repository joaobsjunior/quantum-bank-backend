package com.quantumbank.backend.envelope

import com.quantumbank.backend.bootstrap.MlDsa65
import com.quantumbank.backend.security.SecurityProperties
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.io.StringReader
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64

class HybridEnvelopeKeyServiceTest {

    private val start = Instant.parse("2026-09-19T10:00:00Z")

    private class MutableClock(var now: Instant) : Clock() {
        override fun getZone(): java.time.ZoneId = ZoneOffset.UTC
        override fun withZone(zone: java.time.ZoneId): Clock = this
        override fun instant(): Instant = now
    }

    private fun service(clock: Clock, properties: EnvelopeProperties = EnvelopeProperties(allowEphemeralSigner = true, signerKeyStore = "/nonexistent.p12")) =
        HybridEnvelopeKeyService(properties, EnvelopeSignerFactory(properties, SecurityProperties()), clock)

    @Test
    fun publishesASignedKeySetWithDeterministicKidAndRfc3339Expiry() {
        val service = service(Clock.fixed(start, ZoneOffset.UTC))

        val signed = service.signedKeySet()
        val keySet = signed.keySet

        assertThat(keySet.alg).isEqualTo(EnvelopeKeySet.ALGORITHM)
        assertThat(keySet.kid).hasSize(HybridEnvelopeKeyService.KID_LENGTH).matches("[A-Za-z0-9_-]+")
        assertThat(Base64.getDecoder().decode(keySet.mlkemPublicKey)).hasSize(1184)
        assertThat(Base64.getDecoder().decode(keySet.x25519PublicKey)).hasSize(32)
        assertThat(keySet.notAfter).isEqualTo("2026-09-20T10:00:00Z")
        assertThat(String(keySet.canonicalBytes())).isEqualTo(
            "${keySet.kid}\n${keySet.alg}\n${keySet.mlkemPublicKey}\n${keySet.x25519PublicKey}\n${keySet.notAfter}\n",
        )
        val signer = CertificateFactory.getInstance("X.509").generateCertificate(
            org.bouncycastle.util.io.pem.PemReader(StringReader(signed.signerChain.first())).readPemObject().content.inputStream(),
        ) as X509Certificate
        assertThat(
            MlDsa65.verify(signer.publicKey, keySet.canonicalBytes(), Base64.getDecoder().decode(signed.signature), HybridEnvelopeKeyService.SIGNATURE_CONTEXT),
        ).isTrue()
        assertThat(service.signedKeySet()).isSameAs(signed)
        assertThat(service.keyPairFor(keySet.kid)?.kid).isEqualTo(keySet.kid)
        assertThat(service.keyPairFor("unknown")).isNull()
    }

    @Test
    fun rotatesAfterValidityAndKeepsThePreviousSetForTheGracePeriod() {
        val clock = MutableClock(start)
        val service = service(clock, EnvelopeProperties(allowEphemeralSigner = true, signerKeyStore = "/nonexistent.p12", keySetValidity = Duration.ofHours(1), keySetGrace = Duration.ofMinutes(10)))
        val first = service.signedKeySet().keySet

        clock.now = start.plus(Duration.ofMinutes(59))
        assertThat(service.signedKeySet().keySet.kid).isEqualTo(first.kid)

        clock.now = start.plus(Duration.ofMinutes(61))
        val second = service.signedKeySet().keySet
        assertThat(second.kid).isNotEqualTo(first.kid)
        assertThat(service.keyPairFor(first.kid)).isNotNull()
        assertThat(service.keyPairFor(second.kid)).isNotNull()

        clock.now = start.plus(Duration.ofMinutes(71))
        assertThat(service.keyPairFor(first.kid)).isNull()
        assertThat(service.keyPairFor(second.kid)).isNotNull()
    }
}

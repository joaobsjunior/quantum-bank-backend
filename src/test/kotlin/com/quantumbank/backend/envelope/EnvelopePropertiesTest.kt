package com.quantumbank.backend.envelope

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.time.Duration

class EnvelopePropertiesTest {

    @Test
    fun defaultsRequireTheEnvelopeForTheMobileClientOnBankingPaths() {
        val properties = EnvelopeProperties()

        assertThat(properties.requiresEnvelope("quantum-bank-mobile")).isTrue()
        assertThat(properties.requiresEnvelope("quantum-bank-test")).isFalse()
        assertThat(properties.requiresEnvelope(null)).isFalse()
        assertThat(properties.appliesTo("/pix/transfers")).isTrue()
        assertThat(properties.appliesTo("/statements")).isTrue()
        assertThat(properties.appliesTo("/profile")).isTrue()
        assertThat(properties.appliesTo("/auth/csr")).isFalse()
        assertThat(properties.keySetValidity).isEqualTo(Duration.ofHours(24))
    }

    @Test
    fun rejectsNonPositiveOrNegativeDurations() {
        assertThatThrownBy { EnvelopeProperties(keySetValidity = Duration.ZERO) }.isInstanceOf(IllegalArgumentException::class.java)
        assertThatThrownBy { EnvelopeProperties(keySetGrace = Duration.ofSeconds(-1)) }.isInstanceOf(IllegalArgumentException::class.java)
        assertThatThrownBy { EnvelopeProperties(signatureMaxSkew = Duration.ofSeconds(-1)) }.isInstanceOf(IllegalArgumentException::class.java)
    }
}

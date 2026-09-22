package com.quantumbank.backend.envelope

import com.quantumbank.backend.bootstrap.MlDsa65
import com.quantumbank.backend.bootstrap.TestCrypto
import com.quantumbank.backend.security.SecurityProperties
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.bouncycastle.jcajce.interfaces.MLDSAPublicKey
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.StringReader
import java.nio.file.Path
import java.security.KeyStore
import java.security.cert.CertificateFactory

class EnvelopeSignerTest {

    private val context = "quantum-bank-envelope-keys-v1".toByteArray()

    @Test
    fun signsWithThePkiIssuedIdentityFromTheKeyStore(@TempDir dir: Path) {
        val ca = TestCrypto.certificateAuthority()
        val keyPair = TestCrypto.mlDsaKeyPair()
        val leaf = TestCrypto.issuedCertificate("CN=backend,O=QuantumBank", keyPair, ca)
        val store = TestCrypto.keyStore(dir, "backend-server", keyPair, listOf(leaf, ca.first))

        val signer = KeyStoreEnvelopeSigner(store, TestCrypto.STORE_PASSWORD.toCharArray())

        assertThat(signer.certificateChainPem).hasSize(2)
        assertThat(signer.certificateChainPem.first()).startsWith("-----BEGIN CERTIFICATE-----")
        val message = "hello".toByteArray()
        val signature = signer.sign(message, context)
        assertThat(MlDsa65.verify(keyPair.public, message, signature, context)).isTrue()
        assertThat(MlDsa65.verify(keyPair.public, message, signature, "other".toByteArray())).isFalse()
    }

    @Test
    fun refusesKeyStoresWithoutAnMlDsa65KeyEntry(@TempDir dir: Path) {
        val rsa = TestCrypto.rsaKeyPair()
        val rsaStore = TestCrypto.keyStore(dir, "rsa", rsa, listOf(TestCrypto.selfSignedCertificate("CN=rsa", TestCrypto.mlDsaKeyPair())))
        assertThatThrownBy { KeyStoreEnvelopeSigner(rsaStore, TestCrypto.STORE_PASSWORD.toCharArray()) }
            .isInstanceOf(IllegalArgumentException::class.java)
            .hasMessageContaining("must be ML-DSA-65")

        val trustOnly = TestCrypto.trustStore(dir, "trust", listOf(TestCrypto.certificateAuthority().first))
        assertThatThrownBy { KeyStoreEnvelopeSigner(trustOnly, TestCrypto.STORE_PASSWORD.toCharArray()) }
            .isInstanceOf(IllegalStateException::class.java)
            .hasMessageContaining("no key entry")
    }

    @Test
    fun ephemeralSignerIsSelfSignedAndVerifiable() {
        val signer = EphemeralEnvelopeSigner()

        assertThat(signer.certificateChainPem).hasSize(1)
        val certificate = CertificateFactory.getInstance("X.509").generateCertificate(
            org.bouncycastle.util.io.pem.PemReader(StringReader(signer.certificateChainPem.single())).readPemObject().content.inputStream(),
        ) as java.security.cert.X509Certificate
        assertThat(certificate.subjectX500Principal.name).contains("CN=backend")
        assertThat(certificate.publicKey).isInstanceOf(MLDSAPublicKey::class.java)
        assertThat(MlDsa65.verify(certificate.publicKey, "m".toByteArray(), signer.sign("m".toByteArray(), context), context)).isTrue()
    }

    @Test
    fun factoryPrefersTheKeyStoreAndFailsClosedOutsideLocal(@TempDir dir: Path) {
        val ca = TestCrypto.certificateAuthority()
        val keyPair = TestCrypto.mlDsaKeyPair()
        val store = TestCrypto.keyStore(dir, "backend-server", keyPair, listOf(TestCrypto.issuedCertificate("CN=backend", keyPair, ca), ca.first))

        val fromStore = EnvelopeSignerFactory(
            EnvelopeProperties(signerKeyStore = store.toString(), signerKeyStorePassword = TestCrypto.STORE_PASSWORD),
            SecurityProperties(),
        ).create()
        assertThat(fromStore).isInstanceOf(KeyStoreEnvelopeSigner::class.java)

        val ephemeral = EnvelopeSignerFactory(
            EnvelopeProperties(signerKeyStore = dir.resolve("missing.p12").toString(), allowEphemeralSigner = true),
            SecurityProperties(),
        ).create()
        assertThat(ephemeral).isInstanceOf(EphemeralEnvelopeSigner::class.java)

        assertThatThrownBy {
            EnvelopeSignerFactory(EnvelopeProperties(signerKeyStore = dir.resolve("missing.p12").toString()), SecurityProperties()).create()
        }.isInstanceOf(IllegalStateException::class.java).hasMessageContaining("ephemeral signer not allowed")

        assertThatThrownBy {
            EnvelopeSignerFactory(
                EnvelopeProperties(signerKeyStore = dir.resolve("missing.p12").toString(), allowEphemeralSigner = true),
                SecurityProperties(environment = "prod"),
            ).create()
        }.isInstanceOf(IllegalStateException::class.java)
    }

    @Test
    fun keyStoreEntriesAreReadWithTheJdkPkcs12Implementation(@TempDir dir: Path) {
        val ca = TestCrypto.certificateAuthority()
        val keyPair = TestCrypto.mlDsaKeyPair()
        val store = TestCrypto.keyStore(dir, "backend-server", keyPair, listOf(TestCrypto.issuedCertificate("CN=backend", keyPair, ca), ca.first))
        val loaded = KeyStore.getInstance("PKCS12")
        java.nio.file.Files.newInputStream(store).use { loaded.load(it, TestCrypto.STORE_PASSWORD.toCharArray()) }

        assertThat(loaded.isKeyEntry("backend-server")).isTrue()
    }
}

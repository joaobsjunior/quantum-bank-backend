package com.quantumbank.backend.envelope

import com.quantumbank.backend.security.PostQuantumTls
import com.quantumbank.backend.security.SecurityProperties
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jcajce.spec.ContextParameterSpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Component
import java.io.StringWriter
import java.math.BigInteger
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Duration
import java.util.Date

/**
 * Signs the envelope key set with the backend's ML-DSA-65 identity so the app
 * can verify it in pure Dart against the bundled ML-DSA-87 root, whatever the
 * platform TLS stack negotiated.
 */
interface EnvelopeSigner {
    /** PEM chain, leaf first, as the app expects in `signerChain`. */
    val certificateChainPem: List<String>

    /** Pure ML-DSA-65 signature with the FIPS 204 context [context]. */
    fun sign(message: ByteArray, context: ByteArray): ByteArray
}

private const val ML_DSA_65 = "ML-DSA-65"

internal fun mlDsaSign(privateKey: PrivateKey, message: ByteArray, context: ByteArray): ByteArray {
    val signature = Signature.getInstance(ML_DSA_65, BouncyCastleProvider.PROVIDER_NAME)
    signature.setParameter(ContextParameterSpec(context))
    signature.initSign(privateKey)
    signature.update(message)
    return signature.sign()
}

internal fun pemOf(certificate: X509Certificate): String {
    val writer = StringWriter()
    JcaPEMWriter(writer).use { it.writeObject(certificate) }
    return writer.toString()
}

/** Signer backed by the PKI-issued PKCS#12 identity (the TLS key store by default). */
class KeyStoreEnvelopeSigner(path: Path, password: CharArray) : EnvelopeSigner {
    private val privateKey: PrivateKey
    override val certificateChainPem: List<String>

    init {
        PostQuantumTls.install()
        val store = KeyStore.getInstance("PKCS12")
        Files.newInputStream(path).use { store.load(it, password) }
        val alias = store.aliases().toList().firstOrNull { store.isKeyEntry(it) }
            ?: throw IllegalStateException("envelope signer key store $path has no key entry")
        val key = store.getKey(alias, password) as PrivateKey
        require(key.algorithm == ML_DSA_65) { "envelope signer key must be $ML_DSA_65, got ${key.algorithm}" }
        privateKey = key
        certificateChainPem = store.getCertificateChain(alias).map { pemOf(it as X509Certificate) }
    }

    override fun sign(message: ByteArray, context: ByteArray): ByteArray = mlDsaSign(privateKey, message, context)
}

/**
 * Self-signed ML-DSA-65 signer for the local environment without PKI material
 * (unit tests, developer laptops). The app will refuse it (not chained to the
 * root), which is the intended fail-closed behaviour outside `local`.
 */
class EphemeralEnvelopeSigner(commonName: String = "backend", clock: Clock = Clock.systemUTC()) : EnvelopeSigner {
    private val privateKey: PrivateKey
    override val certificateChainPem: List<String>

    init {
        PostQuantumTls.install()
        val keyPair = KeyPairGenerator.getInstance(ML_DSA_65, BouncyCastleProvider.PROVIDER_NAME).generateKeyPair()
        val name = X500Name("CN=$commonName,O=QuantumBank,OU=ephemeral")
        val now = clock.instant()
        val builder = JcaX509v3CertificateBuilder(
            name,
            BigInteger.valueOf(now.toEpochMilli()),
            Date.from(now.minus(Duration.ofMinutes(1))),
            Date.from(now.plus(Duration.ofDays(1))),
            name,
            keyPair.public,
        )
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(false))
        val signer = JcaContentSignerBuilder(ML_DSA_65).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(keyPair.private)
        val certificate = JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(builder.build(signer))
        privateKey = keyPair.private
        certificateChainPem = listOf(pemOf(certificate))
    }

    override fun sign(message: ByteArray, context: ByteArray): ByteArray = mlDsaSign(privateKey, message, context)
}

/** Selects the signer from configuration; fails closed outside `local`. */
@Component
class EnvelopeSignerFactory(
    private val envelopeProperties: EnvelopeProperties,
    private val securityProperties: SecurityProperties,
) {
    private val logger = LoggerFactory.getLogger(EnvelopeSignerFactory::class.java)

    fun create(): EnvelopeSigner {
        val path = Path.of(envelopeProperties.signerKeyStore)
        if (Files.isRegularFile(path)) {
            return KeyStoreEnvelopeSigner(path, envelopeProperties.signerKeyStorePassword.toCharArray())
        }
        val local = securityProperties.environment == SecurityProperties.LOCAL_ENVIRONMENT
        check(local && envelopeProperties.allowEphemeralSigner) {
            "envelope signer key store ${envelopeProperties.signerKeyStore} not found and ephemeral signer not allowed outside local"
        }
        logger.warn("event=envelope.ephemeral_signer environment={} detail=self-signed ML-DSA-65 signer, devices will not trust it", securityProperties.environment)
        return EphemeralEnvelopeSigner()
    }
}


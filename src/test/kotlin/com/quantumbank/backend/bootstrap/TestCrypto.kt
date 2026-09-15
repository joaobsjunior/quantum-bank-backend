package com.quantumbank.backend.bootstrap

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import java.io.StringWriter
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.util.Date
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter

/** Test-only key, CSR, and certificate factory (no fixtures with baked-in keys). */
object TestCrypto {

    init {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    fun rsaKeyPair(bits: Int = 2048): KeyPair =
        KeyPairGenerator.getInstance("RSA").apply { initialize(bits) }.generateKeyPair()

    // Bouncy Castle provides legacy curves (for example secp192r1) that the JDK
    // no longer ships, so weak-key rejection can be exercised deterministically.
    fun ecKeyPair(curve: String = "secp256r1"): KeyPair =
        KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME)
            .apply { initialize(ECGenParameterSpec(curve)) }
            .generateKeyPair()

    fun ed25519KeyPair(): KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()

    fun csrPem(
        subject: String,
        publicKey: PublicKey,
        signingKey: PrivateKey,
        algorithm: String,
    ): String {
        val builder = JcaPKCS10CertificationRequestBuilder(X500Name(subject), publicKey)
        val csr = builder.build(
            JcaContentSignerBuilder(algorithm).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(signingKey),
        )
        return pem(csr)
    }

    fun rsaCsrPem(subject: String, keyPair: KeyPair = rsaKeyPair()): String =
        csrPem(subject, keyPair.public, keyPair.private, "SHA256withRSA")

    fun selfSignedCertificate(
        subject: String,
        keyPair: KeyPair = rsaKeyPair(),
        notAfter: Instant = Instant.now().plusSeconds(3_600),
    ): X509Certificate {
        val name = X500Name(subject)
        val holder = JcaX509v3CertificateBuilder(
            name,
            BigInteger.valueOf(System.nanoTime()),
            Date.from(Instant.now().minusSeconds(60)),
            Date.from(notAfter),
            name,
            SubjectPublicKeyInfo.getInstance(keyPair.public.encoded),
        ).build(JcaContentSignerBuilder("SHA256withRSA").build(keyPair.private))
        return JcaX509CertificateConverter().getCertificate(holder)
    }

    fun pem(value: Any): String {
        val writer = StringWriter()
        JcaPEMWriter(writer).use { it.writeObject(value) }
        return writer.toString()
    }
}

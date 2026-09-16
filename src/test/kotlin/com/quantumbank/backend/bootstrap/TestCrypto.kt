package com.quantumbank.backend.bootstrap

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import java.io.StringWriter
import java.math.BigInteger
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Security
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.util.Date

/** Test-only key, CSR, certificate and keystore factory (no fixtures with baked-in keys). */
object TestCrypto {

    const val ML_DSA_65 = "ML-DSA-65"
    const val ML_DSA_87 = "ML-DSA-87"
    const val ML_DSA_44 = "ML-DSA-44"
    const val STORE_PASSWORD = "changeit"

    init {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    /** Post-quantum key pair (FIPS 204); ML-DSA-65 is the mobile profile default. */
    fun mlDsaKeyPair(algorithm: String = ML_DSA_65): KeyPair =
        KeyPairGenerator.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME).generateKeyPair()

    fun rsaKeyPair(bits: Int = 2048): KeyPair =
        KeyPairGenerator.getInstance("RSA").apply { initialize(bits) }.generateKeyPair()

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

    /** ML-DSA CSR self-signed with the key it certifies (the pure signature, no pre-hash). */
    fun mlDsaCsrPem(subject: String, keyPair: KeyPair = mlDsaKeyPair(), algorithm: String = keyPair.private.algorithm): String =
        csrPem(subject, keyPair.public, keyPair.private, algorithm)

    fun rsaCsrPem(subject: String, keyPair: KeyPair = rsaKeyPair()): String =
        csrPem(subject, keyPair.public, keyPair.private, "SHA256withRSA")

    fun selfSignedCertificate(
        subject: String,
        keyPair: KeyPair = mlDsaKeyPair(),
        notAfter: Instant = Instant.now().plusSeconds(3_600),
    ): X509Certificate = issue(subject, keyPair.public, X500Name(subject), keyPair.private, notAfter, ca = false, sans = emptyList())

    /** Self-signed ML-DSA-87 CA usable as a trust anchor for loopback TLS tests. */
    fun certificateAuthority(subject: String = "CN=Test Root CA,O=QuantumBank"): Pair<X509Certificate, KeyPair> {
        val keyPair = mlDsaKeyPair(ML_DSA_87)
        return issue(subject, keyPair.public, X500Name(subject), keyPair.private, Instant.now().plusSeconds(3_600), ca = true, sans = emptyList()) to keyPair
    }

    /** Leaf certificate signed by [ca] for TLS (server or client authentication). */
    fun issuedCertificate(
        subject: String,
        keyPair: KeyPair,
        ca: Pair<X509Certificate, KeyPair>,
        sans: List<String> = listOf("localhost"),
    ): X509Certificate =
        // Issuer DN copied byte for byte from the CA subject so JDK chain checks match.
        issue(subject, keyPair.public, X500Name.getInstance(ca.first.subjectX500Principal.encoded), ca.second.private, Instant.now().plusSeconds(3_600), ca = false, sans = sans)

    private fun issue(
        subject: String,
        publicKey: PublicKey,
        issuer: X500Name,
        signingKey: PrivateKey,
        notAfter: Instant,
        ca: Boolean,
        sans: List<String>,
    ): X509Certificate {
        val builder = JcaX509v3CertificateBuilder(
            issuer,
            BigInteger.valueOf(System.nanoTime()),
            Date.from(Instant.now().minusSeconds(60)),
            Date.from(notAfter),
            X500Name(subject),
            SubjectPublicKeyInfo.getInstance(publicKey.encoded),
        )
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(ca))
        if (ca) {
            builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign))
        } else {
            builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.digitalSignature))
            builder.addExtension(
                Extension.extendedKeyUsage,
                false,
                ExtendedKeyUsage(arrayOf(KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth)),
            )
        }
        if (sans.isNotEmpty()) {
            builder.addExtension(
                Extension.subjectAlternativeName,
                false,
                GeneralNames(sans.map { GeneralName(GeneralName.dNSName, it) }.toTypedArray()),
            )
        }
        val signer = JcaContentSignerBuilder(signingKey.algorithm).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(signingKey)
        return JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(builder.build(signer))
    }

    /** PKCS#12 key store (leaf + CA chain) written with the JDK implementation, as the runtime uses. */
    fun keyStore(dir: Path, name: String, keyPair: KeyPair, chain: List<X509Certificate>): Path {
        val path = dir.resolve("$name.p12")
        KeyStore.getInstance("PKCS12").apply {
            load(null, null)
            setKeyEntry(name, keyPair.private, STORE_PASSWORD.toCharArray(), chain.toTypedArray())
            Files.newOutputStream(path).use { store(it, STORE_PASSWORD.toCharArray()) }
        }
        return path
    }

    fun trustStore(dir: Path, name: String, anchors: List<X509Certificate>): Path {
        val path = dir.resolve("$name.p12")
        KeyStore.getInstance("PKCS12").apply {
            load(null, null)
            anchors.forEachIndexed { index, anchor -> setCertificateEntry("anchor-$index", anchor) }
            Files.newOutputStream(path).use { store(it, STORE_PASSWORD.toCharArray()) }
        }
        return path
    }

    fun pem(value: Any): String {
        val writer = StringWriter()
        JcaPEMWriter(writer).use { it.writeObject(value) }
        return writer.toString()
    }
}

package com.quantumbank.backend.security

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider
import java.security.Security
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory

/**
 * Post-quantum transport policy for every TLS socket of this JVM.
 *
 * The JDK 17 JSSE has no ML-DSA signature schemes and no ML-KEM groups, so the
 * backend installs BouncyCastle's BCJSSE as the highest-priority JSSE provider
 * (Tomcat's `server.ssl.*` and the JWK-set `HttpsURLConnection` both resolve
 * `SSLContext.getInstance("TLS")`/`getDefault()` through it) and the plain BC
 * provider for the ML-DSA key, signature and certificate primitives. The JDK
 * PKCS#12 keystore and X.509 certificate factory stay in charge of parsing the
 * PKI-issued stores; they delegate the ML-DSA algorithms to BC.
 *
 * The policy is deliberately post-quantum only: the JVM offers and accepts
 * ML-DSA-65/87 signature schemes and the X25519MLKEM768 hybrid group, nothing
 * classical, on both the server and the client side, and only TLS 1.3.
 */
object PostQuantumTls {
    const val SIGNATURE_SCHEMES = "mldsa65,mldsa87"
    const val NAMED_GROUPS = "X25519MLKEM768"
    const val PROTOCOLS = "TLSv1.3"
    const val JSSE_PROVIDER = BouncyCastleJsseProvider.PROVIDER_NAME

    private val systemProperties = mapOf(
        "jdk.tls.server.SignatureSchemes" to SIGNATURE_SCHEMES,
        "jdk.tls.client.SignatureSchemes" to SIGNATURE_SCHEMES,
        "jdk.tls.namedGroups" to NAMED_GROUPS,
        "jdk.tls.client.protocols" to PROTOCOLS,
        "jdk.tls.server.protocols" to PROTOCOLS,
    )

    /**
     * Installs the providers and the policy. Idempotent and safe to call from
     * `main`, from Spring configuration and from tests; it fails closed when
     * the default `SSLContext` would still be served by a classical provider.
     */
    @JvmStatic
    fun install() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
        if (Security.getProvider(JSSE_PROVIDER) == null) {
            Security.insertProviderAt(BouncyCastleJsseProvider(), 1)
        }
        systemProperties.forEach { (name, value) -> System.setProperty(name, value) }
        // BCJSSE key/trust managers understand ML-DSA chains; select them for
        // every caller that uses the JSSE default algorithm names.
        Security.setProperty("ssl.KeyManagerFactory.algorithm", "PKIX")
        Security.setProperty("ssl.TrustManagerFactory.algorithm", "PKIX")
        verifyInstalled()
    }

    internal fun verifyInstalled() {
        val contextProvider = SSLContext.getInstance("TLS").provider.name
        val keyManagerProvider = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).provider.name
        val trustManagerProvider = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).provider.name
        check(contextProvider == JSSE_PROVIDER && keyManagerProvider == JSSE_PROVIDER && trustManagerProvider == JSSE_PROVIDER) {
            "post-quantum TLS provider is not active (SSLContext=$contextProvider, KeyManagerFactory=$keyManagerProvider, TrustManagerFactory=$trustManagerProvider)"
        }
    }
}

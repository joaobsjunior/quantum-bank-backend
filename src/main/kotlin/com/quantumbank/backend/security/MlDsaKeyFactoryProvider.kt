package com.quantumbank.backend.security

import java.security.Provider

/**
 * Serves only the ML-DSA `KeyFactory`, backed by BouncyCastle, ahead of SUN.
 *
 * Recent JDK 17 updates ship an ML-DSA `KeyFactory` in SUN, so the JDK PKCS#12
 * keystore (and Tomcat, which copies the server key into its own in-memory
 * store) would decode PKI-issued ML-DSA keys as a generic `ML-DSA`
 * `NamedPKCS8Key` that BCJSSE and the BC signature engine cannot use. This
 * provider makes every ML-DSA key decode as a BC key while SUN keeps parsing
 * the stores themselves (BC's PKCS#12 ignores the `-jdktrust` trust anchors).
 */
class MlDsaKeyFactoryProvider : Provider(NAME, "1.0", "ML-DSA KeyFactory backed by BouncyCastle") {
    init {
        service("ML-DSA", "Pure", listOf("MLDSA"))
        service("ML-DSA-44", "MLDSA44", oidAliases("17"))
        service("ML-DSA-65", "MLDSA65", oidAliases("18"))
        service("ML-DSA-87", "MLDSA87", oidAliases("19"))
    }

    private fun service(algorithm: String, spi: String, aliases: List<String>) {
        putService(Service(this, "KeyFactory", algorithm, "$SPI_PREFIX$spi", aliases, null))
    }

    private fun oidAliases(arc: String): List<String> = listOf("$ML_DSA_OID_PREFIX$arc", "OID.$ML_DSA_OID_PREFIX$arc")

    companion object {
        const val NAME = "QB-MLDSA"
        private const val SPI_PREFIX = "org.bouncycastle.jcajce.provider.asymmetric.mldsa.MLDSAKeyFactorySpi\$"
        private const val ML_DSA_OID_PREFIX = "2.16.840.1.101.3.4.3."
    }
}

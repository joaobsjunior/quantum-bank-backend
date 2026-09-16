package com.quantumbank.backend.security

import com.quantumbank.backend.bootstrap.TestCrypto
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.IOException
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyPair
import java.security.KeyStore
import java.security.Security
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSession
import javax.net.ssl.TrustManagerFactory

class PostQuantumTlsTest {

    @Test
    fun installsBcjsseAsTheDefaultJsseProviderIdempotently() {
        PostQuantumTls.install()
        PostQuantumTls.install()

        assertThat(Security.getProviders().first().name).isEqualTo(PostQuantumTls.JSSE_PROVIDER)
        assertThat(Security.getProviders().count { it.name == PostQuantumTls.JSSE_PROVIDER }).isEqualTo(1)
        assertThat(Security.getProviders().count { it.name == "BC" }).isEqualTo(1)
        assertThat(SSLContext.getInstance("TLS").provider.name).isEqualTo(PostQuantumTls.JSSE_PROVIDER)
        assertThat(SSLContext.getDefault().provider.name).isEqualTo(PostQuantumTls.JSSE_PROVIDER)
        assertThat(System.getProperty("jdk.tls.server.SignatureSchemes")).isEqualTo("mldsa65,mldsa87")
        assertThat(System.getProperty("jdk.tls.client.SignatureSchemes")).isEqualTo("mldsa65,mldsa87")
        assertThat(System.getProperty("jdk.tls.namedGroups")).isEqualTo("X25519MLKEM768")
        assertThat(System.getProperty("jdk.tls.server.protocols")).isEqualTo("TLSv1.3")
        assertThat(Security.getProperty("ssl.KeyManagerFactory.algorithm")).isEqualTo("PKIX")
        // The JDK keeps parsing PKCS#12 stores and X.509 certificates; BC provides the ML-DSA primitives.
        assertThat(KeyStore.getInstance("PKCS12").provider.name).isEqualTo("SUN")
        assertThat(java.security.Signature.getInstance("ML-DSA-65").provider.name).isEqualTo("BC")
        PostQuantumTls.verifyInstalled()
    }

    @Test
    fun negotiatesMlDsaMutualTlsOverHybridKeyExchange(@TempDir dir: Path) {
        PostQuantumTls.install()
        val ca = TestCrypto.certificateAuthority()
        val server = mlDsaIdentity(dir, "server", "CN=localhost", ca)
        val client = mlDsaIdentity(dir, "client", "CN=gateway-client", ca)
        val trust = TestCrypto.trustStore(dir, "trust", listOf(ca.first))

        LoopbackTlsServer(sslContext(server, trust)).use { loopback ->
            val response = HttpClient.newBuilder()
                .sslContext(sslContext(client, trust))
                .build()
                .send(HttpRequest.newBuilder(URI.create("https://localhost:${loopback.port}/")).GET().build(), HttpResponse.BodyHandlers.ofString())

            assertThat(response.statusCode()).isEqualTo(200)
            assertThat(response.body()).isEqualTo("pqc-ok")
            val session: SSLSession = response.sslSession().orElseThrow()
            assertThat(session.protocol).isEqualTo("TLSv1.3")
            assertThat(session.peerCertificates.first().publicKey.algorithm).isEqualTo(TestCrypto.ML_DSA_65)
            assertThat(loopback.lastPeer).isEqualTo("CN=gateway-client")
            assertThat(loopback.lastPeerKeyAlgorithm).isEqualTo(TestCrypto.ML_DSA_65)
        }
    }

    @Test
    fun refusesClassicalClientCertificatesAndAnonymousClients(@TempDir dir: Path) {
        PostQuantumTls.install()
        val ca = TestCrypto.certificateAuthority()
        val server = mlDsaIdentity(dir, "server", "CN=localhost", ca)
        val trust = TestCrypto.trustStore(dir, "trust", listOf(ca.first))
        val rsaKeyPair = TestCrypto.rsaKeyPair()
        val rsaClient = TestCrypto.keyStore(dir, "rsa-client", rsaKeyPair, listOf(TestCrypto.issuedCertificate("CN=rsa-client", rsaKeyPair, ca), ca.first))

        LoopbackTlsServer(sslContext(server, trust)).use { loopback ->
            val request = HttpRequest.newBuilder(URI.create("https://localhost:${loopback.port}/")).GET().build()

            // A certificate the CA signed for an RSA key cannot produce an accepted
            // CertificateVerify: the server aborts inside the handshake (TLS alert or
            // connection closed before any HTTP byte) and never records the peer.
            assertThatThrownBy {
                HttpClient.newBuilder().sslContext(sslContext(rsaClient, trust)).build().send(request, HttpResponse.BodyHandlers.ofString())
            }.isInstanceOf(IOException::class.java)
            assertThat(loopback.lastPeer).isNull()

            // No client certificate at all: rejected inside the handshake, never as HTTP.
            assertThatThrownBy {
                HttpClient.newBuilder().sslContext(sslContext(null, trust)).build().send(request, HttpResponse.BodyHandlers.ofString())
            }.isInstanceOf(IOException::class.java)
            assertThat(loopback.lastPeer).isNull()
            assertThat(loopback.rejectedHandshakes).isGreaterThanOrEqualTo(2)
        }
    }

    private fun mlDsaIdentity(dir: Path, name: String, subject: String, ca: Pair<java.security.cert.X509Certificate, KeyPair>): Path {
        val keyPair = TestCrypto.mlDsaKeyPair()
        return TestCrypto.keyStore(dir, name, keyPair, listOf(TestCrypto.issuedCertificate(subject, keyPair, ca), ca.first))
    }

    private fun sslContext(keyStorePath: Path?, trustStorePath: Path): SSLContext {
        val keyManagers = keyStorePath?.let { path ->
            KeyManagerFactory.getInstance("PKIX").apply { init(load(path), TestCrypto.STORE_PASSWORD.toCharArray()) }.keyManagers
        }
        val trustManagers = TrustManagerFactory.getInstance("PKIX").apply { init(load(trustStorePath)) }.trustManagers
        return SSLContext.getInstance("TLSv1.3").apply { init(keyManagers, trustManagers, null) }
    }

    private fun load(path: Path): KeyStore =
        KeyStore.getInstance("PKCS12").apply { Files.newInputStream(path).use { load(it, TestCrypto.STORE_PASSWORD.toCharArray()) } }

    /** Minimal HTTP/1.1 responder over BCJSSE requiring a client certificate. */
    private class LoopbackTlsServer(context: SSLContext) : AutoCloseable {
        private val socket = (context.serverSocketFactory.createServerSocket(0) as SSLServerSocket).apply {
            needClientAuth = true
            enabledProtocols = arrayOf("TLSv1.3")
        }
        private val executor = Executors.newSingleThreadExecutor()
        val port: Int = socket.localPort

        @Volatile
        var lastPeer: String? = null

        @Volatile
        var lastPeerKeyAlgorithm: String? = null

        @Volatile
        var rejectedHandshakes: Int = 0

        init {
            executor.submit {
                while (!socket.isClosed) {
                    try {
                        socket.accept().use { accepted ->
                            val tls = accepted as javax.net.ssl.SSLSocket
                            tls.startHandshake()
                            lastPeer = tls.session.peerPrincipal.name
                            lastPeerKeyAlgorithm = tls.session.peerCertificates.first().publicKey.algorithm
                            tls.inputStream.bufferedReader().let { reader ->
                                var line = reader.readLine()
                                while (!line.isNullOrEmpty()) {
                                    line = reader.readLine()
                                }
                            }
                            tls.outputStream.write("HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\npqc-ok".toByteArray())
                            tls.outputStream.flush()
                        }
                    } catch (_: Exception) {
                        // handshake failures are the expected outcome of the negative cases
                        if (!socket.isClosed) {
                            rejectedHandshakes += 1
                        }
                    }
                }
            }
        }

        override fun close() {
            socket.close()
            executor.shutdownNow()
            executor.awaitTermination(5, TimeUnit.SECONDS)
        }
    }

    @Test
    fun failsClosedWhenTheDefaultJsseProviderIsNotPostQuantum() {
        PostQuantumTls.install()
        val bcjsse = Security.getProvider(PostQuantumTls.JSSE_PROVIDER)
        try {
            Security.removeProvider(PostQuantumTls.JSSE_PROVIDER)
            assertThatThrownBy { PostQuantumTls.verifyInstalled() }
                .isInstanceOf(IllegalStateException::class.java)
                .hasMessageContaining("post-quantum TLS provider is not active")
        } finally {
            Security.insertProviderAt(bcjsse, 1)
        }
        PostQuantumTls.install()
        PostQuantumTls.verifyInstalled()
        assertThat(PostQuantumTlsConfiguration()).isNotNull()
    }
}

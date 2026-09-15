package com.quantumbank.backend.security

import com.quantumbank.backend.bootstrap.TestCrypto
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import tools.jackson.databind.json.JsonMapper

class GatewayClientCertificateFilterTest {

    private val objectMapper = JsonMapper.builder().build()

    private fun filter(enforce: Boolean = true): GatewayClientCertificateFilter =
        GatewayClientCertificateFilter(
            SecurityProperties(mtls = SecurityProperties.MtlsProperties(enforceGatewayIdentity = enforce)),
            objectMapper,
        )

    private fun request(vararg certificateSubjects: String): MockHttpServletRequest {
        val request = MockHttpServletRequest("GET", "/statements")
        if (certificateSubjects.isNotEmpty()) {
            request.setAttribute(
                GatewayClientCertificateFilter.X509_ATTRIBUTE,
                certificateSubjects.map { TestCrypto.selfSignedCertificate(it) }.toTypedArray(),
            )
        }
        return request
    }

    @Test
    fun filterIsSkippedWhenEnforcementIsDisabled() {
        val chain = MockFilterChain()
        val response = MockHttpServletResponse()

        filter(enforce = false).doFilter(request(), response, chain)

        assertThat(chain.request).isNotNull()
        assertThat(response.status).isEqualTo(200)
    }

    @Test
    fun allowsTheGatewayClientCertificate() {
        val chain = MockFilterChain()
        val response = MockHttpServletResponse()

        filter().doFilter(request("CN=gateway-client,O=QuantumBank"), response, chain)

        assertThat(chain.request).isNotNull()
        assertThat(response.status).isEqualTo(200)
    }

    @Test
    fun rejectsOtherCertificatesAndMissingCertificates() {
        listOf(
            request("CN=mobile-smoke-client"),
            request("CN=backend-client"),
            request("O=QuantumBank"),
            request("CN=gateway-client+O=QuantumBank"),
            request(),
        ).forEach { request ->
            val chain = MockFilterChain()
            val response = MockHttpServletResponse()

            filter().doFilter(request, response, chain)

            assertThat(chain.request).isNull()
            assertThat(response.status).isEqualTo(403)
            assertThat(response.contentType).isEqualTo(PROBLEM_JSON)
            assertThat(response.contentAsString).contains("mtls_client_not_allowed")
            assertThat(response.getHeader(CORRELATION_ID_HEADER)).isNotBlank()
        }
    }

    @Test
    fun ignoresAttributesThatAreNotCertificateArrays() {
        val request = MockHttpServletRequest("GET", "/statements")
        request.setAttribute(GatewayClientCertificateFilter.X509_ATTRIBUTE, "not-a-certificate")
        val emptyArray = MockHttpServletRequest("GET", "/statements")
        emptyArray.setAttribute(GatewayClientCertificateFilter.X509_ATTRIBUTE, arrayOf<String>())

        listOf(request, emptyArray).forEach { candidate ->
            val response = MockHttpServletResponse()
            filter().doFilter(candidate, response, MockFilterChain())
            assertThat(response.status).isEqualTo(403)
        }
    }
}

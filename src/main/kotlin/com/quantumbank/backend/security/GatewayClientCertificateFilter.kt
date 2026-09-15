package com.quantumbank.backend.security

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x500.style.IETFUtils
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import tools.jackson.databind.ObjectMapper
import java.security.cert.X509Certificate

/**
 * Transport-level gateway-only guard.
 *
 * Tomcat already requires a client certificate chained to the local CA
 * (`server.ssl.client-auth=NEED`). Every certificate the CA issues (mobile
 * device certificates, service certificates) would satisfy that check, so this
 * filter additionally pins the presented certificate CN to the gateway's own
 * client identity. JWT validation still happens afterwards; this filter only
 * decides who is allowed to talk to the backend at all.
 */
@Component
class GatewayClientCertificateFilter(
    private val securityProperties: SecurityProperties,
    private val objectMapper: ObjectMapper,
) : OncePerRequestFilter() {

    override fun shouldNotFilter(request: HttpServletRequest): Boolean =
        !securityProperties.mtls.enforceGatewayIdentity

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain,
    ) {
        val commonName = presentedCommonName(request)
        if (commonName == null || commonName !in securityProperties.mtls.allowedClientNames) {
            writeProblem(
                objectMapper = objectMapper,
                request = request,
                response = response,
                status = HttpStatus.FORBIDDEN,
                type = "https://quantum-bank.local/problems/transport",
                title = "Forbidden",
                errorCode = "mtls_client_not_allowed",
            )
            return
        }
        filterChain.doFilter(request, response)
    }

    private fun presentedCommonName(request: HttpServletRequest): String? {
        val certificates = request.getAttribute(X509_ATTRIBUTE) as? Array<*> ?: return null
        val leaf = certificates.firstOrNull() as? X509Certificate ?: return null
        return commonNameOf(leaf)
    }

    internal fun commonNameOf(certificate: X509Certificate): String? {
        val subject = X500Name.getInstance(certificate.subjectX500Principal.encoded)
        val commonNames = subject.getRDNs(BCStyle.CN)
        if (commonNames.size != 1 || commonNames[0].isMultiValued) {
            return null
        }
        return IETFUtils.valueToString(commonNames[0].first.value)
    }

    companion object {
        const val X509_ATTRIBUTE = "jakarta.servlet.request.X509Certificate"
    }
}

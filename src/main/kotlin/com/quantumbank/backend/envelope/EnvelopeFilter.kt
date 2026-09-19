package com.quantumbank.backend.envelope

import com.quantumbank.backend.security.quantumBankClientId
import com.quantumbank.backend.security.writeProblem
import jakarta.servlet.FilterChain
import jakarta.servlet.ReadListener
import jakarta.servlet.ServletInputStream
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletRequestWrapper
import jakarta.servlet.http.HttpServletResponse
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import org.springframework.web.util.ContentCachingResponseWrapper
import tools.jackson.databind.ObjectMapper
import java.io.BufferedReader
import java.io.ByteArrayInputStream
import java.io.InputStreamReader
import java.util.Base64

/**
 * Opens the application-layer envelope of banking requests and seals the
 * response with the key derived from the same hybrid secret (feature 012).
 *
 * Runs after Spring Security (default filter order), so the JWT is already
 * validated: the OAuth2 client decides the policy. Clients on the dual TLS
 * tier (`quantum-bank.envelope.required-for-clients`) must envelope every
 * banking request; strict-tier service clients keep plaintext JSON over their
 * post-quantum mutual TLS.
 */
@Component
@Order(Ordered.LOWEST_PRECEDENCE)
class EnvelopeFilter(
    private val properties: EnvelopeProperties,
    private val keyService: HybridEnvelopeKeyService,
    private val codec: HybridEnvelopeCodec,
    private val objectMapper: ObjectMapper,
) : OncePerRequestFilter() {

    public override fun shouldNotFilter(request: HttpServletRequest): Boolean = !properties.appliesTo(request.requestURI)

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain,
    ) {
        val message = try {
            readMessage(request)
        } catch (exception: EnvelopeException) {
            reject(request, response, exception.errorCode)
            return
        }
        if (message == null) {
            if (properties.requiresEnvelope(currentClientId())) {
                reject(request, response, EnvelopeErrorCodes.ENVELOPE_REQUIRED)
            } else {
                filterChain.doFilter(request, response)
            }
            return
        }

        val aad = "${request.method} ${request.requestURI}"
        val opened = try {
            val keyPair = keyService.keyPairFor(message.kid)
                ?: throw EnvelopeException(EnvelopeErrorCodes.ENVELOPE_KEY_UNKNOWN, "unknown envelope key id ${message.kid}")
            codec.open(message, keyPair, aad)
        } catch (exception: EnvelopeException) {
            reject(request, response, exception.errorCode)
            return
        }

        val wrappedRequest = EnvelopedRequest(request, opened.plaintext, message.contentType ?: MediaType.APPLICATION_JSON_VALUE)
        val wrappedResponse = ContentCachingResponseWrapper(response)
        filterChain.doFilter(wrappedRequest, wrappedResponse)

        val body = wrappedResponse.contentAsByteArray
        val contentType = wrappedResponse.contentType ?: MediaType.APPLICATION_JSON_VALUE
        val sealed = codec.seal(opened.responseKey, opened.kid, aad, body, contentType)
        wrappedResponse.resetBuffer()
        response.status = wrappedResponse.status
        response.contentType = EnvelopeMessage.MEDIA_TYPE
        response.setHeader(EnvelopeMessage.CONTENT_TYPE_HEADER, contentType)
        objectMapper.writeValue(response.outputStream, sealed)
        response.flushBuffer()
    }

    /** The envelope from the body (enveloped media type) or the header (bodiless requests); null when absent. */
    internal fun readMessage(request: HttpServletRequest): EnvelopeMessage? {
        val contentType = request.contentType
        val header = request.getHeader(EnvelopeMessage.REQUEST_HEADER)
        return try {
            when {
                contentType != null && MediaType.parseMediaType(contentType).isCompatibleWith(MediaType.parseMediaType(EnvelopeMessage.MEDIA_TYPE)) ->
                    objectMapper.readValue(request.inputStream, EnvelopeMessage::class.java)
                header != null ->
                    objectMapper.readValue(Base64.getUrlDecoder().decode(header), EnvelopeMessage::class.java)
                else -> null
            }
        } catch (_: Exception) {
            throw EnvelopeException(EnvelopeErrorCodes.ENVELOPE_INVALID, "malformed envelope")
        }
    }

    private fun currentClientId(): String? =
        (SecurityContextHolder.getContext().authentication?.principal as? Jwt)?.quantumBankClientId()

    private fun reject(request: HttpServletRequest, response: HttpServletResponse, errorCode: String) {
        writeProblem(
            objectMapper = objectMapper,
            request = request,
            response = response,
            status = HttpStatus.BAD_REQUEST,
            type = "https://quantum-bank.local/problems/envelope",
            title = "Envelope rejected",
            errorCode = errorCode,
        )
    }
}

/** The decrypted request as Spring MVC sees it: plaintext body and the original content type. */
internal class EnvelopedRequest(
    request: HttpServletRequest,
    private val plaintext: ByteArray?,
    private val plaintextContentType: String,
) : HttpServletRequestWrapper(request) {
    private val body: ByteArray = plaintext ?: ByteArray(0)

    override fun getContentType(): String? = if (plaintext == null) null else plaintextContentType

    override fun getContentLength(): Int = body.size

    override fun getContentLengthLong(): Long = body.size.toLong()

    override fun getHeader(name: String): String? =
        if (name.equals(HttpHeaders.CONTENT_TYPE, ignoreCase = true)) contentType else super.getHeader(name)

    override fun getInputStream(): ServletInputStream = object : ServletInputStream() {
        private val delegate = ByteArrayInputStream(body)
        override fun read(): Int = delegate.read()
        override fun isFinished(): Boolean = delegate.available() == 0
        override fun isReady(): Boolean = true
        override fun setReadListener(listener: ReadListener) = throw UnsupportedOperationException("blocking read only")
    }

    override fun getReader(): BufferedReader = BufferedReader(InputStreamReader(inputStream, Charsets.UTF_8))
}

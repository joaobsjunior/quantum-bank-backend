package com.quantumbank.backend.bootstrap

import com.quantumbank.backend.audit.BootstrapAuditEvents
import com.quantumbank.backend.security.SecurityProperties
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.assertj.core.api.Assertions.catchThrowableOfType
import org.junit.jupiter.api.Test
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mockito
import org.springframework.http.HttpStatus
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset

class OtkServiceTest {

    private val now = Instant.parse("2026-05-21T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val repository = Mockito.mock(InMemoryOtkRepository::class.java)
    private val validator = CsrValidator()
    private val auditEvents = BootstrapAuditEvents()
    private val securityProperties = SecurityProperties()

    private fun serviceWith(pkiAdapter: PkiAdapter): OtkService =
        OtkService(repository, validator, pkiAdapter, securityProperties, auditEvents, clock)

    private fun stubConsume(outcome: OtkConsumeOutcome) {
        Mockito.`when`(
            repository.consumeOnce(anyString(), anyString(), anyString(), anyString(), anyString(), anyString()),
        ).thenReturn(outcome)
    }

    private fun csrRequest(
        csr: String = VALID_CSR,
        certificateProfile: String? = null,
        environment: String? = null,
    ): CsrSubmitRequest =
        CsrSubmitRequest(
            otk = "otk-token",
            csr = csr,
            appInstanceId = "app-local-001",
            deviceId = "device-local-001",
            certificateProfile = certificateProfile,
            environment = environment,
        )

    @Test
    fun issueGeneratesTokenAndReturnsExpiry() {
        val service = serviceWith(SucceedingPkiAdapter())

        val response = service.issue(
            oauth2Subject = SUBJECT,
            request = OtkIssueRequest(appInstanceId = "app-local-001", deviceId = "device-local-001"),
            correlationId = "corr-1",
        )

        assertThat(response.otk).isNotBlank()
        assertThat(response.correlationId).isEqualTo("corr-1")
        assertThat(response.expiresAt).isEqualTo(now.plus(securityProperties.otkTtl))
    }

    @Test
    fun submitCsrHappyPathReturnsSignedCertificate() {
        stubConsume(OtkConsumeOutcome.Consumed(record()))
        val service = serviceWith(SucceedingPkiAdapter())

        val response = service.submitCsr(SUBJECT, csrRequest(), "corr-2")

        assertThat(response.certificate).isEqualTo("leaf-cert")
        assertThat(response.certificateChain).containsExactly("leaf-cert", "issuing-cert")
        assertThat(response.correlationId).isEqualTo("corr-2")
    }

    @Test
    fun submitCsrRejectsEmbeddedPrivateKeyMaterial() {
        val service = serviceWith(SucceedingPkiAdapter())

        val problem = catchThrowableOfType(
            { service.submitCsr(SUBJECT, csrRequest(csr = PRIVATE_KEY_CSR), "corr-3") },
            BootstrapProblemException::class.java,
        )

        assertThat(problem.errorCode).isEqualTo(BootstrapErrorCodes.PRIVATE_KEY_REJECTED)
        assertThat(problem.status).isEqualTo(HttpStatus.BAD_REQUEST)
        Mockito.verify(repository, Mockito.never())
            .consumeOnce(anyString(), anyString(), anyString(), anyString(), anyString(), anyString())
    }

    @Test
    fun submitCsrRejectsProfilePolicyMismatch() {
        val service = serviceWith(SucceedingPkiAdapter())

        val problem = catchThrowableOfType(
            { service.submitCsr(SUBJECT, csrRequest(certificateProfile = "other-profile"), "corr-4") },
            BootstrapProblemException::class.java,
        )

        assertThat(problem.errorCode).isEqualTo(BootstrapErrorCodes.CERTIFICATE_PROFILE_MISMATCH)
        assertThat(problem.status).isEqualTo(HttpStatus.BAD_REQUEST)
    }

    @Test
    fun submitCsrRejectsUnsupportedEnvironment() {
        val service = serviceWith(SucceedingPkiAdapter())

        val problem = catchThrowableOfType(
            { service.submitCsr(SUBJECT, csrRequest(environment = "prod"), "corr-5") },
            BootstrapProblemException::class.java,
        )

        assertThat(problem.errorCode).isEqualTo(BootstrapErrorCodes.UNSUPPORTED_ENVIRONMENT)
    }

    @Test
    fun submitCsrRejectsMalformedCsr() {
        val service = serviceWith(SucceedingPkiAdapter())

        val problem = catchThrowableOfType(
            { service.submitCsr(SUBJECT, csrRequest(csr = "not-a-csr"), "corr-6") },
            BootstrapProblemException::class.java,
        )

        assertThat(problem.errorCode).isEqualTo(BootstrapErrorCodes.CSR_INVALID)
        assertThat(problem.status).isEqualTo(HttpStatus.BAD_REQUEST)
    }

    @Test
    fun submitCsrRejectsSubjectMismatch() {
        val service = serviceWith(SucceedingPkiAdapter())

        val problem = catchThrowableOfType(
            { service.submitCsr("mallory@quantumbank.local", csrRequest(), "corr-7") },
            BootstrapProblemException::class.java,
        )

        assertThat(problem.errorCode).isEqualTo(BootstrapErrorCodes.SUBJECT_MISMATCH)
        assertThat(problem.status).isEqualTo(HttpStatus.BAD_REQUEST)
    }

    @Test
    fun submitCsrMapsEveryConsumeOutcomeToProblem() {
        val service = serviceWith(SucceedingPkiAdapter())
        val cases = mapOf(
            OtkConsumeOutcome.NotFound to (BootstrapErrorCodes.OTK_NOT_FOUND to HttpStatus.NOT_FOUND),
            OtkConsumeOutcome.Expired(record()) to (BootstrapErrorCodes.OTK_EXPIRED to HttpStatus.CONFLICT),
            OtkConsumeOutcome.Replayed(record()) to (BootstrapErrorCodes.OTK_REPLAYED to HttpStatus.CONFLICT),
            OtkConsumeOutcome.Revoked(record()) to (BootstrapErrorCodes.OTK_REVOKED to HttpStatus.CONFLICT),
            OtkConsumeOutcome.SubjectMismatch(record()) to (BootstrapErrorCodes.SUBJECT_MISMATCH to HttpStatus.BAD_REQUEST),
            OtkConsumeOutcome.DeviceMismatch(record()) to (BootstrapErrorCodes.DEVICE_MISMATCH to HttpStatus.BAD_REQUEST),
            OtkConsumeOutcome.CertificateProfileMismatch(record()) to
                (BootstrapErrorCodes.CERTIFICATE_PROFILE_MISMATCH to HttpStatus.BAD_REQUEST),
        )

        cases.forEach { (outcome, expected) ->
            Mockito.reset(repository)
            stubConsume(outcome)

            val problem = catchThrowableOfType(
                { service.submitCsr(SUBJECT, csrRequest(), "corr-outcome") },
                BootstrapProblemException::class.java,
            )

            assertThat(problem.errorCode).isEqualTo(expected.first)
            assertThat(problem.status).isEqualTo(expected.second)
        }
    }

    @Test
    fun submitCsrMapsPkiHandoffFailureToBadGateway() {
        stubConsume(OtkConsumeOutcome.Consumed(record()))
        val service = serviceWith(FailingPkiAdapter())

        val problem = catchThrowableOfType(
            { service.submitCsr(SUBJECT, csrRequest(), "corr-8") },
            BootstrapProblemException::class.java,
        )

        assertThat(problem.errorCode).isEqualTo(BootstrapErrorCodes.PKI_HANDOFF_FAILED)
        assertThat(problem.status).isEqualTo(HttpStatus.BAD_GATEWAY)
    }

    private fun record(token: String = "otk-token"): OtkRecord =
        OtkRecord(
            token = token,
            oauth2Subject = SUBJECT,
            appInstanceId = "app-local-001",
            deviceId = "device-local-001",
            certificateProfile = "quantum-bank-mobile-client-v1",
            environment = "local",
            expiresAt = now.plus(Duration.ofMinutes(5)),
        )

    private class SucceedingPkiAdapter : PkiAdapter {
        override fun sign(request: PkiSignRequest): PkiSignResult =
            PkiSignResult(
                certificate = "leaf-cert",
                certificateChain = listOf("leaf-cert", "issuing-cert"),
                expiresAt = Instant.now().plusSeconds(86_400),
            )
    }

    private class FailingPkiAdapter : PkiAdapter {
        override fun sign(request: PkiSignRequest): PkiSignResult =
            throw PkiHandoffException("sign failed")
    }

    private companion object {
        const val SUBJECT = "alice@quantumbank.local"

        val PRIVATE_KEY_CSR =
            """
            -----BEGIN PRIVATE KEY-----
            redacted
            -----END PRIVATE KEY-----
            """.trimIndent()

        const val VALID_CSR = """
-----BEGIN CERTIFICATE REQUEST-----
MIICjzCCAXcCAQAwSjEgMB4GA1UEAwwXYWxpY2VAcXVhbnR1bWJhbmsubG9jYWwx
FTATBgNVBAoMDFF1YW50dW0gQmFuazEPMA0GA1UECwwGTW9iaWxlMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzQr0h5BDvHgVA4qHtO6XI5YUxOLDJ+Xu
egrQntEpjPPRIla2AKmnIGBdylVxVxt4bEXjsNGAhxnpb2AIrL4NiDZtQcjnnheo
9F3kiHfpx60ONC53foaG4J1k1N0/6/5cpM7bO2v+MGHqZTaMF0Fx307ai/2LzgAP
0pbdp4Q+/TkP2TQ8oJs7qzE/8GKz0Ed8fdSZV/3BixC8gdLfAD/oDiXa9yXKz8Zw
SAA/5pWcLDejZJaGjgy6OQtGJA6p/E0v7Q7TtOpXl1Sv+JY4O5k092Cd7BFXeogm
HMR+kgUIVtmV/PRB/kE2uKZdTvZYQbHqlME4za8xie0S1Z4viuovuQIDAQABoAAw
DQYJKoZIhvcNAQELBQADggEBAEdPV1Q/3RwwxfcJerSchT9XyZK36RVOWLJ+Znpw
iemPAmOFyENkjJ5L0kv363H6OaWzUER4JsV6GHbePvdN1YYcG9iLGe0Ne/oq6p4+
AqeT02S75uZlnNIoehmQ26YnMl/oSb+sGqxFuG6KU3Bu43IGkTmn+K4++SDiCMB1
qrs2V+2TPmd/GvAUT7Ouo8nNuqRlO0oB8ph/SnV821djkTiE0Rx7uej71g2exyT6
zlTwLJW4P4lnlEQJEyj787ndkc3BTfcF805nrXP0zUA/EYp9RXmIH58lceecNtSh
eJo9cn++UcwyIZ1B8XEcXILeGKWReRChZtXY4/vXwItEuls=
-----END CERTIFICATE REQUEST-----
"""
    }
}

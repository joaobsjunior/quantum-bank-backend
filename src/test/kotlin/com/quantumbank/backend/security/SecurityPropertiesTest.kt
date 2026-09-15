package com.quantumbank.backend.security

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test

class SecurityPropertiesTest {

    @Test
    fun localEnvironmentMayUsePlaintextIssuerForDevelopment() {
        val properties = SecurityProperties(issuerUri = "http://localhost:8180/realms/quantum-bank-local")

        assertThat(properties.environment).isEqualTo(SecurityProperties.LOCAL_ENVIRONMENT)
        assertThat(properties.mtls.enforceGatewayIdentity).isFalse()
        assertThat(properties.mtls.allowedClientNames).containsExactly("gateway-client")
    }

    @Test
    fun nonLocalEnvironmentsRequireHttpsIssuerAndJwkEndpoints() {
        assertThatThrownBy {
            SecurityProperties(environment = "prod", issuerUri = "http://idp.example/realms/quantum-bank")
        }
            .isInstanceOf(IllegalArgumentException::class.java)
            .hasMessageContaining("issuer-uri must use https")

        assertThatThrownBy {
            SecurityProperties(
                environment = "prod",
                issuerUri = "https://idp.example/realms/quantum-bank",
                jwkSetUri = "http://idp.example/realms/quantum-bank/protocol/openid-connect/certs",
            )
        }
            .isInstanceOf(IllegalArgumentException::class.java)
            .hasMessageContaining("jwk-set-uri must use https")

        val valid = SecurityProperties(
            environment = "prod",
            issuerUri = "https://idp.example/realms/quantum-bank",
            jwkSetUri = "https://idp.example/realms/quantum-bank/protocol/openid-connect/certs",
        )
        assertThat(valid.environment).isEqualTo("prod")
    }

    @Test
    fun otkStoreCapacityMustBePositive() {
        assertThatThrownBy { SecurityProperties(otkMaxRecords = 0) }
            .isInstanceOf(IllegalArgumentException::class.java)
            .hasMessageContaining("otk-max-records")
    }
}

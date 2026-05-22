package com.quantumbank.backend.security

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtIssuerValidator
import org.springframework.security.oauth2.jwt.JwtTimestampValidator
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.core.userdetails.User
import org.springframework.security.web.SecurityFilterChain

@Configuration
@EnableWebSecurity
class SecurityConfig(
    private val securityProperties: SecurityProperties,
    private val authenticationEntryPoint: ProblemDetailsAuthenticationEntryPoint,
    private val accessDeniedHandler: ProblemDetailsAccessDeniedHandler,
) {

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .csrf { csrf -> csrf.disable() }
            .authorizeHttpRequests { authorize ->
                authorize
                    .requestMatchers(HttpMethod.POST, "/auth/otk", "/auth/csr")
                    .hasAuthority(scope("profile:read"))
                    .requestMatchers(HttpMethod.POST, "/pix/transfers")
                    .hasAuthority(scope("pix:write"))
                    .requestMatchers(HttpMethod.GET, "/statements")
                    .hasAuthority(scope("statements:read"))
                    .requestMatchers(HttpMethod.GET, "/profile")
                    .hasAuthority(scope("profile:read"))
                    .requestMatchers(HttpMethod.PUT, "/profile")
                    .hasAuthority(scope("profile:write"))
                    .anyRequest()
                    .authenticated()
            }
            .x509 { x509 ->
                x509.authenticationUserDetailsService { token ->
                    User.withUsername(token.name)
                        .password("")
                        .authorities("ROLE_MTLS_CLIENT")
                        .build()
                }
            }
            .oauth2ResourceServer { resourceServer ->
                resourceServer
                    .jwt { }
                    .authenticationEntryPoint(authenticationEntryPoint)
            }
            .exceptionHandling { exceptions ->
                exceptions
                    .authenticationEntryPoint(authenticationEntryPoint)
                    .accessDeniedHandler(accessDeniedHandler)
            }

        return http.build()
    }

    @Bean
    fun jwtDecoder(): JwtDecoder {
        val decoder = NimbusJwtDecoder.withJwkSetUri(securityProperties.jwkSetUri).build()
        decoder.setJwtValidator(
            DelegatingOAuth2TokenValidator(
                JwtTimestampValidator(securityProperties.clockSkew),
                JwtIssuerValidator(securityProperties.issuerUri),
                audienceValidator(securityProperties.audience),
            ),
        )
        return decoder
    }

    private fun audienceValidator(audience: String): OAuth2TokenValidator<Jwt> =
        OAuth2TokenValidator { jwt ->
            if (jwt.audience.contains(audience)) {
                OAuth2TokenValidatorResult.success()
            } else {
                OAuth2TokenValidatorResult.failure(
                    OAuth2Error(
                        "invalid_token",
                        "JWT audience must contain $audience",
                        null,
                    ),
                )
            }
        }

    private fun scope(value: String): String = "SCOPE_$value"

    companion object {
        const val ACCEPTED_AUDIENCE = "quantum-bank-api"
    }
}

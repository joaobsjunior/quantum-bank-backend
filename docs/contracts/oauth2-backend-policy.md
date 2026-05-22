# OAuth2 Backend Policy Contract

Requirement: AUTH-03, MTLS-02

Owner: Quantum Bank Backend

Backend rejects direct protected requests.

This contract defines the backend defense-in-depth OAuth2 Resource Server
policy for Phase 2.

## Resource Server Ownership

The backend validates OAuth2 bearer tokens on every protected route even when
requests normally arrive through KrakenD.

The backend owns direct-call rejection, endpoint scope authorization, and safe
authorization error responses. KrakenD remains the public app-facing route
boundary.

## Issuer And Audience

Local issuer:

- `http://localhost:8180/realms/quantum-bank-local`

Local JWKS:

- `http://localhost:8180/realms/quantum-bank-local/protocol/openid-connect/certs`

Accepted audience:

- `quantum-bank-api`

Clock skew:

- `60s`

## Protected Route Matrix

| Path | Method | Required scopes | Phase 2 behavior |
| --- | --- | --- | --- |
| `/auth/otk` | `POST` | `openid`, `profile` | Secured stub |
| `/auth/csr` | `POST` | `openid`, `profile` | Secured stub |
| `/pix/transfers` | `POST` | `pix:write` | Secured stub |
| `/statements` | `GET` | `statements:read` | Secured stub |
| `/profile` | `GET` | `profile:read` | Secured stub |

Business behavior for Pix simulation, statements, and profile remains Phase 4
scope.

## Negative Token Matrix

| Case | Expected result |
| --- | --- |
| missing token | `401 application/problem+json` |
| malformed token | `401 application/problem+json` |
| expired token | `401 application/problem+json` |
| wrong issuer | `401 application/problem+json` |
| wrong audience | `401 application/problem+json` |
| missing scope | `403 application/problem+json` |

Tests use direct backend requests for `missingToken`, `malformedToken`,
`expiredToken`, `wrongIssuer`, `wrongAudience`, and `missingScope`.

## Problem Details

Authentication and authorization failures use RFC 9457 problem details with
`application/problem+json`.

Responses include:

- `status`
- `title`
- `errorCode`
- `correlationId`

Responses must not expose token values, stack traces, backend implementation
details, route internals, CSR internals, or PKI internals.

## Gateway Header Trust Boundary

The backend does not trust gateway headers as authentication.

Gateway-forwarded identity or correlation headers may be used only after the
backend has independently validated the bearer token. Headers such as subject,
scope, user, role, or client id cannot replace JWT validation.

## Phase 3 Gateway-to-Backend mTLS

Phase 3 adds transport-layer client certificate authentication for
gateway-to-backend traffic while preserving the OAuth2 Resource Server policy.

- D-24: Gateway-to-backend mTLS protects every configured gateway-to-backend
  hop, including bootstrap routes.
- D-25: Backend keeps JWT Resource Server validation after mTLS is added.
- D-26: Forwarded certificate metadata is supplemental only; backend user
  identity remains JWT-derived.

`server.ssl.client-auth=NEED` requires the gateway client certificate when
backend TLS is enabled. Missing or untrusted gateway client certificates fail at
the TLS handshake layer as a handshake failure, before Spring MVC can return
problem details.

JWT remains the authoritative user identity. Controllers continue to derive user
identity from the validated JWT security context, not from X.509 principal names
or forwarded certificate metadata.

## Out Of Scope

Phase 2 does not implement:

- Real Pix transfer behavior.
- Statement persistence.
- Editable customer profile behavior.
- OTK and CSR business state transitions.
- Certificate lifecycle management.

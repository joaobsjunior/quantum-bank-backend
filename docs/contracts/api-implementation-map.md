# API Implementation Map

Requirement: CONT-02

Owner: Quantum Bank Backend

This map links app-facing KrakenD routes to backend responsibilities for local
v1 implementation.

No direct mobile-to-backend access.

The mobile app calls KrakenD only. Backend service URLs are internal runtime
details and must not appear in mobile configuration, mobile tests, or mobile
documentation as protected API origins.

## Route Responsibility Table

| Gateway path | Backend responsibility | Security context |
| --- | --- | --- |
| `POST /auth/otk` | Issue an OTK bound to `oauth2Subject`, `appInstanceId`, `deviceId`, and `certificateProfile`. | OAuth2 bearer subject from gateway. |
| `POST /auth/csr` | Validate OTK and CSR, consume the OTK atomically, reject private key material, and hand off accepted CSR data to PKI. | OAuth2 bearer subject from gateway. |
| `POST /pix/transfers` | Simulate Pix transfer success or error according to `scenario` with stable response and problem details shapes. | OAuth2 bearer and mTLS context from gateway. |
| `GET /statements` | Return account statement entries for the authenticated subject. | OAuth2 bearer and mTLS context from gateway. |
| `GET /profile` | Return customer registration data for the authenticated subject. | OAuth2 bearer and mTLS context from gateway. |

## Auth Bootstrap Responsibilities

For `POST /auth/otk`, backend validates required mobile binding inputs and
creates a one-time token record using the OTK state machine contract.

For `POST /auth/csr`, backend validates:

- OTK state.
- OTK TTL.
- `oauth2Subject`.
- `appInstanceId`.
- `deviceId`.
- `certificateProfile`.
- CSR parseability and subject policy.
- Absence of private key material.

Backend returns problem details for all validation failures.

## Pix Simulation Responsibilities

Requirement: PIX-API-01

For `POST /pix/transfers`, backend interprets Pix scenario values `SUCCESS` and
`ERROR` sent by the app.

`SUCCESS` returns the success schema defined in the OpenAPI contract. `ERROR`
returns `application/problem+json` using a stable error code and correlation id.

Phase 4 implementation persists both outcomes in H2. `SUCCESS` persists and
returns status `COMPLETED`; `ERROR` persists status `FAILED` and returns stable
errorCode `pix_simulated_error`.

The backend must not rely on random failure for the local v1 Pix simulation;
the caller-provided scenario controls the path so end-to-end tests can cover
both success and error.

## Statement Responsibilities

For `GET /statements`, backend returns deterministic local v1 statement data
for the authenticated subject.

The response must match `StatementResponse` from the gateway OpenAPI contract
and include a `correlationId`.

## Profile Responsibilities

For `GET /profile`, backend returns deterministic customer registration data for
the authenticated subject.

The response must match `ProfileResponse` from the gateway OpenAPI contract and
include a `correlationId`.

## Error Response Contract

All app-facing backend failures routed through KrakenD use problem details with
media type `application/problem+json`.

Backend errors must include:

- `type`
- `title`
- `status`
- `errorCode`
- `correlationId`

Optional `detail`, `instance`, and `fieldErrors` fields may be included when
safe for app display.

## Implementation Boundary

Backend implements route behavior and data ownership. KrakenD owns public API
exposure and gateway policy. PKI owns certificate lifecycle.

Backend implementation must remain compatible with
`api-gateway/openapi/quantum-bank-v1.yaml`.

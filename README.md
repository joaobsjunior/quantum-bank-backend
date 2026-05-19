# Quantum Bank Backend

Spring Boot Kotlin backend for Quantum Bank.

Initial responsibilities:

- OAuth2-protected banking APIs
- Pix success and error simulation
- Statement and customer registration data APIs
- H2 or in-memory persistence for v1 development
- Certificate and mTLS integration points required by the gateway and PKI layer

## Phase 1 Contract Ownership

The backend owns and consumes these Phase 1 contracts:

- [OTK and CSR Contract](docs/contracts/otk-csr-contract.md) for CONT-01 one-time token state, CSR validation, audit events, error codes, and PKI handoff.
- [API Implementation Map](docs/contracts/api-implementation-map.md) for CONT-02 backend responsibilities behind the KrakenD app-facing API.

Later backend implementation must preserve `No direct mobile-to-backend access` and use H2 or an in-memory runtime for local v1 persistence.

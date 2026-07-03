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

## Phase 2 OAuth2 Backend Policy

Phase 2 adds backend defense-in-depth authorization for direct protected
requests.

- [OAuth2 Backend Policy Contract](docs/contracts/oauth2-backend-policy.md) documents AUTH-03 issuer, audience, scopes, negative-token handling, problem details, and gateway header trust boundaries.
- `./gradlew test` runs the direct backend JWT failure matrix.

## Phase 3 Bootstrap Validation

Phase 3 implements backend-owned PKI-02 bootstrap validation before certificate
issuance.

- [OTK and CSR Contract](docs/contracts/otk-csr-contract.md) now documents Phase 3 runtime validation, stable bootstrap error codes, audit events, and the PKI adapter handoff.
- `src/main/kotlin/com/quantumbank/backend/bootstrap/` contains the OTK controllers, atomic in-memory repository, CSR validator, problem-details mapping, and PKI adapter boundary.
- `src/main/kotlin/com/quantumbank/backend/audit/BootstrapAuditEvents.kt` emits source-level bootstrap events without logging OTK token values, CSR PEM, or private key material.
- `./gradlew test --tests "*Otk*" --tests "*Csr*"` runs the focused OTK/CSR validation suite.
- `./gradlew test` runs the full backend verification suite.

## Phase 4 Banking Simulation APIs

Phase 4 adds H2-backed local v1 banking APIs.

- `POST /pix/transfers` persists deterministic `SUCCESS` and `ERROR`
  simulation attempts.
- `GET /statements` returns fixture statement entries for the authenticated JWT
  subject.
- `GET /profile` returns fixture customer registration data.
- `PUT /profile` edits profile fields and requires `profile:write`.

## Phase 6 Docker Runtime

The backend has a multi-stage [Dockerfile](Dockerfile) that builds the Spring
Boot jar with the checked-in Gradle launcher and runs it on Eclipse Temurin 17.
The Phase 6 Compose runtime enables backend TLS/mTLS through environment
variables and mounts PKI-owned local runtime certificates from the `pki`
submodule.

## Testing & CI

- Run tests and enforce coverage: `./gradlew check`.
- Coverage is measured by Kover with a **100% line-coverage** verification rule
  bound to `check`; the build fails below target. Reports land in
  `build/reports/kover/` (`report.xml`, `html/`).
- Reviewed coverage exclusions live in `build.gradle.kts` (Spring Boot bootstrap
  entrypoint only).
- CI (`.github/workflows/ci.yml`) runs `./gradlew check` on every push/PR to
  `main` and uploads the coverage report.

## Runtime Requirements

The backend runs as a JVM service (Eclipse Temurin 17 JRE) with H2 held fully in
memory (`jdbc:h2:mem:...`), so it has no database disk footprint.

| Resource | Build (Docker multi-stage) | Run (container) |
| --- | --- | --- |
| Memory | ~1–2 GB (Gradle `bootJar`) | ~400 MB idle → ~768 MB–1 GB peak (JVM heap + in-memory H2) |
| CPU | 2+ vCPU (faster build) | 0.5–1 vCPU |
| Storage | JDK build image ~450 MB + Gradle cache ~0.5–1.5 GB | runtime image ~350 MB |

- The multi-stage [Dockerfile](Dockerfile) compiles the jar in a `17-jdk` stage
  and runs it on `17-jre`; the build stage is the heaviest step (first build is
  slow and disk-heavy, later builds reuse cached layers).
- No persistent volume is required; it only mounts PKI runtime certs read-only.
- Suggested container limit for local runs: `--memory=1g --cpus=1`.

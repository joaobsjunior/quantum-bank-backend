# OTK and CSR Contract

Requirement: CONT-01, PKI-02

Owner: Quantum Bank Backend

This contract defines the backend-owned vocabulary and validation behavior for
one-time token issuance, CSR submission, and the handoff from application
identity to certificate provisioning.

The backend owns OTK validation. The PKI layer owns certificate issuance,
renewal, and revocation. KrakenD owns public routing and mTLS enforcement at the
gateway boundary.

## Phase 3 Backend Validation

Phase 3 implements PKI-02 in `src/main/kotlin/com/quantumbank/backend/bootstrap/`.
The backend now owns the runtime OTK state machine, CSR parsing, CSR
fingerprinting, stable problem-details responses, and PKI handoff boundary.

The implementation preserves these Phase 3 truths:

- D-09: Backend owns OTK state and CSR validation before PKI handoff.
- D-10: Mobile submits CSR through KrakenD to backend; mobile never calls PKI directly.
- D-11: Backend derives oauth2Subject from JWT, not from client-supplied identity.
- D-12: Phase 3 uses an atomic, concurrency-safe in-memory OTK repository.
- D-13: CSR validation rejects private key material, malformed CSR, unknown profile, unsupported environment, expired OTK, replayed OTK, subject mismatch, app/device mismatch, and profile mismatch.
- D-14: Backend emits source-level audit events for OTK and CSR state changes.
- D-15: Backend bootstrap errors use application/problem+json with stable errorCode and correlationId.

Runtime classes:

- `OtkController` derives `oauth2Subject` from JWT and issues OTKs bound to app, device, profile, and environment.
- `CsrController` derives `oauth2Subject` from JWT and submits CSR data to `OtkService`.
- `InMemoryOtkRepository` uses an atomic `computeIfPresent` transition for one-use OTK consumption.
- `CsrValidator` uses Bouncy Castle `PKCS10CertificationRequest` parsing and SHA-256 fingerprinting over CSR DER bytes.
- `PkiAdapter` invokes the configured PKI-owned `sign-csr.sh` command instead of signing certificates in backend code.
- `BootstrapAuditEvents` emits audit events without OTK token values, CSR PEM, or private key material.

## OTK Definition

OTK means one-time token.

An OTK is a short-lived credential issued after OAuth2 authentication and used
once to authorize a mobile client CSR submission. It is not a login token, API
access token, refresh token, certificate, or private key container.

The OTK record is bound to the authenticated subject and to the client instance
that will submit the CSR. Backend validation must reject any CSR submission that
does not match the binding fields captured when the OTK was issued.

The local v1 TTL is 5 minutes for local v1 unless changed by configuration.

The OTK binding fields are:

- `oauth2Subject`: authenticated OAuth2 subject that requested the OTK.
- `appInstanceId`: stable mobile app installation identifier for this bootstrap.
- `deviceId`: device identifier supplied by the mobile layer for local v1.
- `certificateProfile`: PKI profile requested for the certificate.
- `csrFingerprint`: fingerprint of the CSR submitted for one-use validation.

The backend must not embed secret key material in the OTK payload. The OTK is a
stateful backend record with an opaque client-facing token value.

## OTK State Machine

Each OTK has exactly one current state.

Valid states are:

- `issued`: token exists, TTL has not elapsed, and no CSR was accepted yet.
- `consumed`: CSR validation succeeded and the token was used exactly once.
- `expired`: TTL elapsed before a valid CSR was accepted.
- `replayed`: a token in `consumed`, `expired`, `revoked`, or rejected state was
  presented again.
- `revoked`: token was administratively invalidated before use.
- `rejected_subject_mismatch`: CSR submission did not match `oauth2Subject`.
- `rejected_device_mismatch`: CSR submission did not match `appInstanceId` or
  `deviceId`.

Allowed transitions:

- `issued` to `consumed` when CSR validation passes and handoff to PKI begins.
- `issued` to `expired` when TTL is exceeded.
- `issued` to `revoked` when local policy invalidates the token.
- `issued` to `rejected_subject_mismatch` when the OAuth2 subject does not
  match the OTK binding.
- `issued` to `rejected_device_mismatch` when app or device binding does not
  match the OTK binding.
- Any terminal state to `replayed` when the same client-facing token value is
  submitted again.

Terminal states are `consumed`, `expired`, `replayed`, `revoked`,
`rejected_subject_mismatch`, and `rejected_device_mismatch`.

## CSR Submission Contract

The backend receives CSR submissions through the gateway path `POST /auth/csr`.
The mobile app must call KrakenD, not backend services directly.

The submission payload must include:

- OTK client-facing value.
- CSR encoded as PEM or another explicit format agreed in the OpenAPI contract.
- `oauth2Subject` from the authenticated request context.
- `appInstanceId`.
- `deviceId`.
- `certificateProfile`.

The backend computes `csrFingerprint` from the submitted CSR and stores it on
the OTK record at successful consumption. A later submission with the same OTK
must be treated as replay even if the CSR is byte-for-byte identical.

Private key material is never accepted by backend. Private key generation and
storage are mobile responsibilities. If a request contains private key material
or a field that appears to carry a private key, the backend must reject the
request before PKI handoff.

## Validation Rules

Backend validation must perform these checks before any PKI handoff:

1. Resolve the OTK record by opaque token value.
2. Confirm the OTK exists.
3. Confirm the OTK is in `issued` state.
4. Confirm the OTK has not exceeded the configured TTL.
5. Confirm the authenticated `oauth2Subject` matches the OTK binding.
6. Confirm submitted `appInstanceId` matches the OTK binding.
7. Confirm submitted `deviceId` matches the OTK binding.
8. Confirm requested `certificateProfile` matches the OTK binding.
9. Parse the CSR using a standards-based parser.
10. Confirm the CSR subject and SAN inputs match the OTK binding policy.
11. Compute and persist `csrFingerprint`.
12. Atomically transition the OTK to `consumed`.

Validation must be atomic from the perspective of token consumption. Concurrent
submissions for the same OTK may produce only one successful consumption.

## Audit Events

Backend audit events must be emitted for the following actions:

- `otk.issued`
- `otk.consumed`
- `otk.expired`
- `otk.replayed`
- `otk.revoked`
- `otk.rejected_subject_mismatch`
- `otk.rejected_device_mismatch`
- `csr.rejected_private_key_material`
- `csr.accepted_for_pki_handoff`

Each audit event should include OTK id, `oauth2Subject`, `appInstanceId`,
`deviceId`, `certificateProfile`, resulting state, timestamp, and correlation
id. Audit events must not include private key material.

## Error Codes

Backend error responses for OTK and CSR failures use problem details and stable
application codes.

| errorCode | HTTP status | Meaning |
|-----------|-------------|---------|
| `otk_not_found` | 404 | OTK value does not resolve to a backend record. |
| `otk_expired` | 409 | OTK exceeded the configured TTL. |
| `otk_replayed` | 409 | OTK was already consumed or otherwise terminal. |
| `otk_revoked` | 409 | OTK was revoked before use. |
| `subject_mismatch` | 400 | Authenticated subject does not match `oauth2Subject` from JWT or CSR policy. |
| `device_mismatch` | 400 | Submitted client binding does not match `appInstanceId` or `deviceId`. |
| `certificate_profile_mismatch` | 400 | Requested profile differs from OTK binding or supported profile. |
| `unsupported_environment` | 400 | Requested environment is not supported by local v1. |
| `csr_invalid` | 400 | CSR cannot be parsed or fails CSR policy. |
| `private_key_rejected` | 400 | Request included private key material. |
| `pki_handoff_failed` | 502 | Backend validation passed but PKI handoff failed. |

Each error response must be safe for mobile display and must not leak token
values, CSR internals, or certificate authority implementation details.

## Handoff to PKI

After successful validation, backend hands off the CSR and validated identity
metadata to the PKI layer.

The PKI handoff includes:

- CSR.
- `oauth2Subject`.
- `appInstanceId`.
- `deviceId`.
- `certificateProfile`.
- `csrFingerprint`.
- Backend correlation id.

The backend does not issue, renew, or revoke certificates. It validates the OTK
and CSR contract, consumes the OTK, and delegates certificate lifecycle work to
the PKI owner.

Local v1 handoff uses the configured command:

```sh
../pki/scripts/sign-csr.sh CSR_PATH OUT_CERT_PATH oauth2Subject appInstanceId deviceId local quantum-bank-mobile-client-v1
```

Focused verification:

```sh
./gradlew test --tests "*Otk*" --tests "*Csr*"
./gradlew test
```

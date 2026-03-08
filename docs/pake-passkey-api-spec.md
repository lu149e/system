# PAKE + Passkeys API Spec

## Scope and status

- This document defines the target HTTP contract for auth v2.
- Current repo baseline is still `POST /v1/auth/login` plus `/v1/auth/passkey/*` in `src/main.rs:424`-`src/main.rs:459`.
- Problem responses MUST stay aligned with the current `application/problem+json` shape in `src/api/problem.rs:4`-`src/api/problem.rs:18`.
- Trace propagation MUST stay compatible with `x-trace-id` / `x-request-id` handling in `src/api/handlers.rs:1039`-`src/api/handlers.rs:1046`.

## Decision: `POST /v2/auth/methods` is canonical

### Why POST, not GET

- `GET /v2/auth/methods?identifier=user@example.com` leaks the identifier into URL logs, browser history, proxy caches, CDN logs, and APM tooling. That is amateur hour for an enumeration-sensitive endpoint.
- `POST` keeps the identifier in the body, makes `Cache-Control: no-store` the default posture, and is easier to bind to device capabilities.
- The tradeoff is worse cacheability and less "REST purity". Good. This endpoint should not be cached by shared infrastructure anyway.

### Policy

- Production contract: expose `POST /v2/auth/methods`.
- `GET /v2/auth/methods` SHOULD be disabled with `405 Method Not Allowed` unless a trusted internal BFF absolutely needs it.
- If `GET` is ever enabled for a trusted internal channel, it MUST use `Cache-Control: no-store`, MUST NOT sit behind shared caches, and MUST be treated as lower-security than POST.

## Common protocol rules

### Headers

- Request: `Content-Type: application/json`
- Request: optional `X-Trace-Id` or `X-Request-Id`
- Response: `Cache-Control: no-store, max-age=0`
- Error response: `Content-Type: application/problem+json`

### Problem shape

All non-2xx responses use:

```json
{
  "type": "https://example.com/problems/invalid-credentials",
  "title": "Invalid credentials",
  "status": 401,
  "detail": "Authentication failed",
  "trace_id": "6c90d0d2-4f83-4f23-94d8-9d4b1d8dfad9"
}
```

### Invariants

- Anti-enumeration: unknown account, inactive account, missing PAKE enrollment, and wrong password MUST collapse to the same external outcome wherever feasible.
- TTL: interactive auth flows default to 300 seconds, matching the current MFA/passkey challenge budget configured by `MFA_CHALLENGE_TTL_SECONDS` and reused by passkey flows in `src/modules/auth/application.rs:1953`-`src/modules/auth/application.rs:1958`.
- One-time use: every `flow_id` MUST be consumed exactly once; current passkey implementation already sets the pattern with `DELETE ... RETURNING` in `src/adapters/postgres.rs:1016`-`src/adapters/postgres.rs:1024` and `src/adapters/postgres.rs:1107`-`src/adapters/postgres.rs:1115`.
- Traceability: every successful or rejected step MUST produce audit metadata with `trace_id`, flow kind, client IP, user agent, and rollout/fallback decision.
- Fallback: legacy password fallback is an explicit policy decision, never a silent automatic branch.
- Replay resistance: `flow_id` and protocol state are single-use and bound to flow kind.
- Multi-instance safety: all challenge state is server-side, not in-memory only.

## Endpoint summary

| Endpoint | Purpose | Auth required |
| --- | --- | --- |
| `POST /v2/auth/methods` | Discover safe next auth options for an identifier + client | No |
| `POST /v2/auth/password/login/start` | Start PAKE login handshake | No |
| `POST /v2/auth/password/login/finish` | Finish PAKE login handshake | No |
| `POST /v2/auth/password/upgrade/start` | Start OPAQUE enrollment for a legacy account | Session or upgrade ticket |
| `POST /v2/auth/password/upgrade/finish` | Finish OPAQUE enrollment and update legacy metadata | Session or upgrade ticket |
| `POST /v2/auth/passkeys/login/start` | Start passkey login from the v2 namespace | No |
| `POST /v2/auth/passkeys/login/finish` | Finish passkey login from the v2 namespace | No |
| `POST /v2/auth/passkeys/enroll/start` | Start passkey opt-in enrollment | Session |
| `POST /v2/auth/passkeys/enroll/finish` | Finish passkey opt-in enrollment | Session |

## `POST /v2/auth/methods`

### Purpose

- Returns the safe next-step contract for the client without exposing whether the account definitely exists.
- Replaces the idea of a naive account lookup endpoint.

### Request

```http
POST /v2/auth/methods
Content-Type: application/json
X-Trace-Id: 6c90d0d2-4f83-4f23-94d8-9d4b1d8dfad9
```

```json
{
  "identifier": "user@example.com",
  "channel": "web",
  "client": {
    "supports_pake": true,
    "supports_passkeys": true,
    "supports_conditional_mediation": true,
    "platform": "firefox-linux"
  }
}
```

### Response 200

```json
{
  "request_id": "6c90d0d2-4f83-4f23-94d8-9d4b1d8dfad9",
  "discovery_token": "dtk_2f6e1f3f1fdf4b85b9f76d3b6a3c8f28",
  "discovery_expires_in": 300,
  "methods": [
    {
      "type": "password_pake",
      "version": "opaque_v1",
      "action": "start",
      "path": "/v2/auth/password/login/start"
    },
    {
      "type": "passkey",
      "version": "webauthn_v1",
      "action": "start",
      "path": "/v2/auth/passkeys/login/start",
      "client_mediation": "conditional_if_available"
    }
  ],
  "account_recovery": {
    "kind": "password_reset",
    "path": "/v1/auth/password/forgot"
  },
  "recommended_method": "passkey",
  "legacy_password_fallback": {
    "possible": false,
    "user_visible": false
  }
}
```

### Response notes

- `discovery_token` is an opaque, signed token binding normalized identifier, channel, and client capabilities for 300 seconds.
- Response stays structurally valid even if the account does not exist; do not leak `account_exists`, `passkey_registered`, or `opaque_enrolled`.
- `account_recovery` is intentionally policy-neutral. Returning it does NOT confirm the identifier exists; it tells the client which recovery entrypoint is safe to offer.
- `recommended_method` is a UX hint, not proof of account state.
- `legacy_password_fallback.user_visible` stays `false` for anonymous callers. If you surface this externally you are asking for enumeration bugs.

### Errors

- `400 Bad Request` - malformed body, invalid identifier format, unsupported channel value.
- `429 Too Many Requests` - discovery throttled by identifier/IP bucket.
- `503 Service Unavailable` - only for clear system outage, not for account-state failures.

### Audit and metrics

- Audit events: `auth.v2.methods.requested`, `auth.v2.methods.rejected`
- Metrics to add in `src/observability.rs`: `auth_v2_methods_requests_total{outcome,...}`, `auth_v2_methods_duration_seconds`, `auth_v2_methods_rejected_total{reason}`

## `GET /v2/auth/methods`

### Default production behavior

```http
GET /v2/auth/methods?identifier=user@example.com
```

- Response: `405 Method Not Allowed`
- Rationale: URL-based identifier transport is weaker against logging and cache leakage.

### If enabled for a trusted internal BFF

- Semantics MUST match `POST /v2/auth/methods`.
- Response headers MUST include:

```http
Cache-Control: no-store, max-age=0
Pragma: no-cache
```

- It MUST NOT be enabled for public browser traffic.

## `POST /v2/auth/password/login/start`

### Purpose

- Starts PAKE login and stores one-time server state in `auth_flows`.
- Applies abuse and risk gating before issuing the challenge, same idea as current password login and passkey login in `src/modules/auth/application.rs:1361`-`src/modules/auth/application.rs:1370` and `src/modules/auth/application.rs:1139`-`src/modules/auth/application.rs:1148`.

### Request

```json
{
  "identifier": "user@example.com",
  "discovery_token": "dtk_2f6e1f3f1fdf4b85b9f76d3b6a3c8f28",
  "client": {
    "supports_pake": true,
    "platform": "firefox-linux"
  }
}
```

### Response 200

```json
{
  "flow_id": "af_1f5d8f3db948473d8b49d7c0f9fd7a61",
  "flow_kind": "password_login",
  "protocol": "opaque_v1",
  "server_message": {
    "opaque_message": "BASE64URL_PAYLOAD"
  },
  "expires_in": 300,
  "next": {
    "action": "finish",
    "path": "/v2/auth/password/login/finish"
  }
}
```

### Neutrality rules

- If the account is unknown, inactive, or not yet enrolled in OPAQUE, the server still returns a structurally valid response.
- For non-existent or non-enrolled accounts, the returned `server_message` may be derived from a deterministic dummy record or a server-controlled fake OPAQUE record so finish-time behavior stays indistinguishable enough. Do not improvise crypto; the chosen library/boundary must support this safely.
- If policy wants legacy fallback, that decision is stored internally on the flow. It is not exposed here.

### Errors

- `400 Bad Request` - malformed request or missing `supports_pake=true`.
- `401 Unauthorized` - reserved for invalid discovery token only if the token format itself is bad; not for unknown accounts.
- `429 Too Many Requests` - lockout or abuse gating. Return `Retry-After`, same behavior shape as current `AuthError::LoginLocked` mapping in `src/api/problem.rs:146`-`src/api/problem.rs:157`.
- `503 Service Unavailable` - PAKE service unavailable and fallback policy forbids legacy path.

### Problem types

- `https://example.com/problems/invalid-request`
- `https://example.com/problems/login-locked`
- `https://example.com/problems/pake-unavailable`

## `POST /v2/auth/password/login/finish`

### Purpose

- Finishes PAKE handshake, evaluates MFA/risk, and reuses the existing session + refresh issuance path now implemented in `issue_session_tokens` at `src/modules/auth/application.rs:1560`-`src/modules/auth/application.rs:1618`.

### Request

```json
{
  "flow_id": "af_1f5d8f3db948473d8b49d7c0f9fd7a61",
  "client_message": {
    "opaque_message": "BASE64URL_PAYLOAD"
  },
  "device_info": "Firefox on Linux"
}
```

### Response 200 - authenticated

```json
{
  "authenticated": true,
  "access_token": "...",
  "refresh_token": "...",
  "token_type": "Bearer",
  "expires_in": 900,
  "mfa_required": false,
  "challenge_id": null,
  "upgrade_required": false
}
```

### Response 200 - MFA step-up required

```json
{
  "authenticated": false,
  "access_token": null,
  "refresh_token": null,
  "token_type": null,
  "expires_in": null,
  "mfa_required": true,
  "challenge_id": "mfa_7f4b3fd8...",
  "message": "Additional verification required",
  "upgrade_required": false
}
```

### Response 200 - authenticated but PAKE upgrade required next

```json
{
  "authenticated": true,
  "access_token": "...",
  "refresh_token": "...",
  "token_type": "Bearer",
  "expires_in": 900,
  "mfa_required": false,
  "challenge_id": null,
  "upgrade_required": true,
  "upgrade": {
    "path": "/v2/auth/password/upgrade/start",
    "deadline_hint": "before_v1_sunset"
  }
}
```

### External failure behavior

- Invalid flow, expired flow, replayed flow, wrong password, unknown account, inactive account, and invalid PAKE client message MUST converge to the same generic auth failure contract as much as protocol safety permits.
- If the flow internally used approved legacy fallback and that fallback fails, the external response is still generic `401 invalid-credentials`.
- If the flow is already consumed, return generic `401 invalid-credentials`, not a special replay oracle.

### Errors

- `400 Bad Request` - malformed message only when request cannot be parsed.
- `401 Unauthorized` - `invalid-credentials` for invalid/expired/replayed flow or failed verification.
- `429 Too Many Requests` - lockout or repeated flow abuse.
- `503 Service Unavailable` - downstream cryptographic dependency unavailable and no fallback permitted.

### Problem types

- `https://example.com/problems/invalid-credentials`
- `https://example.com/problems/login-locked`
- `https://example.com/problems/pake-unavailable`

## `POST /v2/auth/password/upgrade/start`

### Purpose

- Starts OPAQUE enrollment for a legacy password account.
- Minimal supported entry points:
  - authenticated session after successful v1 or v2 login
  - valid password-reset completion flow
  - tightly scoped server-issued upgrade ticket from an approved migration path

### Request

```json
{
  "upgrade_context": "session",
  "client": {
    "supports_pake": true,
    "platform": "firefox-linux"
  }
}
```

### Reserved recovery-bridge request shape

When the server issues a recovery bridge, the same endpoint uses the existing `upgrade_context` field plus the free-form client payload to carry the bridge reference:

```json
{
  "upgrade_context": "recovery_bridge",
  "client_message": {
    "recovery_flow_id": "af_recovery_bridge_123"
  },
  "client": {
    "supports_pake": true,
    "platform": "firefox-linux"
  }
}
```

- `recovery_flow_id` is a server-issued, one-time auth-flow identifier.
- Unknown, expired, or replayed bridge ids MUST fail with `https://example.com/problems/invalid-recovery-bridge`.
- Policy-driven login risk that cannot step up with MFA SHOULD fail with `https://example.com/problems/recovery-required` instead of collapsing into generic invalid credentials.

### Response 200

```json
{
  "flow_id": "af_9d8f5a41d26d4b4c8f86ebf2fc94820a",
  "flow_kind": "password_upgrade",
  "protocol": "opaque_v1",
  "server_message": {
    "registration_response": "BASE64URL_PAYLOAD"
  },
  "expires_in": 300,
  "next": {
    "action": "finish",
    "path": "/v2/auth/password/upgrade/finish"
  }
}
```

### Errors

- `401 Unauthorized` - missing or invalid session/upgrade ticket.
- `401 Unauthorized` - invalid or expired recovery bridge.
- `403 Forbidden` - recovery bridge required by policy but not satisfied.
- `409 Conflict` - account already has active OPAQUE credential and policy forbids re-enrollment.
- `429 Too Many Requests` - upgrade abuse/throttle.
- `503 Service Unavailable` - PAKE dependency unavailable.

## `POST /v2/auth/password/upgrade/finish`

### Purpose

- Persists the OPAQUE credential record and updates legacy metadata.

### Request

```json
{
  "flow_id": "af_9d8f5a41d26d4b4c8f86ebf2fc94820a",
  "client_message": {
    "registration_upload": "BASE64URL_PAYLOAD"
  }
}
```

### Response 200

```json
{
  "upgraded": true,
  "opaque_version": "opaque_v1",
  "legacy_password": {
    "login_allowed": true,
    "deprecation_window": "temporary"
  }
}
```

### Side effects

- Write or upsert `opaque_credentials`.
- Mark `credentials.migrated_to_opaque_at` and `credentials.last_legacy_verified_at` or equivalent reporting fields.
- Optionally set `credentials.legacy_login_allowed=false` later in rollout phases, never at phase 1 by surprise.
- Emit audit event `auth.v2.password.upgrade.completed`.

### Errors

- `401 Unauthorized` - invalid or expired upgrade flow.
- `409 Conflict` - upgrade state race or already consumed flow.
- `422 Unprocessable Entity` - cryptographically invalid registration upload.
- `503 Service Unavailable` - credential store or PAKE dependency unavailable.

## `POST /v2/auth/passkeys/login/start`

### Purpose

- Starts passkey authentication from the unified v2 namespace.
- In phase 1 this can be an alias over the existing WebAuthn flow already implemented in `src/modules/auth/application.rs:1130`-`src/modules/auth/application.rs:1211`.

### Request

```json
{
  "identifier": "user@example.com",
  "discovery_token": "dtk_2f6e1f3f1fdf4b85b9f76d3b6a3c8f28"
}
```

### Response 200

```json
{
  "flow_id": "af_7d1d4f...",
  "flow_kind": "passkey_login",
  "protocol": "webauthn_v1",
  "options": {
    "publicKey": {}
  },
  "expires_in": 300
}
```

### Errors

- `400 Bad Request` - malformed request.
- `401 Unauthorized` - generic invalid credentials if passkey login cannot proceed.
- `403 Forbidden` - passkeys disabled for the service.
- `429 Too Many Requests` - abuse/lockout.

## `POST /v2/auth/passkeys/login/finish`

### Purpose

- Finishes passkey login and returns the same auth result envelope used by password finish.

### Request

```json
{
  "flow_id": "af_7d1d4f...",
  "credential": {
    "id": "...",
    "rawId": "...",
    "response": {},
    "type": "public-key"
  },
  "device_info": "Firefox on Linux"
}
```

### Response 200

- Same authenticated/MFA response shapes as `POST /v2/auth/password/login/finish`.

### Errors

- `401 Unauthorized` - invalid credentials or invalid/expired flow.
- `403 Forbidden` - passkeys disabled.
- `422 Unprocessable Entity` - invalid WebAuthn assertion payload.
- `429 Too Many Requests` - abuse/lockout.

## `POST /v2/auth/passkeys/enroll/start`

### Purpose

- Authenticated opt-in passkey enrollment in the v2 namespace.
- Operationally this is the same ceremony family already present in `/v1/auth/passkey/register/*` from `src/main.rs:443`-`src/main.rs:450`; this doc just normalizes it under v2.

### Request

```json
{
  "label": "Personal laptop",
  "authenticator_preference": "platform_or_cross_platform"
}
```

### Response 200

```json
{
  "flow_id": "af_8f14b6...",
  "flow_kind": "passkey_register",
  "protocol": "webauthn_v1",
  "options": {
    "publicKey": {}
  },
  "expires_in": 300
}
```

### Errors

- `401 Unauthorized` - no valid bearer token.
- `403 Forbidden` - passkeys globally disabled, same current posture as `AuthError::PasskeyDisabled` in `src/api/problem.rs:111`-`src/api/problem.rs:117`.
- `409 Conflict` - enrollment blocked by account policy.

## `POST /v2/auth/passkeys/enroll/finish`

### Request

```json
{
  "flow_id": "af_8f14b6...",
  "credential": {
    "id": "...",
    "rawId": "...",
    "response": {},
    "type": "public-key"
  }
}
```

### Response 200

```json
{
  "enrolled": true,
  "passkey_count": 1,
  "recommended_login_method": "passkey"
}
```

### Errors

- `401 Unauthorized` - invalid/expired flow.
- `422 Unprocessable Entity` - invalid WebAuthn attestation/assertion payload.
- `503 Service Unavailable` - passkey subsystem unavailable.

## Fallback policy

### Rules

- Legacy fallback is controlled by config/allowlist, not by best effort.
- Allowed fallback reasons are limited to:
  - account not yet upgraded to OPAQUE
  - PAKE dependency degraded during early rollout
  - explicitly approved legacy client segment
- Fallback MUST be recorded in the flow state and audit trail.
- Fallback MUST increment dedicated metrics.
- Fallback MUST be disabled by default for admin/internal privileged cohorts first, not last.

### What is forbidden

- Silent fallback after an internal PAKE verification bug without any audit or metric.
- User-visible branching like "this account still uses old password login" before auth success.
- Using fallback to mask SLO regressions forever. That just buries the bug.

## TTL and one-time semantics

- Discovery token TTL: 300s
- Login start flow TTL: 300s
- Upgrade flow TTL: 300s
- Passkey enrollment flow TTL: 300s
- Consumed flows remain queryable only through audit data, not reusable state.
- Janitor/background pruning should mirror the current passkey challenge janitor operational model in `src/observability.rs:122`-`src/observability.rs:165` and `src/health.rs:149`-`src/health.rs:155`.

## Audit events to standardize

- `auth.v2.methods.requested`
- `auth.v2.methods.rejected`
- `auth.v2.password.login.challenge.issued`
- `auth.v2.password.login.rejected`
- `auth.v2.password.login.success`
- `auth.v2.password.login.fallback_v1_used`
- `auth.v2.password.upgrade.started`
- `auth.v2.password.upgrade.completed`
- `auth.v2.password.upgrade.rejected`
- `auth.v2.passkey.enroll.started`
- `auth.v2.passkey.enroll.completed`

## Open validation items before implementation

- Confirm the chosen OPAQUE library can safely support fake records / dummy responses for anti-enumeration.
- Confirm whether v2 will alias existing passkey handlers first or immediately move them to `auth_flows`.
- Confirm exact problem type URLs before clients hardcode them.

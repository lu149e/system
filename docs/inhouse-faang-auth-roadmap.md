# In-House Auth Roadmap (FAANG-Level Target)

## Goal

Build and operate a fully in-house identity platform with strong phishing resistance,
high abuse resistance, fast incident response, and provable security controls.

Reference docs for the password modernization track:

- `docs/pake-passkey-prd.md`
- `docs/pake-passkey-migration-plan.md`

## Non-Negotiable Principles

1. Transport security first: no auth traffic without TLS.
2. Generic external auth errors: never leak account state to attackers.
3. Passwordless-first architecture: passkeys as primary factor.
4. Risk-adaptive controls: challenge users only when risk requires it.
5. Operational excellence: detect and contain auth incidents quickly.

## Current Baseline (already present)

- Password hashing with Argon2.
- MFA challenge flow and backup codes.
- Refresh token rotation and replay detection.
- Login abuse controls and lockout controls.
- JWKS endpoint and key rotation support.

## 30 / 60 / 90 Plan

### Days 0-30 (Tier-0 hardening)

Scope:

- Enforce secure transport at edge and app trust boundary.
- Remove account-enumeration signals in login responses.
- Add abuse controls by account + IP + device fingerprint seed.
- Strengthen audit and alerting for auth anomalies.

Deliverables:

- App-level policy to reject insecure forwarded protocol in production mode.
- Generic login failure problem contract for inactive/unknown/invalid states.
- Security dashboards and alerts for lockout spikes and refresh replay events.
- Runbook for emergency token-family revoke and key kill-switch.

Exit criteria:

- No endpoint accepts insecure auth traffic in production.
- Login responses do not reveal account state.
- MTTD for auth abuse events under 5 minutes.

### Days 31-60 (Passwordless foundation)

Scope:

- Implement WebAuthn registration/authentication ceremony server-side.
- Add device binding and step-up policy hooks.
- Keep password as fallback while passkey adoption grows.

Deliverables:

- `/v1/auth/webauthn/register/*` and `/v1/auth/webauthn/login/*` endpoints.
- Credential store for public keys, counters, attestation metadata.
- Policy engine path for mandatory step-up on risky actions.

Exit criteria:

- Passkey login available for all supported clients.
- Password login remains fallback only.
- Replay and cloned authenticator detections are audited.

### Days 61-90 (Risk engine + elite operations)

Scope:

- Build in-house risk scoring pipeline.
- Introduce adaptive controls (allow, challenge, block).
- Formalize red-team and game-day operations.

Deliverables:

- Risk model features: geo velocity, ASN reputation, device novelty, session age.
- Real-time auth decision API used by login and sensitive actions.
- Incident drills for account takeover and refresh token replay campaigns.

Exit criteria:

- Adaptive auth policy active in production.
- MTTR for auth incidents under 30 minutes.
- Quarterly red-team findings closed within SLA.

## Engineering Epics (Ordered)

1. Transport and trust boundary hardening.
2. Enumeration-safe auth contracts.
3. Abuse and throttling v2.
4. Passkey platform.
5. Risk engine and adaptive auth.
6. Recovery hardening (account recovery, high-risk user changes).
7. Security operations and continuous verification.

## Metrics (must be green)

- p95 login latency < 250ms.
- Auth SLO >= 99.99%.
- 0 open high/critical code scanning findings in auth components.
- Refresh replay containment <= 1 minute from first detection.
- 100% key rotation drills complete without downtime.

## Immediate Implementation Queue (next iterations)

1. Add secure transport enforcement middleware for production traffic.
2. Add risk decision hook abstraction in auth application service.
3. Add passkey domain model and persistence interfaces.
4. Add WebAuthn API handlers and challenge state storage.
5. Add adaptive rate-limit profile by risk score.

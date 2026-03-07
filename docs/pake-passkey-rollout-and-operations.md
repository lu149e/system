# PAKE + Passkeys Rollout and Operations

## Scope and status

- This doc covers how to roll out auth v2 without kidding ourselves about readiness.
- Current repo already has useful production building blocks: audit events, sessions, refresh rotation, risk decisions, passkey metrics, readiness endpoints, and passkey challenge janitor plumbing (`src/observability.rs:13`-`src/observability.rs:44`, `src/health.rs:149`-`src/health.rs:168`, `docs/observability-auth-refresh.md:1`).
- Target state adds PAKE-specific controls, dashboards, alerts, feature flags, and rollback procedures. The runtime metrics now exist in `src/observability.rs`, and the shipped operational assets live in `docs/grafana/auth-refresh-runtime-prometheus.json`, `docs/alerts/auth-refresh-alert-rules.yaml`, and `docs/deployment-production-checklist.md`.

## Current vs target

### Current

- Password login is still single-shot `email + password` via `POST /v1/auth/login` in `src/main.rs:438` and `src/api/handlers.rs:691`.
- Passkeys exist behind runtime flags `PASSKEY_ENABLED`, `PASSKEY_RP_ID`, `PASSKEY_RP_ORIGIN`, `PASSKEY_CHALLENGE_PRUNE_INTERVAL_SECONDS` in `src/config.rs:167`-`src/config.rs:183`.
- Passkey transient state has a janitor and readiness component already wired in `src/observability.rs` and `src/health.rs`.

### Target

- Discovery + PAKE login live under `/v2/auth/*`.
- Passkey login/enrollment participates in the same rollout, metrics, and fallback language.
- Legacy v1 login stays available only behind explicit policy until sunset.

## Rollout strategy

## Feature flags

### Existing flags to keep using

- `PASSKEY_ENABLED`
- `PASSKEY_RP_ID`
- `PASSKEY_RP_ORIGIN`
- `PASSKEY_CHALLENGE_PRUNE_INTERVAL_SECONDS`

### New target flags

- `AUTH_V2_METHODS_ENABLED` - exposes `POST /v2/auth/methods`
- `AUTH_V2_PASSWORD_PAKE_ENABLED` - enables PAKE start/finish handlers
- `AUTH_V2_PASSWORD_UPGRADE_ENABLED` - enables upgrade enrollment endpoints
- `AUTH_V2_PASSKEY_NAMESPACE_ENABLED` - exposes `/v2/auth/passkeys/*` aliases or new handlers
- `AUTH_V2_AUTH_FLOWS_ENABLED` - enables shared flow store usage
- `AUTH_V2_LEGACY_FALLBACK_MODE` - `disabled | allowlisted | broad`
- `AUTH_V2_CLIENT_ALLOWLIST` - CSV or remote config of clients/channels allowed into v2
- `AUTH_V2_SHADOW_AUDIT_ONLY` - compute v2 eligibility without serving v2 externally

### Flag rules

- Flags are evaluated server-side.
- Client versions alone are not enough; tie rollout to server allowlists.
- Fallback mode must be independently kill-switchable from v2 handler exposure.

## Phases

### Phase 0 - decision and dark readiness

- Validate OPAQUE library or alternative boundary with security review.
- Land schema, ports, and metrics without sending production traffic.
- Enable `AUTH_V2_SHADOW_AUDIT_ONLY=true` in non-prod, then internal prod shadow.

### Phase 1 - internal and canary staff

- Enable `AUTH_V2_METHODS_ENABLED` and `AUTH_V2_PASSWORD_PAKE_ENABLED` only for employees/internal test clients.
- Keep `AUTH_V2_LEGACY_FALLBACK_MODE=allowlisted`.
- Success criterion: stable auth success rate, low fallback ratio, no unexplained 401/429 spikes.

### Phase 2 - opt-in beta clients

- Expand to web beta and one mobile cohort.
- Keep v1 visible but not default for these cohorts.
- Start authenticated legacy-to-OPAQUE upgrade after successful login.

### Phase 3 - passkey-first UX for eligible clients

- Serve `recommended_method=passkey` for clients with conditional mediation support.
- Keep password PAKE as fallback.
- Start measuring passkey-first conversion separately from raw passkey enrollment.

### Phase 4 - broad rollout

- Default new compatible clients to v2.
- Restrict v1 to approved legacy clients and break-glass fallback.
- Disable new legacy-only password enrollment paths.

### Phase 5 - v1 sunset

- Remove v1 from default client configs.
- Keep kill-switch only for a tightly bounded window.
- Start decommission plan for legacy password data after exit criteria are met.

## Channel strategy

- `internal` - staff and QA only
- `canary_web` - modern browsers, lowest support risk
- `canary_mobile` - latest app versions only
- `beta_external` - invited customers/tenants
- `broad_general` - default production traffic
- `legacy_holdout` - explicitly carved-out old clients

Each auth event should include rollout channel in audit metadata.

## Observability

## Metrics to keep

- Existing passkey, refresh, problem, and risk metrics in `src/observability.rs` stay as the baseline.
- Existing dashboard guidance in `docs/observability-auth-refresh.md` remains relevant.

## Metrics to add for v2

- `auth_v2_methods_requests_total{outcome,channel}`
- `auth_v2_methods_rejected_total{reason}`
- `auth_v2_methods_duration_seconds{outcome}`
- `auth_v2_password_start_requests_total{outcome,channel}`
- `auth_v2_password_start_duration_seconds{outcome}`
- `auth_v2_password_finish_requests_total{outcome,channel}`
- `auth_v2_password_finish_duration_seconds{outcome}`
- `auth_v2_password_rejected_total{reason}`
- `auth_v2_password_upgrade_requests_total{operation,outcome}`
- `auth_v2_password_upgrade_duration_seconds{operation,outcome}`
- `auth_v2_legacy_fallback_total{reason,channel}`
- `auth_v2_auth_flow_janitor_enabled`
- `auth_v2_auth_flow_prune_interval_seconds`
- `auth_v2_auth_flow_prune_runs_total{outcome}`
- `auth_v2_auth_flow_prune_last_success_unixtime`
- `auth_v2_auth_flow_prune_last_failure_unixtime`
- `auth_v2_auth_flow_pruned_total`
- `auth_v2_auth_flow_prune_errors_total`
- `auth_v2_auth_flows_active{flow_kind}`
- `auth_v2_auth_flows_expired_pending_total`
- `auth_v2_auth_flows_oldest_expired_pending_age_seconds`

## Audit events to add

- `auth.v2.methods.requested`
- `auth.v2.methods.rejected`
- `auth.v2.password.login.challenge.issued`
- `auth.v2.password.login.success`
- `auth.v2.password.login.rejected`
- `auth.v2.password.login.fallback_v1_used`
- `auth.v2.password.upgrade.started`
- `auth.v2.password.upgrade.completed`
- `auth.v2.password.upgrade.rejected`
- `auth.v2.rollout.flag_override_used`

## Logs

- Structured logs MUST include: `trace_id`, `flow_id`, `flow_kind`, `rollout_channel`, `client_id` or app version, IP, user agent, and fallback reason when applicable.
- Do not log raw identifiers, passwords, PAKE messages, or WebAuthn blobs.

## Dashboards

Minimum dashboards before broad rollout:

- v2 success rate by channel
- v2 latency p50/p95/p99 by endpoint
- fallback volume and ratio by reason
- auth flow janitor health and backlog
- passkey enrollment success vs login success
- 401/429/5xx problem rate by endpoint and client version
- upgrade completion ratio for legacy accounts

Shipped repo assets now cover the baseline rollout views:

- `docs/grafana/auth-refresh-runtime-prometheus.json` includes auth v2 success/error ratio, password latency, fallback pressure, and auth-flow janitor/backlog panels.
- `docs/alerts/auth-refresh-alert-rules.yaml` includes the matching recording and alert rules for password finish error ratio, fallback ratio, and auth-flow prune/backlog degradation.
- `scripts/validate-observability-artifacts.sh` validates the Grafana JSON and Prometheus rules before anyone calls the assets production-ready.

## Alerts

Minimum alert set before external rollout:

- PAKE finish failure ratio above threshold for 10m
- fallback ratio above threshold for 10m
- auth flow prune failures sustained for 10m
- active expired flow backlog above threshold
- v2 5xx rate above threshold
- passkey registration or login rejection spike after release

Current shipped alerts and records live in `docs/alerts/auth-refresh-alert-rules.yaml` and include:

- `auth:auth_v2_password_finish_error_ratio_10m`
- `auth:auth_v2_legacy_fallback_ratio_15m`
- `auth:auth_v2_auth_flow_prune_errors_10m`
- `auth:auth_v2_auth_flow_oldest_expired_pending_age_seconds_max_15m`
- `AuthV2PasswordFinishErrorRatioHigh`
- `AuthV2PasswordFinishErrorRatioCritical`
- `AuthV2LegacyFallbackRatioHigh`
- `AuthV2AuthFlowPruneErrorsSustained`
- `AuthV2AuthFlowExpiredBacklogHigh`

## Suggested initial thresholds

- `WARNING`: `auth_v2_password_finish` error ratio >= 5% for 10m with at least 50 finish attempts
- `CRITICAL`: `auth_v2_password_finish` error ratio >= 10% for 10m with at least 100 finish attempts
- `WARNING`: fallback ratio >= 3% for 15m after canary stabilization
- `CRITICAL`: fallback ratio >= 10% for 10m in broad rollout
- `WARNING`: auth flow prune failures >= 5 in 10m
- `CRITICAL`: oldest expired pending flow age >= 900s for 15m

## Security and threat model summary

## Assets

- account identifiers
- legacy password hashes
- OPAQUE credential blobs
- passkey credentials
- auth flow state
- sessions and refresh tokens

## Main threats

- account enumeration through methods/start/finish differences
- flow replay and token replay
- downgrade from PAKE to legacy password
- credential stuffing on legacy path during coexistence
- passkey ceremony abuse or malformed client payloads
- observability leaks containing identifiers or crypto payloads
- library-level cryptographic bugs or unsafe defaults

## Controls

- neutral responses across unknown/inactive/unenrolled cases
- one-time server-side flows with TTL and prune jobs
- explicit fallback policy with audit trail
- rate limiting and lockout reuse from current login path
- risk decision reuse from current login path in `src/modules/auth/application.rs:1499`-`src/modules/auth/application.rs:1558`
- no custom crypto, no homegrown PAKE transcript handling
- privileged kill-switches per rollout channel

## Notable residual risks

- If the chosen OPAQUE library cannot support fake record handling safely, anti-enumeration gets harder and the protocol choice may need to change.
- If v1 fallback remains broad for too long, attackers will target the weakest path. Obviously.

## Runbooks

## Runbook: PAKE finish failure spike

1. Confirm whether the issue is isolated to one client channel/version.
2. Check `auth_v2_password_finish_requests_total` and `auth_v2_password_rejected_total{reason}`.
3. Compare `auth:auth_v2_password_finish_error_ratio_10m`, `auth:auth_v2_legacy_fallback_ratio_15m`, and problem response rate in `docs/grafana/auth-refresh-runtime-prometheus.json`.
4. If impact is material, disable `AUTH_V2_PASSWORD_PAKE_ENABLED` for affected channels.
5. Keep `AUTH_V2_METHODS_ENABLED` on only if it can safely recommend passkeys or v1 fallback.
6. Capture sample traces via `trace_id` and audit rows before changing more flags.

## Runbook: auth flow store degradation

1. Check DB health plus `auth_v2_auth_flow_prune_runs_total`, `auth_v2_auth_flows_expired_pending_total`, and `auth_v2_auth_flows_oldest_expired_pending_age_seconds`.
2. If `auth_flows` writes or consumes fail, disable `AUTH_V2_PASSWORD_PAKE_ENABLED` and `AUTH_V2_PASSWORD_UPGRADE_ENABLED`.
3. Keep existing passkey path on `passkey_challenges` only if it is isolated and healthy.
4. Do not leave partially working shared flow storage enabled.

## Runbook: fallback explosion

1. Check if the cause is new cohort onboarding, specific client version, or protocol service failure.
2. If `auth:auth_v2_legacy_fallback_ratio_15m` exceeds go/no-go limits, move the affected cohort back to v1.
3. Audit every fallback reason bucket; unexpected `internal_error` or `unknown` buckets are release blockers.

## Runbook: passkey regression during v2 rollout

1. Use current passkey metrics and audit events already documented in `docs/observability-auth-refresh.md`.
2. If only the v2 namespace is broken, route passkey traffic back to existing `/v1/auth/passkey/*` handlers.
3. Do not disable passkeys globally unless the regression affects the shared WebAuthn core itself.

## Rollback and fallback policy

### Fast rollback

- Turn off `AUTH_V2_PASSWORD_PAKE_ENABLED`.
- Keep `AUTH_V2_METHODS_ENABLED` only if it can safely recommend the remaining valid path.
- Set `AUTH_V2_LEGACY_FALLBACK_MODE=allowlisted` or `broad` only as a time-bounded emergency measure.
- If janitor backlog is growing, also turn off `AUTH_V2_AUTH_FLOWS_ENABLED` and confirm `auth_v2_auth_flow_janitor_enabled` drops to `0` after rollout.
- Re-run the smoke and observability checks from `docs/deployment-production-checklist.md` before calling the rollback complete.

### What rollback does not mean

- It does not mean deleting new tables.
- It does not mean pretending the incident did not happen.
- It does not mean leaving broad fallback on for weeks because nobody wants to debug the real problem.

## Go / no-go criteria

## Go from shadow to internal canary

- schema migrations applied cleanly in staging and prod
- flow janitor metrics and readiness checks implemented
- basic dashboards exist
- problem contracts frozen for pilot clients
- support team briefed on fallback and upgrade behavior

## Go from internal canary to external beta

- 7 days stable internal traffic
- success rate within 1 percentage point of v1 baseline
- fallback ratio < 5%
- no unresolved high-severity audit or logging leak issues

## Go to broad rollout

- 14 days stable beta traffic
- p95 `start + finish` latency within agreed budget
- fallback ratio < 2%
- passkey regressions understood and controlled
- on-call runbooks rehearsed

## No-go conditions

- unexplained enumeration signal between methods/start/finish
- missing or noisy fallback audit data
- janitor/backlog instability in auth flow storage
- protocol library unresolved security concerns
- client inability to recover from expired flows cleanly

## v1 sunset criteria

- >= 90% of target password logins use v2 for at least 30 days
- >= 95% of active password-enabled accounts have `opaque_credentials`
- fallback ratio < 1% for 30 days and limited to named legacy clients
- password reset and password change create or refresh OPAQUE credentials by default
- help center, support, and incident docs updated
- rollback kill-switch exists but is approved for only a short post-sunset window

## Production-ready dependencies

These are mandatory before claiming real readiness:

- chosen PAKE library reviewed for maintenance, interoperability, fake-record support, and failure semantics
- DB migration tested against production-like row counts
- auth flow janitor implemented with readiness and alerts
- dashboards and alerts shipped, not just listed in a doc
- client compatibility matrix documented by platform/browser/app version
- recovery path aligned: password reset/change must not keep minting legacy-only accounts
- support playbooks for expired flows, passkey opt-in, and legacy fallback
- security sign-off on threat model and logging redaction
- game day covering PAKE outage and broad rollback

## Recommended implementation order

1. Schema + ports
2. Observability + audit vocabulary
3. Feature flag framework for v2
4. PAKE dark-path integration
5. Authenticated upgrade path
6. Pilot rollout
7. Broad rollout and v1 sunset prep

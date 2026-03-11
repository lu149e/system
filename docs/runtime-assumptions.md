# Runtime Assumptions & Requirements

## Infrastructure

### Required Services
- **PostgreSQL** 16+ - Primary data store
- **Redis** 7+ - Session/cache, rate limiting

### TLS Requirements
- Database: `sslmode=require` (or verify-full/verify-ca)
- Redis: `rediss://` or `?tls=true`
- Application does NOT handle TLS - terminate at load balancer

### Network
- Expects to be behind reverse proxy/load balancer
- `X-Forwarded-For` header support when `TRUST_X_FORWARDED_FOR=true`
- Requires `TRUSTED_PROXY_IPS` or `TRUSTED_PROXY_CIDRS` if using proxy

## Secrets

### Required Secrets
| Secret | Format | Generation |
|--------|--------|------------|
| `REFRESH_TOKEN_PEPPER` | String (32+ chars) | `openssl rand -base64 32` |
| `MFA_ENCRYPTION_KEY_BASE64` | Base64 (32 bytes decoded) | `openssl rand -base64 32` |
| `JWT_PRIVATE_KEY_PEM` | Ed25519 private key | `openssl genpkey -algorithm ED25519` |

### Secret Sources
1. Environment variables
2. Files (use `*_FILE` suffix): `JWT_PRIVATE_KEY_PEM_FILE`, `SENDGRID_API_KEY_FILE`
3. Kubernetes Secrets (mounted volumes)

## File System

### Migrations
- Location: `./migrations` relative to working directory
- In Kubernetes: mount via PVC or init container
- Runs automatically on startup if configured

### JWT Keys
- File paths in `JWT_KEYSET`: relative to working directory
- Keys read at startup, cached in memory
- For rotation: use `JWT_KEYSET` with multiple keys + `JWT_PRIMARY_KID`

## Runtime Behavior

### Health Endpoints
- `/healthz` - Basic liveness (process is up)
- `/readyz` - Readiness (inmemory: immediate ok; postgres_redis: validates DB ping and Redis ping when adapter is present, plus auth-owned janitor posture)

### Metrics
- Endpoint: `/metrics`
- Format: Prometheus text
- Protection: Optional bearer token via `METRICS_BEARER_TOKEN`

### Graceful Shutdown
- Catches `SIGTERM` and `SIGINT`, flips runtime state to `draining`, and withdraws readiness before exit
- Stops accepting new connections while allowing in-flight requests to finish within `AUTH_SHUTDOWN_GRACE_PERIOD_SECONDS`
- Broadcasts shutdown to auth-owned background loops (outbox dispatcher, passkey janitor, auth-flow janitor) so idle workers do not wait for a full poll interval
- Requires Kubernetes `terminationGracePeriodSeconds` to exceed the app shutdown budget; the production baseline now uses `AUTH_SHUTDOWN_GRACE_PERIOD_SECONDS=25` with `terminationGracePeriodSeconds=40`

## Email

### Providers
- `noop` - Development, logs emails
- `sendgrid` - Production email delivery

### Outbox Pattern
When `EMAIL_DELIVERY_MODE=outbox`:
- Emails written to `email_outbox` table
- Background worker polls and delivers
- Supports retries with exponential backoff
- Dead letter handling via `email_outbox_dead_letter`

## Rate Limiting

### Login Abuse Protection
- Redis-based sliding window counter
- Fail-closed by default (`LOGIN_ABUSE_REDIS_FAIL_MODE=fail_closed`)
- Configurable per-IP and email+IP modes

### Configuration
- `LOGIN_MAX_ATTEMPTS`: 5 (default)
- `LOGIN_LOCKOUT_SECONDS`: 900 (15 min)
- `LOGIN_LOCKOUT_MAX_SECONDS`: 7200 (2 hours, escalating)

## Observability

### Logging
- JSON structured logging via `tracing`
- Output: stdout
- Integrates with cloud logging (CloudWatch, GCP, Azure)

### Metrics
- Request duration histograms
- Login attempt counters
- Token issuance counters
- Email delivery metrics
- Runtime drain and shutdown metrics: `auth_runtime_draining`, `auth_runtime_shutdowns_total{reason}`
- Redis incident posture metric: `auth_login_abuse_redis_incidents_total{operation,posture}`
- Auth-flow backlog recovery metrics: `auth_v2_auth_flows_expired_pending_total`, `auth_v2_auth_flows_oldest_expired_pending_age_seconds`, `auth_v2_auth_flow_prune_runs_total`, `auth_v2_auth_flow_pruned_total`

### Readiness Failure Semantics
- `components.app=status=draining` means the pod is intentionally leaving rotation and should not receive new traffic
- `components.database` and `components.redis` report dependency posture explicitly and fail readiness closed for auth-v2-critical incidents
- `components.auth_flow_janitor=status=degraded` means the shared auth-flow cleanup contract is no longer trustworthy; treat that as rollout-blocking until recovery is verified

### Drill Contract
- Use `scripts/test-auth-v2-dr-chaos.sh` to validate captured `/readyz` and `/metrics` evidence for drain withdrawal, dependency brownout signaling, and backlog recovery
- When auth-v2 recovery overlaps JWT key rollback, include the drill script's `--jwt-rollback-restore-jwks`, `--jwt-rollback-restore-check`, `--jwt-rollback-retire-jwks`, and `--jwt-rollback-retire-check` artifacts so rollback proof is executable instead of operator folklore
- Use `scripts/validate-deploy-readiness.sh` to enforce that rollout assets still match the shutdown budget and drain contract before promotion

### Tracing
- OpenTelemetry not currently integrated
- Request IDs propagated via `X-Request-ID` header

## Security Considerations

### User Session Storage
- Refresh tokens stored in Redis with TTL
- Access tokens: stateless JWT

### Password Storage
- Argon2id hashing
- Configurable memory/iterations in code

### MFA
- TOTP (Google Authenticator compatible)
- Secrets encrypted with `MFA_ENCRYPTION_KEY_BASE64`

## Dependencies

### Rust Runtime
- Single-threaded by default (`tokio` multi-threaded)
- No dynamic loading of plugins

### File Descriptors
- Ensure ulimit >= 4096 for production
- Connections: DB pool + Redis + OS handles

# Deployment Production Checklist

## Prereqs

- Kubernetes cluster with an ingress controller and cert manager (or pre-provisioned TLS secret).
- PostgreSQL 16+ reachable from the cluster with TLS enabled.
- Redis 7+ reachable from the cluster with TLS enabled.
- Container image published for app (`ghcr.io/lu149e/system:<tag>`); migration job reuses the same image with run mode `migrate`.
- Access to create/update namespace-scoped resources in `auth` namespace.
- Manifest preflight completed with `scripts/validate-k8s-manifests.sh` and `scripts/validate-deploy-readiness.sh`.
- Production overlay inputs finalized (ingress host/TLS, external DB/Redis CIDRs, digest-pinned image) and generated into `artifacts/production-overlay/generated/`.
- GitHub Actions secret `KUBE_CONFIG_B64` configured with base64-encoded kubeconfig for the target cluster/namespace.
- For manual production workflows, configure secret inputs as repository/environ secrets:
  - required: `PROD_AUTH_DATABASE_URL`, `PROD_AUTH_REDIS_URL`, `PROD_AUTH_REFRESH_TOKEN_PEPPER`, `PROD_AUTH_MFA_ENCRYPTION_KEY_BASE64`, `PROD_AUTH_JWT_KEYSET`, `PROD_AUTH_JWT_PRIMARY_KID`
  - optional: `PROD_AUTH_METRICS_BEARER_TOKEN`, `PROD_AUTH_SENDGRID_API_KEY`, `PROD_AUTH_SENDGRID_FROM_EMAIL`, `PROD_AUTH_VERIFY_EMAIL_URL_BASE`, `PROD_AUTH_PASSWORD_RESET_URL_BASE`

## Required Environment Variables and Secrets

Use `deploy/k8s/configmap.yaml` for non-secret runtime config.

Do not apply `deploy/k8s/secret.template.yaml`; it is reference-only. Generate a concrete manifest with `scripts/generate-k8s-secret-manifest.sh`.

Required secret environment variables for `scripts/generate-k8s-secret-manifest.sh`:

- `DATABASE_URL`
- `REDIS_URL`
- `REFRESH_TOKEN_PEPPER`
- `MFA_ENCRYPTION_KEY_BASE64`
- `JWT_KEYSET` and `JWT_PRIMARY_KID` (or legacy single-key variables)

Optional variables (included only when set):

- `METRICS_BEARER_TOKEN`
- `SENDGRID_API_KEY`
- `SENDGRID_FROM_EMAIL`
- `VERIFY_EMAIL_URL_BASE`
- `PASSWORD_RESET_URL_BASE`

Quick generation helpers:

```bash
# Refresh token pepper (32+ random bytes, base64)
openssl rand -base64 32

# MFA encryption key (32 bytes, base64)
openssl rand -base64 32

# Ed25519 keypair example
openssl genpkey -algorithm ED25519 -out /tmp/private.pem
openssl pkey -in /tmp/private.pem -pubout -out /tmp/public.pem
```

Strongly recommended secrets:

- `METRICS_BEARER_TOKEN`
- `SENDGRID_API_KEY` when `EMAIL_PROVIDER=sendgrid`

## Migration Procedure

1. Set one release tag and apply it to both `deployment.yaml` and `migration-job.yaml`.
   - Baseline default is `ghcr.io/lu149e/system:main` for non-placeholder deployability.
   - For real releases, prefer immutable tags (`ghcr.io/lu149e/system:<git-sha>`) or digest pinning (`ghcr.io/lu149e/system@sha256:<digest>`).
2. Run migration job before app rollout:

```bash
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/configmap.yaml
# Generate and apply a concrete production secret manifest
DATABASE_URL='postgres://auth_user:...' \
REDIS_URL='rediss://:...' \
REFRESH_TOKEN_PEPPER='...' \
MFA_ENCRYPTION_KEY_BASE64='...' \
JWT_KEYSET='auth-ed25519-v2|/var/run/secrets/auth/jwt/v2-private.pem|/var/run/secrets/auth/jwt/v2-public.pem' \
JWT_PRIMARY_KID='auth-ed25519-v2' \
./scripts/generate-k8s-secret-manifest.sh
kubectl apply -f artifacts/production-secrets/auth-api-secrets.yaml
kubectl apply -f deploy/k8s/migration-job.yaml
kubectl wait --for=condition=complete job/auth-api-migrate -n auth --timeout=10m
```

3. Verify job logs and confirm no SQL errors:

```bash
kubectl logs job/auth-api-migrate -n auth
```

Migration run-mode contract:

- The job executes `/app/auth migrate`.
- Equivalent invocation for ad-hoc runs: `AUTH_RUN_MODE=migrate /app/auth`.
- `AUTH_RUNTIME=postgres_redis` applies migrations and exits `0` on success.
- `AUTH_RUNTIME=inmemory` exits non-zero with a clear "migrations not applicable" error.

4. Apply/refresh using environment overlays instead of baseline-only apply:

```bash
# Staging (tag-based image allowed)
kubectl apply -k deploy/k8s/overlays/staging

# Production (digest pin + explicit environment inputs required)
kubectl apply -k artifacts/production-overlay/generated
```

## Promotion Flow (Staging -> Production)

1. Publish release image and capture digest:

```bash
# GitHub Actions -> release-image
# Use digest from workflow summary/artifact (artifacts/image-release/reference.txt)
```

2. Generate production overlay from templates:

```bash
IMAGE_DIGEST='sha256:<64-hex>' \
INGRESS_HOST='auth.example.com' \
TLS_SECRET_NAME='auth-api-tls' \
POSTGRES_CIDR='10.20.30.0/24' \
REDIS_CIDR='10.20.40.0/24' \
./scripts/generate-production-overlay.sh
```

   - Templates are versioned in `deploy/k8s/overlays/production/templates/`.
   - Generated, environment-resolved manifests are written to `artifacts/production-overlay/generated/`.
   - The generator fails fast on missing/invalid inputs.

3. Run deploy readiness gate locally or in GitHub Actions:

```bash
# local non-strict
./scripts/validate-deploy-readiness.sh

# local strict (governed)
STRICT_DEPLOY_VALIDATION=true ./scripts/validate-deploy-readiness.sh
```

4. Prefer manual governance workflow to generate a promotion-ready artifact (no cluster apply):

```bash
# GitHub Actions -> production-promotion-manual
# Required inputs:
# - image_digest (sha256:...)
# - ingress_host
# - tls_secret_name
# - postgres_cidr
# - redis_cidr
```

   - Signature gate: verifies `ghcr.io/lu149e/system@<digest>` with Cosign keyless against GitHub OIDC issuer and release workflow identity.
   - Readiness gate: runs `scripts/generate-production-overlay.sh` and strict `scripts/validate-deploy-readiness.sh`.
   - Manifest gate: renders `kustomize build` output and runs `kubeconform -strict`.
    - Always uploads:
      - `production-manifest-<run_id>` (`artifacts/production-promotion/production-manifests.yaml`)
      - `production-promotion-evidence-<run_id>` (promotion logs + deploy readiness logs + generated overlay)

5. Generate concrete secret manifest for production deployment:

```bash
DATABASE_URL='postgres://auth_user:...' \
REDIS_URL='rediss://:...' \
REFRESH_TOKEN_PEPPER='...' \
MFA_ENCRYPTION_KEY_BASE64='...' \
JWT_KEYSET='auth-ed25519-v2|/var/run/secrets/auth/jwt/v2-private.pem|/var/run/secrets/auth/jwt/v2-public.pem' \
JWT_PRIMARY_KID='auth-ed25519-v2' \
./scripts/generate-k8s-secret-manifest.sh
```

6. Execute controlled deployment workflow (dry-run by default, apply only when explicit):

```bash
# GitHub Actions -> production-deploy-manual
# Required inputs:
# - image_digest (sha256:...)
# - ingress_host
# - tls_secret_name
# - postgres_cidr
# - redis_cidr
# Optional inputs:
# - apply_changes=false (default; non-destructive dry-run mode)
# - allow_client_dry_run_fallback=false (default; only for simulation when API server is unreachable)
# - namespace=auth
```

   - Always performs: signature verify, overlay generation, strict deploy readiness, render + `kubeconform -strict`, kube auth setup, and `kubectl apply --dry-run=server`.
   - Optional simulation fallback (only with `apply_changes=false`): if `allow_client_dry_run_fallback=true` and server dry-run fails due cluster connectivity, workflow marks fallback in summary/artifacts and skips kubectl server validation.
   - Apply gate: only mutates cluster when `apply_changes=true`.
   - Safety guard: fails fast if `apply_changes=true` and `KUBE_CONFIG_B64` is missing.
   - Post-apply smoke checks (only in apply mode): rollout status, endpoint readiness, `/healthz` and `/readyz` via service port-forward.
   - Always uploads execution evidence: `production-deploy-manual-<run_id>`.

7. If you are not using the controlled workflow, apply generated production overlay only after validation passes:

```bash
kubectl apply -f artifacts/production-secrets/auth-api-secrets.yaml
kubectl apply -k artifacts/production-overlay/generated
```

## Network Policy and Scheduling Hardening

`deploy/k8s/networkpolicy.yaml` and `deploy/k8s/poddisruptionbudget.yaml` provide a conservative baseline.

- Set ingress controller namespace label selector:
  - default assumes `kubernetes.io/metadata.name=ingress-nginx`
  - if your controller namespace is different, update `deploy/k8s/networkpolicy.yaml`
- Baseline egress allows PostgreSQL/Redis via pod+namespace selectors:
  - PostgreSQL: namespace `auth` + label `app.kubernetes.io/name=postgres` on port `5432`
  - Redis: namespace `auth` + label `app.kubernetes.io/name=redis` on port `6379`
  - If your services run in another namespace, change only the `namespaceSelector` value.
- External DB/Redis override templates for production are versioned in:
  - `deploy/k8s/overlays/production/templates/networkpolicy-production-egress.patch.yaml`
  - Keep DNS rule and least-privilege ports (`5432`, `6379`) unchanged.
  - Provide CIDR values to the generator and apply via `kubectl apply -k artifacts/production-overlay/generated`.
- Verify DNS selector compatibility:
  - baseline targets pods labeled `k8s-app=kube-dns` in `kube-system`
  - adjust selector if your cluster uses different CoreDNS labels
- Keep workload spread controls in `deploy/k8s/deployment.yaml`:
  - `podAntiAffinity` is preferred (non-blocking)
  - `topologySpreadConstraints` use `ScheduleAnyway` for hostname/zone balance without blocking scheduling under pressure

Validation commands (run after applying manifests):

```bash
# Confirm resources are present
kubectl get networkpolicy,pdb -n auth

# Confirm auth-api pods match PDB selector and spread as expected
kubectl get pods -n auth -l app.kubernetes.io/name=auth-api -o wide
kubectl describe pdb auth-api -n auth

# Validate network policy intent from control plane perspective
kubectl describe networkpolicy auth-api-default-deny-with-explicit-allows -n auth

# Functional egress checks from an auth-api pod (examples)
kubectl exec -it auth-api-pod-xxx -n auth -- nslookup kubernetes.default.svc.cluster.local
kubectl exec -it auth-api-pod-xxx -n auth -- sh -c 'nc -vz <postgres-ip> 5432'
kubectl exec -it auth-api-pod-xxx -n auth -- sh -c 'nc -vz <redis-ip> 6379'
```

## Manifest Governance Gate

- Local preflight (non-strict): `./scripts/validate-k8s-manifests.sh`
- Local preflight (strict; fails if optional tools are missing): `STRICT_K8S_VALIDATION=true ./scripts/validate-k8s-manifests.sh`
- Manual GitHub gate with artifacts/logs: `Actions -> k8s-manifest-validation-manual -> Run workflow`
- Workflow artifact path: `artifacts/k8s-manifest-validation/` (placeholder report, YAML/kustomize/kubeconform logs)
- Generate production overlay: `IMAGE_DIGEST=... INGRESS_HOST=... TLS_SECRET_NAME=... POSTGRES_CIDR=... REDIS_CIDR=... ./scripts/generate-production-overlay.sh`
- Deploy readiness gate (generated production overlay + digest policy): `./scripts/validate-deploy-readiness.sh`
- Deploy readiness strict mode: `STRICT_DEPLOY_VALIDATION=true ./scripts/validate-deploy-readiness.sh`
- Manual GitHub gate with artifacts/logs: `Actions -> deploy-readiness-validation-manual -> Run workflow`
- Workflow artifact path: `artifacts/deploy-readiness/` (placeholder report, render log, digest policy report)
- Production promotion workflow (no apply): `Actions -> production-promotion-manual -> Run workflow`
- Promotion artifacts: `production-manifest-<run_id>` and `production-promotion-evidence-<run_id>`

## Smoke Checks Post Deploy

After applying `deployment.yaml`, `service.yaml`, and `ingress.yaml`:

- Confirm deployment rollout is healthy:
  - `kubectl rollout status deployment/auth-api -n auth --timeout=5m`
- Confirm endpoints are ready:
  - `kubectl get endpoints auth-api -n auth`
- Validate liveness/readiness probes from inside a pod:
  - `kubectl exec -it auth-api-pod-xxx -n auth -- wget -qO- http://localhost:8080/healthz`
  - `kubectl exec -it auth-api-pod-xxx -n auth -- wget -qO- http://localhost:8080/readyz`
- Baseline ingress is hostless for safe defaults; validate with explicit Host header when you define one:
  - `curl -fsS -H 'Host: auth.your-domain.tld' https://<ingress-address>/.well-known/jwks.json`
- Validate metrics protection works:
  - without token expect `401` when token is configured
  - with token expect `200` and Prometheus payload

## Rollback Strategy

- Roll back workload first:
  - `kubectl rollout undo deployment/auth-api -n auth`
- If release included DB changes, use forward-fix migrations rather than destructive down migrations.
- Re-run smoke checks after rollback and verify auth/login/refresh baseline behavior.

## Runtime Assumptions

- TLS is terminated at ingress/load balancer; the app serves HTTP inside the cluster.
- Health endpoints are `GET /healthz` (liveness/startup) and `GET /readyz` (readiness).
- Metrics endpoint is `GET /metrics` and should be protected with `METRICS_BEARER_TOKEN` and/or network policy.
- App is expected to run behind trusted proxies only when `TRUST_X_FORWARDED_FOR=true` and trusted proxy ranges are configured.

## Observability Checks and Alerts

Verify the following during rollout and for at least one full traffic cycle:

- `auth_problem_responses_total` does not spike unexpectedly.
- `auth_refresh_rejected_total{reason="token_rotation_error"}` remains at baseline.
- `auth_email_outbox_queue_depth` and `auth_email_outbox_oldest_due_age_seconds` remain within expected thresholds.
- Pod restart count is stable (`kubectl get pods -n auth`).
- Ingress 5xx and upstream latency stay within SLO budgets.

Baseline alert and dashboard artifacts remain in:

- `docs/alerts/auth-refresh-alert-rules.yaml`
- `docs/grafana/auth-refresh-runtime-prometheus.json`
- `docs/observability-auth-refresh.md`

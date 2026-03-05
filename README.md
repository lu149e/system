# Auth API - Batch 5

Base tecnica para API de autenticacion en Rust con Axum/Tokio, arquitectura hexagonal por dominio, persistencia PostgreSQL (SQLx) y control anti-abuso distribuido en Redis.

## Arquitectura

- `src/modules/auth`: register, verify-email, login (+ MFA challenge), MFA enroll/activate/verify/disable, password forgot/reset/change, refresh, logout, logout-all, sessions, me (capa de aplicacion y puertos).
- `src/modules/auth/ports`: puerto de proteccion anti-abuso para login (adapter Redis en runtime seguro).
- `src/modules/sessions`: modelo de sesion y reglas de revocacion/compromiso.
- `src/modules/tokens`: JWT access token, refresh token opaco, rotacion y reuse detection.
- `src/modules/audit`: evento de auditoria obligatorio con `trace_id`.
- `src/adapters/postgres.rs`: adapters SQLx para `users/credentials`, MFA (`mfa_factors/challenges/backup_codes`), `sessions`, `refresh_tokens`, `audit_events`.
- `src/adapters/outbox.rs`: adapter persistente de outbox de email (enqueue/fetch-due/mark-sent/mark-failed) y worker dispatcher.
- `src/adapters/redis.rs`: adapter Redis para lockout y ventana de intentos por email/IP.
- `src/adapters/inmemory.rs`: fallback de desarrollo, deshabilitado por defecto.
- `src/api`: handlers HTTP `/v1` y modelo de error `application/problem+json`.
- `migrations/0001_init_auth_core.sql`: esquema base de auth core.
- `migrations/0002_add_credentials.sql`: tabla `credentials` para hash de password.
- `migrations/0003_guard_credentials_coverage.sql`: valida cobertura de `credentials` para todos los usuarios.
- `migrations/0004_add_verification_tokens.sql`: tabla de tokens one-time para verificacion de email.
- `migrations/0005_add_password_reset_tokens.sql`: tabla de tokens one-time para reset de password.
- `migrations/0006_add_mfa_tables.sql`: tablas `mfa_factors`, `mfa_challenges` y `mfa_backup_codes`.
- `migrations/0007_add_mfa_challenge_failed_attempts.sql`: agrega contador de intentos fallidos por challenge MFA.
- `migrations/0009_add_email_outbox.sql`: tabla persistente `email_outbox` para desacoplar envio transaccional del request path.
- `migrations/0010_add_outbox_processing_lease.sql`: lease de procesamiento para workers outbox multi-instancia.
- `migrations/0011_add_outbox_replay_audit.sql`: auditoria append-only para replay manual de dead-letter (`requeue`).
- `migrations/0012_add_outbox_replay_change_ticket.sql`: agrega `change_ticket` para trazabilidad de caso/ticket en replay auditado.
- `migrations/0013_harden_outbox_replay_apply_audit_constraints.sql`: agrega constraints DB para exigir actor/ticket validos en filas `is_apply=true`.
- `migrations/0014_enforce_outbox_replay_audit_append_only.sql`: aplica guardas DB (triggers) para bloquear `UPDATE/DELETE` y mantener `outbox_replay_audit` append-only.
- `migrations/0015_allow_outbox_replay_audit_controlled_maintenance_override.sql`: mantiene default append-only y habilita override break-glass por sesion solo para mantenimiento controlado.

## Endpoints v1 implementados

- `POST /v1/auth/register`
- `POST /v1/auth/verify-email`
- `POST /v1/auth/login`
- `POST /v1/auth/mfa/enroll`
- `POST /v1/auth/mfa/activate`
- `POST /v1/auth/mfa/verify`
- `POST /v1/auth/mfa/disable`
- `POST /v1/auth/password/forgot`
- `POST /v1/auth/password/reset`
- `POST /v1/auth/password/change`
- `POST /v1/auth/token/refresh`
- `POST /v1/auth/logout`
- `POST /v1/auth/logout-all`
- `GET /v1/auth/sessions`
- `DELETE /v1/auth/sessions/{session_id}`
- `GET /v1/auth/me`
- `GET /.well-known/jwks.json` (publicacion de clave publica para validacion JWT)
- `GET /metrics` (operativo, formato Prometheus)
- `GET /healthz` (liveness)
- `GET /readyz` (readiness; valida dependencias segun runtime)

Notas de contrato:

- `POST /v1/auth/login` devuelve tokens cuando MFA no aplica, o `mfa_required=true` con `challenge_id` cuando MFA esta habilitado.

## Variables de entorno

- `APP_ADDR` (opcional, default `0.0.0.0:8080`)
- `AUTH_RUN_MODE` (opcional, default `server`; valores: `server`, `migrate`)
- `AUTH_RUNTIME` (opcional, default `postgres_redis`; valores: `postgres_redis`, `inmemory`)
- `ALLOW_INSECURE_INMEMORY` (opcional, default `false`; requerido en `true` para habilitar runtime in-memory)
- `METRICS_BEARER_TOKEN` (opcional; si se define, `GET /metrics` exige `Authorization: Bearer <token>`)
- `METRICS_BEARER_TOKEN_FILE` (opcional; ruta de archivo con bearer token para `GET /metrics`; no puede coexistir con `METRICS_BEARER_TOKEN`)
- `METRICS_ALLOWED_CIDRS` (opcional; lista CSV de CIDRs permitidos para `GET /metrics`, ejemplo: `10.10.0.0/16,127.0.0.0/8`)
- `TRUST_X_FORWARDED_FOR` (opcional, default `false`; habilitar solo detras de proxy confiable)
- `TRUSTED_PROXY_IPS` (opcional; lista separada por comas de IPs exactas confiables)
- `TRUSTED_PROXY_CIDRS` (opcional; lista separada por comas de CIDR confiables)
- `DATABASE_URL` (requerido cuando `AUTH_RUNTIME=postgres_redis`)
- `DATABASE_MAX_CONNECTIONS` (opcional, default `10`)
- `REDIS_URL` (requerido cuando `AUTH_RUNTIME=postgres_redis`)
- `ENFORCE_DATABASE_TLS` (opcional, default `false`; si `true`, exige `sslmode=require|verify-ca|verify-full` o `ssl=true` en `DATABASE_URL`)
- `ENFORCE_REDIS_TLS` (opcional, default `false`; si `true`, exige `REDIS_URL` con `rediss://` o query `tls=true`)
- `JWT_KEYSET` (opcional; habilita multi-key rotation. Formato CSV `kid|private_key_path|public_key_path`. Para claves solo-validacion deja `private_key_path` vacio: `kid||public_key_path`)
- `JWT_PRIMARY_KID` (opcional con `JWT_KEYSET`; si no se define se toma la primera clave del keyset)
- `JWT_PRIVATE_KEY_PEM` (legacy; requerido si `JWT_KEYSET` no esta definido)
- `JWT_PUBLIC_KEY_PEM` (legacy; requerido si `JWT_KEYSET` no esta definido)
- `JWT_KEY_ID` (legacy opcional, default `auth-ed25519-v1`; solo aplica sin `JWT_KEYSET`)
- `JWT_ISSUER` (opcional, default `auth-api`)
- `JWT_AUDIENCE` (opcional, default `auth-clients`)
- `REFRESH_TOKEN_PEPPER` (requerido)
- `ACCESS_TTL_SECONDS` (opcional, default `900`)
- `REFRESH_TTL_SECONDS` (opcional, default `1209600`)
- `EMAIL_VERIFICATION_TTL_SECONDS` (opcional, default `86400`)
- `PASSWORD_RESET_TTL_SECONDS` (opcional, default `900`)
- `EMAIL_PROVIDER` (opcional, default `noop`; valores: `noop`, `sendgrid`)
- `EMAIL_DELIVERY_MODE` (opcional, default `inline`; valores: `inline`, `outbox`)
- `EMAIL_OUTBOX_POLL_INTERVAL_MS` (opcional, default `1000`; intervalo de polling del dispatcher en modo outbox)
- `EMAIL_OUTBOX_BATCH_SIZE` (opcional, default `25`; cantidad maxima de mensajes por lote)
- `EMAIL_OUTBOX_MAX_ATTEMPTS` (opcional, default `8`; intentos maximos por mensaje, incluyendo el primer envio)
- `EMAIL_OUTBOX_LEASE_MS` (opcional, default `30000`; duracion del lease de procesamiento por worker, debe ser `>= EMAIL_OUTBOX_POLL_INTERVAL_MS`)
- `EMAIL_OUTBOX_BACKOFF_BASE_MS` (opcional, default `1000`; backoff exponencial base entre reintentos)
- `EMAIL_OUTBOX_BACKOFF_MAX_MS` (opcional, default `60000`; tope de backoff entre reintentos)
- `SENDGRID_API_KEY` (requerido cuando `EMAIL_PROVIDER=sendgrid`; no combinar con `SENDGRID_API_KEY_FILE`)
- `SENDGRID_API_KEY_FILE` (opcional; ruta de archivo con API key de SendGrid, recomendado en produccion)
- `SENDGRID_API_BASE_URL` (opcional, default `https://api.sendgrid.com`)
- `SENDGRID_FROM_EMAIL` (requerido cuando `EMAIL_PROVIDER=sendgrid`)
- `SENDGRID_FROM_NAME` (opcional; nombre visible del remitente en SendGrid)
- `VERIFY_EMAIL_URL_BASE` (requerido cuando `EMAIL_PROVIDER=sendgrid`; URL base para construir link de verificacion con query `token`)
- `PASSWORD_RESET_URL_BASE` (requerido cuando `EMAIL_PROVIDER=sendgrid`; URL base para construir link de reset con query `token`)
- `SENDGRID_TIMEOUT_MS` (opcional, default `3000`; timeout HTTP por intento de envio a SendGrid)
- `SENDGRID_MAX_RETRIES` (opcional, default `2`; reintentos adicionales para fallos transitorios: error de transporte, `429`, `5xx`)
- `SENDGRID_RETRY_BASE_DELAY_MS` (opcional, default `200`; backoff exponencial base entre reintentos)
- `SENDGRID_RETRY_MAX_DELAY_MS` (opcional, default `2000`; tope de backoff exponencial entre reintentos)
- `SENDGRID_RETRY_JITTER_PERCENT` (opcional, default `20`; jitter uniforme aplicado al backoff por intento, rango `0..100`)
- `EMAIL_METRICS_LATENCY_ENABLED` (opcional, default `false`; si `true`, habilita histograma de latencia para entrega de email)
- `MFA_CHALLENGE_TTL_SECONDS` (opcional, default `300`)
- `MFA_CHALLENGE_MAX_ATTEMPTS` (opcional, default `3`)
- `MFA_TOTP_ISSUER` (opcional, default `auth-api`)
- `MFA_ENCRYPTION_KEY_BASE64` (requerido; clave AES-256 en base64, 32 bytes decodificados)
  - Ejemplo de generacion: `openssl rand -base64 32`
- `BOOTSTRAP_USER_EMAIL` (opcional; debe venir junto con `BOOTSTRAP_USER_PASSWORD`)
- `BOOTSTRAP_USER_PASSWORD` (opcional; debe venir junto con `BOOTSTRAP_USER_EMAIL`)
- `LOGIN_MAX_ATTEMPTS` (opcional, default `5`)
- `LOGIN_ATTEMPT_WINDOW_SECONDS` (opcional, default `300`)
- `LOGIN_LOCKOUT_SECONDS` (opcional, default `900`)
- `LOGIN_LOCKOUT_MAX_SECONDS` (opcional, default `7200`; tope de backoff progresivo)
- `LOGIN_ABUSE_ATTEMPTS_PREFIX` (opcional, default `auth:login-abuse:attempts`)
- `LOGIN_ABUSE_LOCK_PREFIX` (opcional, default `auth:login-abuse:lock`)
- `LOGIN_ABUSE_STRIKES_PREFIX` (opcional, default `auth:login-abuse:strikes`)
- `LOGIN_ABUSE_REDIS_FAIL_MODE` (opcional, default `fail_closed`; valores: `fail_closed`, `fail_open`)
- `LOGIN_ABUSE_BUCKET_MODE` (opcional, default `email_and_ip`; valores: `ip_only`, `email_and_ip`)
- `AUTH_TEST_DATABASE_URL` (opcional; URL de PostgreSQL para ejecutar pruebas de integracion del adapter Postgres)

## Ejemplo de entorno (seguro por defecto)

```bash
APP_ADDR=0.0.0.0:8080
AUTH_RUNTIME=postgres_redis
# Recomendado en produccion: usar METRICS_BEARER_TOKEN_FILE via secret mount
METRICS_BEARER_TOKEN=replace_with_long_random_token
# METRICS_BEARER_TOKEN_FILE=/var/run/secrets/auth/metrics_token
METRICS_ALLOWED_CIDRS=10.10.0.0/16
TRUST_X_FORWARDED_FOR=false
TRUSTED_PROXY_IPS=10.0.0.10,10.0.0.11
TRUSTED_PROXY_CIDRS=10.0.1.0/24
DATABASE_URL=postgres://auth_user:change_me@localhost:5432/auth
DATABASE_MAX_CONNECTIONS=10
REDIS_URL=redis://127.0.0.1:6379
ENFORCE_DATABASE_TLS=false
ENFORCE_REDIS_TLS=false
JWT_PRIVATE_KEY_PEM="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
JWT_PUBLIC_KEY_PEM="-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
JWT_KEY_ID=auth-ed25519-v1
# Alternativa para rotacion multi-key con archivos PEM (no combinar con JWT_*_PEM legacy):
# JWT_KEYSET="auth-ed25519-v2|/run/secrets/jwt/v2-private.pem|/run/secrets/jwt/v2-public.pem,auth-ed25519-v1||/run/secrets/jwt/v1-public.pem"
# JWT_PRIMARY_KID=auth-ed25519-v2
JWT_ISSUER=auth-api
JWT_AUDIENCE=auth-clients
REFRESH_TOKEN_PEPPER=replace_with_long_random_secret
ACCESS_TTL_SECONDS=900
REFRESH_TTL_SECONDS=1209600
EMAIL_VERIFICATION_TTL_SECONDS=86400
PASSWORD_RESET_TTL_SECONDS=900
EMAIL_PROVIDER=noop
EMAIL_DELIVERY_MODE=inline
EMAIL_OUTBOX_POLL_INTERVAL_MS=1000
EMAIL_OUTBOX_BATCH_SIZE=25
EMAIL_OUTBOX_MAX_ATTEMPTS=8
EMAIL_OUTBOX_LEASE_MS=30000
EMAIL_OUTBOX_BACKOFF_BASE_MS=1000
EMAIL_OUTBOX_BACKOFF_MAX_MS=60000
MFA_CHALLENGE_TTL_SECONDS=300
MFA_CHALLENGE_MAX_ATTEMPTS=3
MFA_TOTP_ISSUER=auth-api
MFA_ENCRYPTION_KEY_BASE64=replace_with_base64_32_bytes_key
LOGIN_MAX_ATTEMPTS=5
LOGIN_ATTEMPT_WINDOW_SECONDS=300
LOGIN_LOCKOUT_SECONDS=900
LOGIN_LOCKOUT_MAX_SECONDS=7200
LOGIN_ABUSE_ATTEMPTS_PREFIX=auth:login-abuse:attempts
LOGIN_ABUSE_LOCK_PREFIX=auth:login-abuse:lock
LOGIN_ABUSE_STRIKES_PREFIX=auth:login-abuse:strikes
LOGIN_ABUSE_REDIS_FAIL_MODE=fail_closed
LOGIN_ABUSE_BUCKET_MODE=email_and_ip
```

## Ejemplo de entorno (produccion con transporte endurecido)

```bash
AUTH_RUNTIME=postgres_redis
DATABASE_URL=postgres://auth_user:replace_me@db.internal:5432/auth?sslmode=verify-full
REDIS_URL=rediss://redis.internal:6380
ENFORCE_DATABASE_TLS=true
ENFORCE_REDIS_TLS=true
```

## Ejemplo de email transaccional real (SendGrid)

```bash
EMAIL_PROVIDER=sendgrid
EMAIL_DELIVERY_MODE=outbox
# Recomendado: secret file montado por orquestador (Vault/Kubernetes/Azure Key Vault CSI)
SENDGRID_API_KEY_FILE=/var/run/secrets/auth/sendgrid_api_key
# Alternativa (menos segura): SENDGRID_API_KEY=SG.xxxxx
SENDGRID_API_BASE_URL=https://api.sendgrid.com
SENDGRID_FROM_EMAIL=noreply@auth.example.com
SENDGRID_FROM_NAME=Auth API
VERIFY_EMAIL_URL_BASE=https://app.example.com/verify-email
PASSWORD_RESET_URL_BASE=https://app.example.com/reset-password
SENDGRID_TIMEOUT_MS=3000
SENDGRID_MAX_RETRIES=2
SENDGRID_RETRY_BASE_DELAY_MS=200
SENDGRID_RETRY_MAX_DELAY_MS=2000
SENDGRID_RETRY_JITTER_PERCENT=20
# Opcional para latencia de email en runtime Prometheus
EMAIL_METRICS_LATENCY_ENABLED=false
EMAIL_OUTBOX_POLL_INTERVAL_MS=1000
EMAIL_OUTBOX_BATCH_SIZE=25
EMAIL_OUTBOX_MAX_ATTEMPTS=8
EMAIL_OUTBOX_LEASE_MS=30000
EMAIL_OUTBOX_BACKOFF_BASE_MS=1000
EMAIL_OUTBOX_BACKOFF_MAX_MS=60000
```

## Modo in-memory (solo desarrollo)

- Debe habilitarse de forma explicita con `AUTH_RUNTIME=inmemory` y `ALLOW_INSECURE_INMEMORY=true`.
- No usar en produccion: no ofrece persistencia ni coordinacion distribuida.

### Notas de seguridad

- No hay credenciales por defecto de usuario inicial.
- Si falta cualquiera de `BOOTSTRAP_USER_EMAIL` o `BOOTSTRAP_USER_PASSWORD`, el bootstrap del usuario inicial se deshabilita de forma segura.
- Cuando el bootstrap queda deshabilitado por configuracion incompleta, se emite un warning en logs al arrancar.
- No se registran secretos ni tokens en logs de aplicacion.
- Auditoria de auth mantiene `trace_id` obligatorio en todos los eventos del dominio.
- Si defines `METRICS_BEARER_TOKEN`, el endpoint `/metrics` queda protegido con bearer token.
- Alternativamente, usa `METRICS_BEARER_TOKEN_FILE` para evitar exponer el token en variables de entorno.
- Para email transaccional, prioriza `SENDGRID_API_KEY_FILE` sobre `SENDGRID_API_KEY` para evitar exposicion del secreto en process list y dumps de entorno.
- Si `EMAIL_PROVIDER=sendgrid` y falta cualquier variable requerida (`SENDGRID_API_KEY(_FILE)`, `SENDGRID_FROM_EMAIL`, `VERIFY_EMAIL_URL_BASE`, `PASSWORD_RESET_URL_BASE`), la app falla en startup (fail fast).
- Si `EMAIL_DELIVERY_MODE=outbox`, la app exige `AUTH_RUNTIME=postgres_redis` (persistencia obligatoria para entrega desacoplada).
- En modo `outbox`, register/forgot-password mantienen contrato anti-enumeracion: el request no bloquea por outage del proveedor; la entrega se resuelve async por worker.
- Politica de dispatcher outbox: cada worker reclama lotes de forma atomica (`UPDATE ... FOR UPDATE SKIP LOCKED`) y marca filas en `processing` con lease hasta `EMAIL_OUTBOX_LEASE_MS`.
- Filas en `processing` no se reclaman de nuevo hasta que vence el lease; si un worker queda colgado, esas filas vuelven a ser reclamables al expirar el lease.
- Politica de dispatcher outbox: polling cada `EMAIL_OUTBOX_POLL_INTERVAL_MS`, lote `EMAIL_OUTBOX_BATCH_SIZE`, lease `EMAIL_OUTBOX_LEASE_MS`, reintentos con backoff exponencial acotado entre `EMAIL_OUTBOX_BACKOFF_BASE_MS` y `EMAIL_OUTBOX_BACKOFF_MAX_MS`, hasta `EMAIL_OUTBOX_MAX_ATTEMPTS`.
- Para despliegues multi-instancia, mantener `EMAIL_OUTBOX_LEASE_MS` por encima del tiempo tipico de envio (incluyendo retries del proveedor) para minimizar duplicados por expiracion prematura del lease.
- Politica de retries SendGrid: hasta `1 + SENDGRID_MAX_RETRIES` intentos por email, con backoff exponencial acotado (`min(SENDGRID_RETRY_BASE_DELAY_MS * 2^(n-1), SENDGRID_RETRY_MAX_DELAY_MS)`) y jitter uniforme por intento en el rango `[backoff * (1 - j), min(backoff * (1 + j), SENDGRID_RETRY_MAX_DELAY_MS)]`, donde `j = SENDGRID_RETRY_JITTER_PERCENT / 100`.
- Solo se reintenta en fallos transitorios (`429`, `5xx` y errores de transporte/timeout). Respuestas `4xx` no transitorias fallan sin retry.
- Si defines `METRICS_ALLOWED_CIDRS`, `/metrics` solo responde a clientes dentro de esos rangos (ademas del bearer si aplica).
- El endpoint `/.well-known/jwks.json` publica todas las claves publicas activas configuradas (Ed25519), cada una con `kid` unico.
- Runbook operativo de rotacion JWT (introduccion, switch de primaria, convivencia, retiro y rollback): `docs/jwt-key-rotation-runbook.md`.
- Por defecto no se confia en `x-forwarded-for`; habilitalo solo si el edge/proxy limpia ese header.
- Si `TRUST_X_FORWARDED_FOR=true`, debes definir `TRUSTED_PROXY_IPS` o `TRUSTED_PROXY_CIDRS`; la app solo toma `x-forwarded-for` cuando el socket remoto coincide con un proxy confiable.
- Si `ENFORCE_DATABASE_TLS=true`, el startup falla si `DATABASE_URL` no explicita transporte seguro (`sslmode=require|verify-ca|verify-full` o equivalente `ssl=true`).
- Si `ENFORCE_REDIS_TLS=true`, el startup falla si `REDIS_URL` no usa `rediss://` o `tls=true`.
- El lockout de login soporta `LOGIN_ABUSE_BUCKET_MODE`:
  - `ip_only`: bucket `email|ip`.
  - `email_and_ip`: bucket dual `email|any` + `email|ip`.
- Lockout aplica backoff progresivo por bucket: parte de `LOGIN_LOCKOUT_SECONDS`, duplica por reincidencia y limita en `LOGIN_LOCKOUT_MAX_SECONDS`.
- Registro usa respuesta neutra para reducir enumeracion de cuentas.
- Verify-email usa token one-time hasheado en DB y TTL configurable.
- Reemision de verify-email invalida tokens pendientes previos del mismo usuario.
- Forgot-password usa respuesta neutra para evitar enumeracion de emails.
- Reset-password usa token one-time hasheado, invalida sesiones activas y revoca refresh tokens.
- Change-password requiere access token valido, verifica password actual y revoca sesiones/refresh al completar.
- Login con MFA habilitado no emite tokens directamente: retorna `mfa_required=true` + `challenge_id`.
- MFA verify permite reintentos acotados por challenge; al superar `MFA_CHALLENGE_MAX_ATTEMPTS` o al validar correctamente, el challenge queda consumido.
- Backup codes MFA se entregan una sola vez en activacion y se almacenan hasheados.
- MFA disable requiere step-up (password actual + TOTP/backup code) y revoca sesiones activas.
- Sessions endpoint lista sesiones activas del usuario autenticado y permite revocacion puntual por `session_id`.

### Notas de formato JWT PEM

- Se aceptan claves PEM multi-line reales o con saltos escapados (`\n`) en variables de entorno.

## Migraciones en startup

- Cuando `AUTH_RUNTIME=postgres_redis`, el servicio ejecuta migraciones SQL al arrancar (`sqlx::migrate!`) y falla en startup si hay incompatibilidades.
- `0003_guard_credentials_coverage.sql` bloquea el arranque si detecta usuarios sin fila en `credentials` para evitar huecos silenciosos de autenticacion.

## Modo de ejecucion para migraciones

- Comando canonico en contenedor: `/app/auth migrate`.
- Alternativa equivalente: `AUTH_RUN_MODE=migrate /app/auth`.
- Contrato por runtime:
  - `AUTH_RUNTIME=postgres_redis`: ejecuta migraciones SQL y termina con exit code `0` en exito.
  - `AUTH_RUNTIME=inmemory`: falla rapido con error explicito porque no hay migraciones aplicables.

## Pruebas locales con Postgres

- Helper local: `scripts/test-postgres-local.sh`.
- Si no defines `AUTH_TEST_DATABASE_URL`, el script arma la URL con `PGPASSWORD` y defaults locales:
  - `PGHOST=127.0.0.1`
  - `PGPORT=5432`
  - `PGUSER=postgres`
  - `PGDATABASE=postgres`
- Ejemplos:
  - `PGPASSWORD='<tu_password>' scripts/test-postgres-local.sh`
  - `PGPASSWORD='<tu_password>' scripts/test-postgres-local.sh adapters::postgres::tests::`
  - `AUTH_TEST_DATABASE_URL='postgres://user:pass@127.0.0.1:5432/postgres' cargo test postgres_backed_auth_flow_smoke_with_metrics_protection -- --nocapture`
  - `AUTH_TEST_DATABASE_URL='postgres://user:pass@127.0.0.1:5432/postgres' scripts/test-postgres-local.sh`

## Observabilidad operativa

- Baseline de paneles, umbrales y queries SQL para refresh/auth: `docs/observability-auth-refresh.md`.
- Runbook operativo para ciclo completo de rotacion JWT: `docs/jwt-key-rotation-runbook.md`.
- Este baseline soporta la respuesta operativa para `auth.refresh.reuse_detected`, `auth.refresh.rejected` (`token_rotation_error`) y picos de `429`.
- Endpoint Prometheus expuesto: `GET /metrics`.
- Si `METRICS_BEARER_TOKEN` esta configurado, Prometheus debe enviar `Authorization: Bearer <token>`.
- Si `METRICS_ALLOWED_CIDRS` esta configurado, la IP origen resuelta del scraper debe estar dentro de esos CIDRs.
- Metricas de refresh instrumentadas en runtime:
  - `auth_refresh_requests_total{outcome=...}`
  - `auth_refresh_rejected_total{reason=...}`
  - `auth_refresh_duration_seconds{outcome=...}`
  - `auth_problem_responses_total{status=...,type=...}`
- Metricas de email transaccional:
  - `auth_email_delivery_total{provider=...,template=...,outcome=success|failure}`
  - `auth_email_delivery_duration_seconds{provider=...,template=...,outcome=...}` (solo si `EMAIL_METRICS_LATENCY_ENABLED=true`)
  - `auth_email_retry_attempts_total{provider=...,template=...,outcome=...}`
  - `auth_email_retry_attempts{provider=...,template=...,outcome=...}` (histograma de intensidad de retries por envio)
  - `auth_email_outbox_queue_depth`
  - `auth_email_outbox_oldest_pending_age_seconds`
  - `auth_email_outbox_oldest_due_age_seconds`
  - `auth_email_outbox_dispatch_total{provider=...,template=...,outcome=sent|failed_retryable|failed_exhausted}`
- Incluye señal de hardening de exposicion: `status=403,type=https://example.com/problems/metrics-access-denied`.
- Incluye señal de autenticacion de metricas: `status=401,type=https://example.com/problems/metrics-auth-required`.
- Templates importables de Grafana:
  - SQL/auditoria: `docs/grafana/auth-refresh-security-dashboard.json`
  - Prometheus/runtime: `docs/grafana/auth-refresh-runtime-prometheus.json`
- Reglas de alertas Prometheus: `docs/alerts/auth-refresh-alert-rules.yaml`.
- Ejemplo de enrutamiento Alertmanager: `docs/alertmanager/auth-routing-example.yaml`.
- Ejemplo de configuracion Prometheus (scrape + rules): `docs/prometheus/prometheus-auth-example.yaml`.
- Validacion local de artefactos de observabilidad: `scripts/validate-observability-artifacts.sh`.
- Validacion local de manifiestos Kubernetes (placeholders, sintaxis YAML, render Kustomize y schema): `scripts/validate-k8s-manifests.sh`.
- Tooling operativo para dead-letter de outbox (inspect/requeue/report): `scripts/outbox-dead-letter-tool.sh`.
- Atajo para reporte de dead-letter por provider/template/edad: `scripts/outbox-dead-letter-report.sh`.
- Smoke test reproducible de tooling operativo (DB temporal + migraciones + checkpoints): `scripts/test-ops-tooling-smoke.sh`.
- Snippets SQL parametrizados para operaciones manuales: `scripts/sql/outbox-dead-letter-queries.sql`.
- Tooling de rollout para compliance de `outbox_replay_audit` (inspect/remediate/validate/status): `scripts/outbox-replay-audit-compliance-tool.sh`.
- Workflow manual para gate/auditoria de compliance: `.github/workflows/replay-audit-compliance-manual.yml`.
- Workflow manual para smoke test de tooling operativo: `.github/workflows/ops-tooling-smoke-manual.yml`.
- Workflow manual para validacion de manifiestos K8s: `.github/workflows/k8s-manifest-validation-manual.yml`.
- Workflow manual para validacion de deploy readiness: `.github/workflows/deploy-readiness-validation-manual.yml`.
- Workflow manual de promocion productiva (firma + readiness + render + schema): `.github/workflows/production-promotion-manual.yml`.
- Workflow manual de deploy controlado a produccion (dry-run por defecto + apply opcional): `.github/workflows/production-deploy-manual.yml`.
- Los workflows manuales `k8s-manifest-validation-manual` y `deploy-readiness-validation-manual` instalan versiones pineadas de `kustomize` y `kubeconform`, por lo que `strict_validation=true` queda soportado end-to-end en runners de GitHub Actions.
- Snippets SQL parametrizados para el rollout de compliance: `scripts/sql/outbox-replay-audit-compliance-queries.sql`.
- Snippets SQL DBA para verificar guardas append-only y smoke tests de rechazo: `scripts/sql/outbox-replay-audit-append-only-queries.sql`.
- El comando `requeue` registra auditoria persistente en `outbox_replay_audit` tanto en dry-run como en apply (incluye actor, ticket, filtros, scope y conteos).
- En `--apply` los flags `--actor` y `--ticket` son obligatorios y no aceptan vacio/`unknown`; ademas `--ticket` debe cumplir formato configurable por `OUTBOX_REPLAY_TICKET_PATTERN` (dry-run sigue permisivo y registra `unknown` si no se informa ticket).
- Patron por defecto de ticket: `^((INC|CHG)[0-9]{5,}|CASE[-_ ]?[0-9]{1,12}|[A-Za-z][A-Za-z0-9]{1,14}-[0-9]{1,12})$` (cubre ServiceNow tipo `INC0012345`/`CHG0012345`, `CASE-12345` y Jira-like `AUTH-1234`).
- Override por entorno: exportar `OUTBOX_REPLAY_TICKET_PATTERN='tu_regex_ere'` antes de ejecutar tooling; en `--apply` el script valida primero la sintaxis del regex y luego el valor de ticket.
- La DB impone esa calidad solo para `is_apply=true` (constraint `outbox_replay_audit_apply_actor_ticket_ck`); no se aplica regex estricta de ticket para mantener compatibilidad entre formatos heterogeneos (Jira/ServiceNow/Azure DevOps/casos internos).
- La DB impone append-only real en `outbox_replay_audit`: triggers `outbox_replay_audit_block_update` y `outbox_replay_audit_block_delete` rechazan `UPDATE/DELETE` por defecto.
- Break-glass explicito: solo se permite mutar en una transaccion de mantenimiento si se setean `SET LOCAL auth.outbox_replay_audit_maintenance_override=on`, `SET LOCAL auth.outbox_replay_audit_maintenance_actor=...` y `SET LOCAL auth.outbox_replay_audit_maintenance_ticket=...`.
- El comando `audit` permite revisar ejecuciones recientes de replay (filtrable por `--provider`/`--template`/`--ticket`).
- Soporte de indices para queries de observabilidad: `migrations/0008_add_audit_observability_indexes.sql`.

## Deployment artifacts

- Imagen multi-stage para runtime productivo: `Dockerfile`.
- Exclusion de contexto para build reproducible: `.dockerignore`.
- Integracion local app + postgres + redis: `docker-compose.yml` + `compose.env.example`.
- Baseline Kubernetes canonico (namespace/config/deploy/service/ingress/migration-job/HPA): `deploy/k8s/`.
- Default baseline image for deployability: `ghcr.io/lu149e/system:main` in `deploy/k8s/deployment.yaml` and `deploy/k8s/migration-job.yaml` (override with release tag, ideally immutable digest).
- Baseline ingress is hostless (`deploy/k8s/ingress.yaml`); set host/TLS in your environment overlay.
- Baseline network policy uses selector-based egress for in-cluster `postgres`/`redis` plus DNS; for external endpoints, add overlay egress rules instead of loosening baseline.
- Gate de validacion de manifiestos K8s para pre-deploy/manual CI: `scripts/validate-k8s-manifests.sh`.
- Checklist de despliegue productivo (pre, migrate, smoke, rollback, observabilidad): `docs/deployment-production-checklist.md`.

### Publicar imagen OCI en GHCR (manual o por tag)

- Workflow: `.github/workflows/release-image.yml`.
- Triggers soportados:
  - Manual (`workflow_dispatch`) con input opcional `tag` (ejemplo `v1.4.0`).
  - Push de tags Git que cumplan `v*`.
- Autenticacion: usa `GITHUB_TOKEN` nativo de GitHub Actions (`packages:write`), sin PAT hardcodeado.
- Tags publicados por ejecucion: `main`, `sha-<commit>`, `refs/tags/<tag>` (si corre por tag push) y `tag` manual si se informa en dispatch.
- Evidencia generada:
  - Artifact `image-release-<run_id>` con `image.txt`, `digest.txt`, `tags.txt`, `reference.txt`.
  - Artifact `image-sbom-<run_id>` con SBOM SPDX JSON del digest publicado.
  - Firma keyless Cosign del digest usando OIDC de GitHub Actions (certificado emitido por Fulcio).

Pasos recomendados:

1. Ejecutar release manual desde UI (`Actions -> release-image -> Run workflow`) o por CLI:
   - `gh workflow run release-image.yml -f tag=v1.4.0`
2. Descargar artifact `image-release-<run_id>` y tomar el digest (`digest.txt`).
3. Verificar firma Cosign del digest (recomendado antes de promover):
   - `export OWNER="<org-or-user>"`
   - `export REPO="<repo>"`
   - `export DIGEST="sha256:<digest>"`
   - `cosign verify ghcr.io/lu149e/system@${DIGEST} --certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-identity "https://github.com/${OWNER}/${REPO}/.github/workflows/release-image.yml@refs/heads/main"`
   - Para releases por tag, usar la identidad del ref de tag (`...@refs/tags/<tag>`).
4. Descargar artifact `image-sbom-<run_id>` para evidencia de composicion (archivo `sbom.spdx.json`).
5. Parchear manifiestos de baseline a digest inmutable:
   - `sed -i 's|ghcr.io/lu149e/system:[^[:space:]]*|ghcr.io/lu149e/system@sha256:TU_DIGEST|g' deploy/k8s/deployment.yaml deploy/k8s/migration-job.yaml`
6. Validar render y aplicar con tu pipeline de despliegue.

### Workflow manual: promotion artifact para produccion (sin apply)

- Ejecutar: `Actions -> production-promotion-manual -> Run workflow`.
- Inputs obligatorios: `image_digest`, `ingress_host`, `tls_secret_name`, `postgres_cidr`, `redis_cidr`.
- Gate de firma: valida keyless Cosign para `ghcr.io/lu149e/system@<digest>` con issuer `https://token.actions.githubusercontent.com` e identidad del workflow `release-image.yml` en `refs/heads/main` o `refs/tags/*`.
- Gate de readiness: ejecuta `scripts/generate-production-overlay.sh` y luego `scripts/validate-deploy-readiness.sh` en modo estricto (`STRICT_DEPLOY_VALIDATION=true`).
- Gate de manifiestos: renderiza `kustomize build artifacts/production-overlay/generated` y corre `kubeconform -strict` sobre el YAML renderizado.
- Artifacts publicados siempre:
  - `production-manifest-<run_id>` con `artifacts/production-promotion/production-manifests.yaml`.
  - `production-promotion-evidence-<run_id>` con logs/evidencia (`artifacts/production-promotion/`, `artifacts/deploy-readiness/` y overlay generado).
- Alcance intencional: este workflow NO aplica al cluster ni requiere credenciales de Kubernetes.

### Workflow manual: controlled deploy a produccion (dry-run default, apply opcional)

- Ejecutar: `Actions -> production-deploy-manual -> Run workflow`.
- Inputs obligatorios: `image_digest`, `ingress_host`, `tls_secret_name`, `postgres_cidr`, `redis_cidr`.
- Inputs operativos:
  - `apply_changes` (boolean, default `false`): en `false` ejecuta solo dry-run server-side; en `true` aplica manifiestos al cluster.
  - `allow_client_dry_run_fallback` (boolean, default `false`): solo para simulacion; si el server-side dry-run no puede contactar el API server y `apply_changes=false`, permite continuar sin el gate de `kubectl --dry-run=server`.
  - `namespace` (default `auth`): namespace destino para dry-run/apply/smoke.
- Secret requerido: `KUBE_CONFIG_B64` (kubeconfig en base64 para autenticar `kubectl` en el cluster objetivo).
- Secuencia del workflow:
  - Instala tooling pineado (`kustomize`, `kubeconform`, `kubectl`, `cosign`).
  - Verifica firma keyless Cosign del digest.
  - Genera overlay productivo + ejecuta `validate-deploy-readiness` en modo estricto.
  - Renderiza manifiestos y valida schema con `kubeconform -strict`.
  - Configura kube auth desde `KUBE_CONFIG_B64`.
  - Ejecuta siempre `kubectl apply --dry-run=server` sobre el manifiesto renderizado.
  - Solo si `apply_changes=true`, ejecuta `kubectl apply` real y smoke checks (`rollout status`, endpoints, `GET /healthz`, `GET /readyz` via port-forward).
- Controles de seguridad:
  - Si `apply_changes=true` y falta `KUBE_CONFIG_B64`, falla rapido antes de cualquier intento de apply.
  - El fallback client-side nunca se usa en modo apply; solo aplica en dry-run no destructivo y con flag explicito.
  - Summary final explicita modo (`dry-run` vs `apply`) y estado del job.
  - Publica artifacts/logs siempre: `production-deploy-manual-<run_id>`.

### Smoke test rapido: tooling replay-audit/dead-letter

- Default local (`DATABASE_URL` si existe; si no, `postgres://postgres@127.0.0.1:5432/postgres`): `bash scripts/test-ops-tooling-smoke.sh`
- URL admin explicita: `bash scripts/test-ops-tooling-smoke.sh --postgres-url 'postgres://postgres:secret@127.0.0.1:5432/postgres'`
- Conservar DB temporal para inspeccion manual: `bash scripts/test-ops-tooling-smoke.sh --keep-db`
- Flujo del smoke script: crea DB efimera, aplica `migrations/*.sql`, provisiona roles (`outbox_replay_maintainer`, `ops_replay_oncall`, `auth_app_runtime`), ejecuta checkpoints (`status`, `validate-constraint --apply`, `status --require-release-ready`, `audit --limit 1`) y limpia DB al final salvo `--keep-db`.

### Workflow manual: smoke test de tooling operativo (GitHub Actions)

- Ejecutar: `Actions -> ops-tooling-smoke-manual -> Run workflow`.
- Secret recomendado: `OUTBOX_REPLAY_AUDIT_DATABASE_URL` (URL admin de PostgreSQL).
- Input opcional `postgres_url`: si se informa, sobreescribe el secret para esa ejecucion.
- Input `keep_db` (boolean, default `false`): cuando vale `true`, agrega `--keep-db` al smoke script.
- Evidencia: el job siempre sube artifact `ops-tooling-smoke-<run_id>` con `artifacts/ops-tooling-smoke/smoke.log`, incluso si el smoke falla.

### Playbook rapido: validar constraint `outbox_replay_audit_apply_actor_ticket_ck`

1. **Inspeccionar historico no conforme (solo lectura)**
   - `scripts/outbox-replay-audit-compliance-tool.sh inspect-noncompliant --limit 100`
   - Acotar por ventana para lotes pequenos: `--created-after`, `--created-before`, `--id-after`, `--id-before`.
2. **Remediar por lotes (dry-run primero, apply explicito)**
   - Dry-run: `scripts/outbox-replay-audit-compliance-tool.sh remediate-noncompliant --created-after '2026-03-01T00:00:00Z' --limit 50`
   - Apply: `scripts/outbox-replay-audit-compliance-tool.sh remediate-noncompliant --created-after '2026-03-01T00:00:00Z' --limit 50 --apply --actor oncall.sre --ticket INC-9001 --set-actor migration.legacy --set-ticket LEGACY-IMPORT`
   - Controles: `--apply` obligatorio para mutar, `--actor` + `--ticket` obligatorios en apply, `--ticket`/`--set-ticket` validan formato con `OUTBOX_REPLAY_TICKET_PATTERN`, y por defecto exige filtros de scope (usar `--allow-unfiltered` solo con aprobacion explicita).
   - Seguridad operacional: el comando muestra `scope_noncompliant_total` antes de mutar, emite warnings de APPLY y declara el uso del override break-glass (`auth.outbox_replay_audit_maintenance_*`) acotado a una sola transaccion.
   - Trazabilidad: cada apply inserta una fila en `outbox_replay_audit` con `operation_type='requeue'` y `template_filter='compliance_remediate_noncompliant'` para conservar evidencia sin cambiar el contrato historico del campo `operation_type`.
3. **Validar constraint (dry-run primero, apply despues)**
   - Pre-check dry-run: `scripts/outbox-replay-audit-compliance-tool.sh validate-constraint`
   - Ejecutar validacion real: `scripts/outbox-replay-audit-compliance-tool.sh validate-constraint --apply --lock-timeout-ms 10000 --statement-timeout-ms 900000`
4. **Gate de posture antes de release/auditoria**
   - Salida operativa (texto): `scripts/outbox-replay-audit-compliance-tool.sh status`
   - Salida machine-readable: `scripts/outbox-replay-audit-compliance-tool.sh status --format json`
    - Gate estricto local/CI (exit code no-cero si no esta listo): `scripts/outbox-replay-audit-compliance-tool.sh status --format json --require-release-ready`
    - Campos clave: `constraint_exists`, `constraint_validated`, `append_only_triggers_present`, `historical_noncompliant_total`, `recent_apply_total`, `operator_roles_missing_membership_count`, `operator_roles_missing_membership` (CSV legacy), `operator_roles_missing_membership_list` (JSON array), `release_ready`.
    - Ejemplo de resultado accionable: `operator_roles_missing_membership_count=1` y `operator_roles_missing_membership=ops_replay_oncall`.
   - Compatibilidad: sin `--require-release-ready`, `status` conserva comportamiento previo (texto sigue informativo y JSON solo reporta posture).
5. **Workflow manual de GitHub Actions (artifact + gate opcional)**
    - Ejecutar: `Actions -> replay-audit-compliance-manual -> Run workflow`.
    - DB URL: usar secret `OUTBOX_REPLAY_AUDIT_DATABASE_URL` o pasar input `database_url` en `workflow_dispatch`.
    - Gate: `strict_gate=true` agrega `--require-release-ready`; si falla, el job termina en rojo.
    - Role drift opcional: `app_role` se mapea a `--app-role`, `operator_roles` (CSV) se mapea a `--operator-role`, y `maintenance_role` setea `PGOPTIONS='-c auth.outbox_replay_audit_maintenance_role=<role>'` para esa ejecucion.
    - Ejemplo "strict governance" (dispatch via CLI): `gh workflow run replay-audit-compliance-manual.yml -f strict_gate=true -f recent_window_days=7 -f app_role=auth_app_runtime -f operator_roles=ops_replay_oncall,ops_replay_admin -f maintenance_role=outbox_replay_maintainer`.
    - Evidencia: el workflow publica `artifacts/replay-audit-compliance/status.json` y `artifacts/replay-audit-compliance/status.log` como artifact descargable.
6. **Abort/rollback operativo**
   - Si `inspect-noncompliant` sigue devolviendo filas, no correr `VALIDATE CONSTRAINT`; continuar remediando por lotes.
   - Si `validate-constraint --apply` falla por lock timeout, abortar ventana y reintentar con menor carga o timeout mayor.
   - Si un lote de remediate apply se ejecuto con valores incorrectos, revertir con update acotado por IDs/ventana usando `scripts/sql/outbox-replay-audit-compliance-queries.sql` (con override break-glass explicito en transaccion controlada) y volver a inspeccionar antes de validar.

## Evidencia reproducible de performance/soak

- Artefactos de carga/soak para rutas criticas de auth (`login`, `refresh`, `me`): `scripts/perf/`.
- Script unico de ejecucion y gate KPI: `scripts/perf/run-auth-load-soak.sh`.
- Documentacion detallada (escenarios, KPI, salidas y tuning): `docs/performance/auth-load-soak.md`.
- Salida machine-readable para evidencia: `artifacts/perf/kpi-summary.json`.
- Workflow de GitHub Actions solo manual (no bloquea CI por defecto): `.github/workflows/perf-evidence-manual.yml`.

## Runbook rapido para `credentials` faltantes

- Si el startup falla por cobertura de `credentials`, no fuerces deploy parcial.
- Ejecuta una migracion correctiva controlada: crear fila en `credentials` para cada usuario afectado y disparar reset obligatorio de password.
- Reintenta el deploy solo cuando la validacion de cobertura quede en verde.

## Runbook rapido para incidentes de refresh

### 1) Deteccion

- Señales de alerta:
  - Pico de `auth.refresh.reuse_detected`.
  - Pico de `auth.refresh.rejected` con `reason=token_rotation_error`.
  - Aumento sostenido de `401` en `/v1/auth/token/refresh`.
- Confirmar alcance por ventana de tiempo y por `trace_id`.

### 2) Contencion inmediata

- Si hay sospecha de replay activo, priorizar contencion sobre UX:
  - mantener `LOGIN_ABUSE_REDIS_FAIL_MODE=fail_closed`.
  - revocar sesiones comprometidas del usuario/segmento afectado.
- Si la causa es infraestructura (rotacion), activar mitigacion operativa:
  - verificar salud de PostgreSQL/latencia/locks.
  - reducir presion de trafico de refresh (rate-limit temporal en edge si aplica).

### 3) Diagnostico tecnico

- Revisar auditoria por `trace_id`:
  - `auth.refresh.reuse_detected` -> posible robo/replay de token.
  - `auth.refresh.rejected` + `token_rotation_error` -> fallo de persistencia/tx.
- Correlacionar con estado de DB:
  - bloqueos y timeouts de transaccion.
  - errores de conectividad o agotamiento de pool.

### 4) Recuperacion

- Una vez estabilizada infraestructura:
  - validar que `auth.refresh.rejected` vuelva a baseline.
  - validar que nuevas rotaciones de refresh cierren en `auth.refresh.success`.
- Para usuarios impactados:
  - forzar re-login si hubo compromiso de sesion.
  - comunicar impacto/ventana si aplica SLA externo.

### 5) Post-incident

- Capturar RCA con causa primaria y radio de impacto.
- Definir accion preventiva concreta (pool sizing, timeout, indice, observabilidad, o hardening de cliente).
- Agregar/regresar prueba automatizada si se detecto hueco en cobertura.

## Hardening pendiente

- Ejecutar migraciones y endurecer permisos de DB/Redis (usuarios con privilegios minimos por entorno).
- Integrar proveedor de correo transaccional para entrega real de tokens de verificacion y reset.
- En produccion, activar `ENFORCE_DATABASE_TLS=true` y `ENFORCE_REDIS_TLS=true` con endpoints TLS reales.
- Ejecutar periodicamente simulacro de rotacion JWT usando `docs/jwt-key-rotation-runbook.md` (incluyendo validaciones de convivencia y retiro).
- Validar politicamente `LOGIN_ABUSE_REDIS_FAIL_MODE`: `fail_closed` maximiza seguridad; `fail_open` mejora disponibilidad ante caidas de Redis (comportamiento tecnico ya cubierto por tests de resiliencia).

## Nota de supply-chain

- El job de CI ejecuta `cargo audit --ignore RUSTSEC-2023-0071` por una limitacion del metapaquete `sqlx` que incluye crates de drivers no usados (MySQL) en `Cargo.lock`.
- Alcance real de esta API: solo PostgreSQL (`sqlx` con feature `postgres` + `default-features=false`).
- Riesgo residual: bajo para este servicio (no se usa MySQL en runtime), pero debe revisarse al actualizar `sqlx`.

## Siguientes pasos

1. Calibrar umbrales/ventanas por bucket (`email|any` vs `email|ip`) con datos reales de trafico y fraude.
2. Materializar dashboards en Grafana/monitoring usando `docs/observability-auth-refresh.md` y validar umbrales en staging.
3. Activar branch protection exigiendo jobs `quality`, `supply-chain` y `observability` en PRs.
4. Conectar reglas `docs/alerts/auth-refresh-alert-rules.yaml` + routing `docs/alertmanager/auth-routing-example.yaml` al stack real.

# Observabilidad operativa de refresh/auth

Este documento define una linea base para dashboards y alertas sobre:

- `auth.refresh.reuse_detected`
- `auth.refresh.rejected` (especialmente `reason=token_rotation_error`)
- picos de `429` en autenticacion
- picos y ratio alto de decisiones `block` del motor de riesgo de login
- outcomes de ceremonias passkey (`challenge.issued`, `success`, `rejected`, incluido `auth.passkey.login.rejected`)
- step-up MFA disparado por riesgo (`auth.mfa.challenge.issued` con `risk_reason`)
- picos de `403` en `/metrics` por politica de acceso (`metrics-access-denied`)
- picos de `401` en `/metrics` por bearer faltante/invalido (`metrics-auth-required`)

Se puede implementar con Prometheus (si ya existen metricas) o con consultas sobre `audit_events` en PostgreSQL.

## Artefactos listos para usar

- Templates de dashboard Grafana:
  - SQL/auditoria: `docs/grafana/auth-refresh-security-dashboard.json`.
  - Prometheus/runtime: `docs/grafana/auth-refresh-runtime-prometheus.json`.
- Reglas de alertas Prometheus:
  - `docs/alerts/auth-refresh-alert-rules.yaml`.
- Ejemplo de enrutamiento Alertmanager (critical vs warning):
  - `docs/alertmanager/auth-routing-example.yaml`.
- Ejemplo de configuracion Prometheus (scrape + rules):
  - `docs/prometheus/prometheus-auth-example.yaml`.
- Script de validacion local (dashboards JSON + reglas Prometheus):
  - `scripts/validate-observability-artifacts.sh`.
- Indices de soporte en DB para consultas de observabilidad:
  - `migrations/0008_add_audit_observability_indexes.sql`.
- Endpoint Prometheus para scrapping:
  - `GET /metrics`
  - si `METRICS_BEARER_TOKEN` o `METRICS_BEARER_TOKEN_FILE` estan configurados, incluir header `Authorization: Bearer <token>` desde Prometheus
  - si `METRICS_ALLOWED_CIDRS` esta configurado, la IP origen del scraper debe pertenecer a esos rangos
  - metricas incluidas para auth runtime:
    - `auth_refresh_requests_total{outcome=success|error}`
    - `auth_login_risk_decisions_total{decision=allow|block, reason=...}`
    - `auth_login_risk_penalty_total{profile=standard|elevated|aggressive, reason=...}`
    - `auth_passkey_requests_total{operation=register_start|register_finish|login_start|login_finish, outcome=success|error}`
    - `auth_passkey_login_rejected_total{reason=...}`
    - `auth_passkey_register_rejected_total{reason=...}`
    - `auth_password_forgot_accepted_total{outcome=...}`
    - `auth_password_reset_rejected_total{reason=...}`
    - `auth_passkey_challenge_janitor_enabled`
    - `auth_passkey_challenge_prune_interval_seconds`
    - `auth_passkey_challenge_prune_runs_total{outcome=success|error}`
    - `auth_passkey_challenge_prune_last_success_unixtime`
    - `auth_passkey_challenge_prune_last_failure_unixtime`
    - `auth_passkey_challenge_pruned_total`
    - `auth_passkey_challenge_prune_errors_total`
    - `auth_refresh_rejected_total{reason=...}`
    - `auth_refresh_duration_seconds{outcome=success|error}`
    - `auth_problem_responses_total{status=..., type=...}`
    - `auth_email_delivery_total{provider=..., template=verification|password_reset, outcome=success|failure}`
    - `auth_email_delivery_duration_seconds{provider=..., template=..., outcome=...}` (opcional; requiere `EMAIL_METRICS_LATENCY_ENABLED=true`)
    - `auth_email_retry_attempts_total{provider=..., template=..., outcome=...}`
    - `auth_email_retry_attempts{provider=..., template=..., outcome=...}`
    - `auth_email_outbox_queue_depth`
    - `auth_email_outbox_oldest_pending_age_seconds`
    - `auth_email_outbox_oldest_due_age_seconds`
    - `auth_email_outbox_dispatch_total{provider=..., template=..., outcome=sent|failed_retryable|failed_exhausted}`
    - `auth_email_outbox_claimed_per_poll` (histograma)
    - `auth_email_outbox_reclaimed_after_expiry_total`
    - `auth_email_outbox_claim_failures_total`
- Recomendacion: aplicar migraciones antes de importar el dashboard SQL para evitar full scans en `audit_events`.

## Ejemplo de scrape Prometheus

Ver tambien: `docs/prometheus/prometheus-auth-example.yaml`.

```yaml
scrape_configs:
  - job_name: auth-api
    metrics_path: /metrics
    scheme: http
    static_configs:
      - targets:
          - auth-api.internal:8080
    # Opcional: solo si la API define METRICS_BEARER_TOKEN
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/secrets/auth_metrics_token

    # Recomendacion operacional:
    # - Si usas METRICS_ALLOWED_CIDRS, verifica la IP origen efectiva del scrape
    #   (directa o via proxy) para evitar bloqueos no deseados.
```

## Objetivos

1. Detectar replay de refresh tokens en minutos, no en horas.
2. Distinguir rapidamente problema de seguridad (reuse) vs problema de infraestructura (rotacion).
3. Activar contencion con umbrales claros y consistentes con el runbook.

## Paneles recomendados

1. **Refresh reuse (conteo/minuto)**
   - Serie principal: eventos `auth.refresh.reuse_detected`.
2. **Refresh rejected por razon (stacked)**
   - Desglose por `metadata.reason` (`token_not_found`, `token_expired`, `token_rotation_error`, etc.).
3. **Ratio de errores de rotacion**
   - `token_rotation_error / total refresh attempts`.
4. **401 en endpoint de refresh**
   - tasa y porcentaje sobre requests totales de `/v1/auth/token/refresh`.
5. **429 en login/auth**
   - picos por endpoint para validar efecto de anti-abuso.
6. **Latencia P95/P99 de refresh**
   - para correlacionar errores de rotacion con degradacion de DB.
7. **Queue depth de email outbox (trend)**
   - profundidad actual y tendencia para detectar atraso sostenido.
8. **Dispatch rate de outbox por outcome**
   - series separadas para `sent`, `failed_retryable`, `failed_exhausted`.
9. **Failure ratio de outbox + retry pressure**
   - combinar ratio de fallos del dispatcher y presion de retries para triage rapido.
10. **Oldest pending age de outbox**
    - edad del mensaje pendiente mas antiguo para separar backlog real de picos transitorios de profundidad.
11. **Oldest due age de outbox**
    - edad del mensaje due mas antiguo (`next_attempt_at <= now`) para detectar estancamiento real sin ruido de mensajes en backoff.
12. **Claim/lease churn de outbox**
    - promedio de claims por poll y reclamos tras expiracion para detectar workers trabados o lease tuning agresivo.
13. **Claim failures de outbox (ventana 10m)**
    - `sum(increase(auth_email_outbox_claim_failures_total[10m]))` para detectar fallos sostenidos de query/claim aunque el worker siga vivo.
14. **Eventos de ceremonia passkey por tipo**
    - `auth.passkey.register.challenge.issued`, `auth.passkey.register.success`, `auth.passkey.register.rejected`, `auth.passkey.login.challenge.issued`, `auth.passkey.login.success`, `auth.passkey.login.rejected`.
15. **Rechazos de registro passkey por reason**
    - desglose de `metadata.reason` en `auth.passkey.register.rejected` para separar policy (`account_not_active`) de fallos de cliente.
16. **MFA challenges por `risk_reason`**
    - distinguir challenges por riesgo real vs challenges normales (`risk_reason` ausente) para tuning de policy.
17. **Passkey login rejected por reason (runtime metric)**
    - `sum by (reason) (rate(auth_passkey_login_rejected_total[5m]))` para detectar rapidamente si domina `invalid_or_expired_challenge` (friccion/TTL) o `invalid_passkey_response` (regresion cliente/WebAuthn).
18. **Passkey login rejected por reason (audit SQL)**
    - `event_type='auth.passkey.login.rejected'` agrupado por `metadata.reason` para correlacion operacional/forense por minuto.
19. **Passkey register rejected por reason (runtime metric)**
    - `sum by (reason) (rate(auth_passkey_register_rejected_total[5m]))` para detectar drift de challenge (`invalid_or_expired_challenge`), mismatch (`challenge_user_mismatch`) o regresiones cliente (`invalid_passkey_response`).
20. **Password recovery abuse signals (runtime metrics)**
    - `sum by (reason) (rate(auth_password_reset_rejected_total[5m]))` para detectar picos de `token_not_found/expired/already_used` o `account_not_active`.
    - `sum by (outcome) (rate(auth_password_forgot_accepted_total[5m]))` para vigilar proporcion `unknown` en forgot-password.
21. **Login risk penalty pressure (runtime metric)**
    - `sum by (profile, reason) (rate(auth_login_risk_penalty_total[5m]))` para validar que la penalizacion adaptativa no derive en lockouts excesivos por falsos positivos.

## Umbrales iniciales (accionables)

> Ajustar con datos reales de trafico/fraude.

- **Alerta CRITICAL - posible incidente de replay**
  - `refresh.reuse_detected >= 10` en 5 minutos, o
  - `refresh.reuse_detected / refresh_total >= 0.5%` durante 10 minutos.
- **Alerta WARNING - degradacion de rotacion/interna**
  - `internal >= 5` en 5 minutos (en Prometheus: `auth_refresh_rejected_total{reason="internal"}`).
- **Alerta CRITICAL - fallo sostenido de rotacion/interna**
  - `internal / refresh_total >= 2%` durante 10 minutos.
- **Alerta WARNING - lockout agresivo / friccion UX**
  - `429` en login/auth por encima de baseline + 3 desviaciones por 15 minutos.
- **Alerta WARNING - bloqueos de riesgo de login anormalmente altos**
  - `sum(increase(auth_login_risk_decisions_total{decision="block"}[10m])) >= 50`, o
  - `auth:login_risk_block_ratio_10m >= 10%` durante 10 minutos.
- **Alerta WARNING - penalizacion adaptativa de riesgo excesiva**
  - `auth:login_risk_penalty_units_10m >= 150` por 10m.
- **Alerta WARNING - rechazo elevado de passkey login**
  - `auth:passkey_login_rejected_ratio_10m >= 20%` por 10m con `>= 20` requests `login_finish`.
- **Alerta WARNING - rechazo elevado de passkey register finish**
  - `auth:passkey_register_rejected_ratio_10m >= 25%` por 10m con `>= 10` requests `register_finish`.
- **Alerta WARNING - pico de mismatch user/flow en passkey register**
  - `challenge_user_mismatch >= 5` en 10m.
- **Alerta WARNING - picos de rechazo en password reset**
  - `auth:password_reset_rejected_10m >= 20` sostenido por 10m.
- **Alerta WARNING - alto ratio unknown en forgot-password**
  - `auth:password_forgot_unknown_ratio_10m >= 60%` por 10m con `>= 30` requests de forgot.
- **Alerta WARNING - pico de passkey login por reason critica**
  - `invalid_passkey_response >= 10` en 10m, o
  - `invalid_or_expired_challenge >= 20` en 10m.
- **Alerta WARNING - sondeo/bloqueo en endpoint de metricas**
  - `metrics-access-denied >= 20` en 15 minutos.
- **Alerta WARNING - autenticacion fallida en endpoint de metricas**
  - `metrics-auth-required >= 20` en 15 minutos.
- **Alerta WARNING - degradacion proveedor email transaccional**
  - `auth:email_failure_ratio_10m >= 5%` por 10m (con volumen minimo de 50 envios/10m).
- **Alerta WARNING - presion alta de reintentos email**
  - `auth:email_retry_pressure_10m >= 0.8` por 15m (con volumen minimo de 50 envios/10m).
- **Alerta WARNING - backlog alto sostenido de outbox email**
  - `max_over_time(auth_email_outbox_oldest_due_age_seconds[15m]) >= 600`
    y `max_over_time(auth_email_outbox_queue_depth[15m]) >= 20` por 10m.
- **Alerta WARNING - ratio alto de fallos del dispatcher outbox**
  - `auth:email_outbox_dispatch_failure_ratio_10m >= 20%` por 10m (con volumen minimo de 25 dispatches/10m).
- **Alerta CRITICAL - procesamiento outbox aparentemente estancado**
  - `max_over_time(auth_email_outbox_oldest_due_age_seconds[15m]) >= 900`
    y `sum(increase(auth_email_outbox_dispatch_total[15m])) == 0`
    y `sum(increase(auth_email_outbox_claimed_per_poll_count[15m])) == 0` por 15m.
- **Alerta WARNING - fallos sostenidos de claim/fetch en outbox**
  - `sum(increase(auth_email_outbox_claim_failures_total[10m])) >= 10` por 10m.

## Consultas SQL base (fuente: audit_events)

### 1) Refresh reuse por minuto

```sql
SELECT
  date_trunc('minute', created_at) AS ts,
  count(*) AS reuse_count
FROM audit_events
WHERE event_type = 'auth.refresh.reuse_detected'
  AND created_at >= now() - interval '24 hours'
GROUP BY 1
ORDER BY 1;
```

### 2) Refresh rejected por reason

```sql
SELECT
  date_trunc('minute', created_at) AS ts,
  COALESCE(metadata->>'reason', 'unknown') AS reason,
  count(*) AS rejected_count
FROM audit_events
WHERE event_type = 'auth.refresh.rejected'
  AND created_at >= now() - interval '24 hours'
GROUP BY 1, 2
ORDER BY 1, 2;
```

### 3) Rotation error ratio (aproximado)

```sql
WITH rejected AS (
  SELECT
    date_trunc('minute', created_at) AS ts,
    count(*) FILTER (WHERE metadata->>'reason' = 'token_rotation_error') AS rotation_error_count,
    count(*) AS rejected_count
  FROM audit_events
  WHERE event_type = 'auth.refresh.rejected'
    AND created_at >= now() - interval '24 hours'
  GROUP BY 1
),
success AS (
  SELECT
    date_trunc('minute', created_at) AS ts,
    count(*) AS success_count
  FROM audit_events
  WHERE event_type = 'auth.refresh.success'
    AND created_at >= now() - interval '24 hours'
  GROUP BY 1
)
SELECT
  COALESCE(s.ts, r.ts) AS ts,
  COALESCE(r.rotation_error_count, 0) AS rotation_error_count,
  COALESCE(r.rejected_count, 0) + COALESCE(s.success_count, 0) AS refresh_total,
  CASE
    WHEN (COALESCE(r.rejected_count, 0) + COALESCE(s.success_count, 0)) = 0 THEN 0
    ELSE COALESCE(r.rotation_error_count, 0)::numeric
         / (COALESCE(r.rejected_count, 0) + COALESCE(s.success_count, 0))::numeric
  END AS rotation_error_ratio
FROM success s
FULL OUTER JOIN rejected r ON s.ts = r.ts
ORDER BY 1;
```

## Runbook por alerta Prometheus

- `AuthRefreshReuseDetectedSpike` (critical): activar contencion inmediata (revocar refresh tokens activos, invalidar sesiones sospechosas, exigir re-login), abrir incidente de seguridad y preservar evidencias de IP/device.
- `AuthRefreshReuseDetectedRatioHigh` (critical): tratar como replay sostenido; aplicar contencion por segmentos de riesgo, reforzar detecciones en WAF/rate limits y verificar compromiso de credenciales.
- `AuthRefreshInternalErrorBurst` (warning): revisar salud de infraestructura auth (DB, pool, timeouts, errores de transaccion) antes de ajustar logica de autenticacion.
- `AuthRefreshInternalErrorRatioHigh` (critical): escalar a incidente de disponibilidad; habilitar mitigaciones (degradar paths no criticos, proteger capacidad DB) y comunicar impacto a on-call.
- `AuthLoginLocked429Spike` (warning): validar que no haya regresion de anti-abuso; recalibrar umbrales de lockout para reducir friccion sin bajar proteccion.
- `AuthLoginRiskBlockSpike` (warning): investigar si hay ataque activo o reglas demasiado agresivas; revisar `reason` dominante (`blocked_source_ip`, `blocked_user_agent`, `blocked_email_domain`) antes de ajustar policy.
- `AuthLoginRiskBlockRatioHigh` (warning): tratar como degradacion de UX/precision del motor de riesgo; validar falsos positivos y definir rollback parcial de reglas si compromete conversion legitima.
- `AuthLoginRiskPenaltyUnitsSpike` (warning): revisar `auth_login_risk_penalty_total` por `profile/reason`; si domina `aggressive` sin evidencia de ataque, recalibrar reglas de riesgo para evitar lockouts excesivos.
- `AuthPasskeyErrorRatioHigh` (warning): revisar configuracion `PASSKEY_RP_ID`/`PASSKEY_RP_ORIGIN`, reloj de nodos, persistencia de `passkey_challenges` y eventos de rechazo (`invalid_passkey_*`) para aislar si es regresion de app o cambio de cliente/browser.
- `AuthPasskeyLoginRejectedRatioHigh` (warning): revisar distribucion por `reason` en `auth_passkey_login_rejected_total`; si domina `invalid_or_expired_challenge`, priorizar estado/TTL/sincronizacion; si domina `invalid_passkey_response`, priorizar regresion cliente/WebAuthn.
- `AuthPasskeyLoginRejectedInvalidResponseSpike` (warning): validar cambios recientes en cliente/browser WebAuthn, formatos de payload y compatibilidad de ceremonias en `login_finish`.
- `AuthPasskeyLoginRejectedInvalidOrExpiredChallengeSpike` (warning): validar caducidad real de challenge, retrasos UX entre start/finish y posibles perdidas de estado entre nodos.
- `AuthPasskeyRegisterRejectedRatioHigh` (warning): revisar `auth_passkey_register_rejected_total` por `reason`; si domina `challenge_user_mismatch`, validar correlacion de identidad/flow, si domina `invalid_passkey_response`, investigar regresiones de cliente en registro.
- `AuthPasskeyRegisterRejectedInvalidResponseSpike` (warning): validar cambios recientes de cliente/browser WebAuthn durante registro y compatibilidad de payload `register_finish`.
- `AuthPasskeyRegisterRejectedChallengeMismatchSpike` (warning): revisar sesiones cruzadas, consistencia `flow_id`-usuario en frontend y posibles condiciones de carrera en tabs/dispositivos durante registro.
- `AuthPasswordResetRejectedSpike` (warning): revisar reasons dominantes en `auth_password_reset_rejected_total`; si predominan `token_not_found/expired`, investigar abuso de tokens y bruteforce de recovery; si domina `account_not_active`, revisar uso indebido sobre cuentas pendientes/inactivas.
- `AuthPasswordForgotUnknownRatioHigh` (warning): tratar como posible enumeracion/stuffing; reforzar rate limits/WAF y validar que la respuesta externa se mantenga generica sin leak de existencia de cuenta.
- `AuthPasskeyChallengePruneErrorsSustained` (warning): revisar logs del janitor de passkey, conectividad/transacciones contra DB y saturacion de locks; si persiste, ejecutar poda manual controlada sobre `passkey_challenges` por `expires_at <= now()`.
- `AuthPasskeyChallengePruneHeartbeatMissing` (warning): validar que el janitor este habilitado/ejecutando en pods (`auth_passkey_challenge_janitor_enabled=1`) y que existan corridas `success` en `auth_passkey_challenge_prune_runs_total`; si no, revisar scheduler loop, runtime stalls y salud DB.
- `AuthPasskeyChallengePruneHeartbeatStale` (warning): revisar `auth:passkey_prune_last_success_age_seconds` versus `auth_passkey_challenge_prune_interval_seconds`; si supera 3x sostenido, investigar stalls parciales del loop aun cuando no haya errores explícitos.
- `AuthMetricsAccessDeniedSpike` (warning): confirmar CIDRs permitidos y origen real del scraper (directo/proxy); investigar sondeo externo si no corresponde a scrapers legitimos.
- `AuthMetricsAuthRequiredSpike` (warning): rotar/validar bearer token del scraper, revisar expiracion/secrets mount y descartar intentos de acceso sin credenciales.
- `AuthEmailFailureRatioSustained` (warning): validar estado del proveedor (API/status page), credenciales y quotas; revisar codigos de respuesta upstream y decidir failover/cola de contingencia.
- `AuthEmailRetryPressureHigh` (warning): investigar throttling/degradacion del proveedor; aumentar backoff/jitter o reducir concurrencia de envio para evitar amplificacion de fallos.
- `AuthEmailOutboxQueueBacklogHigh` (warning):
  1. Confirmar tendencia en dashboards (`Email Outbox Oldest Due vs Pending Age` + `Email Outbox Queue Depth`): `due` alto indica atraso real; `pending` alto con `due` bajo suele indicar backlog en backoff programado.
  2. Verificar salud del dispatcher (pods/restarts, logs `email outbox dispatch failed`, latencia DB, lock contention).
  3. Correlacionar con `Email Outbox Dispatch Rates`: si `sent_rate` cae pero hay `failed_retryable`, priorizar incidente de proveedor/conectividad; si todo cae, priorizar worker/runtime.
  4. Mitigar: aumentar replicas del worker, bajar `EMAIL_OUTBOX_POLL_INTERVAL_MS` o subir `EMAIL_OUTBOX_BATCH_SIZE` temporalmente, monitoreando impacto en DB.
- `AuthEmailOutboxDispatchFailureRatioHigh` (warning):
  1. Identificar mix de `failed_retryable` vs `failed_exhausted` para separar degradacion transitoria de fallos definitivos.
  2. Revisar codigos/errores del proveedor y estado de credenciales/quotas; confirmar que no haya cambios de red/DNS/TLS.
  3. Si domina `failed_retryable`, ajustar backoff/jitter y/o reducir concurrencia para evitar tormenta de reintentos.
  4. Si domina `failed_exhausted`, activar replay controlado de mensajes fallidos y abrir incidente con proveedor.
- `AuthEmailOutboxProcessingStalled` (critical):
  1. Validar que `oldest_due_age_seconds` supera 15m y que no hay claims/dispatch en 15m (descartar falso positivo por bajo trafico).
  2. Comprobar que el dispatcher esta vivo (proceso/pod activo, loops de polling, errores de claim/lease en logs).
  3. Revisar lease/locking en DB (`processing`, `lease_expires_at`) y metricas de churn (`auth_email_outbox_reclaimed_after_expiry_total`) para detectar workers trabados o expiraciones recurrentes.
  4. Mitigar inmediatamente: reiniciar worker atascado, escalar replicas y, si aplica, reducir temporalmente `EMAIL_OUTBOX_LEASE_MS` para recuperar filas bloqueadas.
  5. Si persiste >30m, declarar incidente de disponibilidad de notificaciones y comunicar impacto a stakeholders.
- `AuthEmailOutboxClaimFailuresSustained` (warning):
  1. Confirmar en dashboard el valor de `auth_email_outbox_claim_failures_total` (10m/15m) y revisar si coincide con aumento de `oldest_due_age_seconds`.
  2. Revisar logs del worker para errores `email outbox fetch failed` y clasificar causa (timeout DB, pool saturado, lock contention, error SQL).
  3. Validar salud de PostgreSQL y del pool de conexiones (latencia, conexiones activas, waits), y aplicar mitigacion inicial: escalar worker o aliviar presion de DB.
  4. Si los fallos se sostienen >20m o hay crecimiento de backlog, escalar a incidente de disponibilidad de notificaciones.

## Runbook operativo dead-letter outbox

- Script principal: `scripts/outbox-dead-letter-tool.sh`.
- Modo reporte directo: `scripts/outbox-dead-letter-report.sh`.
- Query snippets parametrizados: `scripts/sql/outbox-dead-letter-queries.sql`.
- Auditoria persistente de replay manual: tabla `outbox_replay_audit` (append-only).
- Referencia DBA para guardas append-only (triggers + smoke tests): `scripts/sql/outbox-replay-audit-append-only-queries.sql`.

### Uso rapido

- Inspeccionar mensajes exhaustos (solo lectura):
  - `scripts/outbox-dead-letter-tool.sh inspect --provider sendgrid --limit 25`
- Reporte agregado por provider/template y buckets de edad:
  - `scripts/outbox-dead-letter-tool.sh report --failed-after '2026-03-01T00:00:00Z'`
  - `scripts/outbox-dead-letter-report.sh --template verification`
- Replay controlado (dry-run por defecto):
  - `scripts/outbox-dead-letter-tool.sh requeue --template verification --failed-after '2026-03-01T00:00:00Z' --limit 20`
- Ejecutar replay real:
  - `scripts/outbox-dead-letter-tool.sh requeue --template verification --failed-after '2026-03-01T00:00:00Z' --limit 20 --apply --actor oncall.sre --ticket INC-12345`
- Revisar auditoria de replay:
  - `scripts/outbox-dead-letter-tool.sh audit --limit 50`
  - `scripts/outbox-dead-letter-tool.sh audit --provider sendgrid --template verification --ticket INC-12345 --limit 20`

### Controles de seguridad

- `requeue` corre en dry-run por defecto; no muta filas sin `--apply`.
- `requeue` exige al menos un filtro (`--provider`, `--template`, `--failed-after`, `--failed-before`) para evitar replay masivo accidental.
- Para replay masivo intencional, usar `--allow-unfiltered` de forma explicita y preferir `--limit` conservador por lotes.
- `requeue` requiere `--actor` y `--ticket` cuando se usa `--apply` (cumplimiento/auditoria y trazabilidad de change-control); en `--apply` no se permite vacio/`unknown` y `--ticket` debe matchear `OUTBOX_REPLAY_TICKET_PATTERN`; en dry-run sin valores explicitos se registra `unknown`.
- Patron por defecto para `OUTBOX_REPLAY_TICKET_PATTERN`: `^((INC|CHG)[0-9]{5,}|CASE[-_ ]?[0-9]{1,12}|[A-Za-z][A-Za-z0-9]{1,14}-[0-9]{1,12})$`.
- Override por entorno: exportar `OUTBOX_REPLAY_TICKET_PATTERN='tu_regex_ere'` antes de correr `requeue --apply` o `remediate-noncompliant --apply`; el script valida sintaxis del regex y luego valida el/los tickets.
- Cada ejecucion de `requeue` (dry-run y apply) inserta una fila de auditoria con actor, ticket, filtros, `is_apply`, `selected_count`, `updated_count` y timestamp.
- En modo `--apply`, update + insercion de auditoria se ejecutan en la misma sentencia SQL para mantener trazabilidad transaccional.
- La tabla `outbox_replay_audit` refuerza en DB esa regla para `is_apply=true` con el constraint `outbox_replay_audit_apply_actor_ticket_ck` (sin regex estricta de ticket por compatibilidad multi-sistema).
- La tabla `outbox_replay_audit` se protege como append-only a nivel DB: los triggers `outbox_replay_audit_block_update` y `outbox_replay_audit_block_delete` bloquean `UPDATE/DELETE` por defecto con errores explicitos de cumplimiento.
- Break-glass de mantenimiento: mutaciones en `outbox_replay_audit` solo se habilitan dentro de una transaccion controlada con `SET LOCAL auth.outbox_replay_audit_maintenance_override=on`, metadata obligatoria (`auth.outbox_replay_audit_maintenance_actor` + `auth.outbox_replay_audit_maintenance_ticket`) y membresia del caller en el rol de mantenimiento efectivo.
- Rol de mantenimiento efectivo: por defecto `outbox_replay_maintainer`; puede sobreescribirse por sesion via `auth.outbox_replay_audit_maintenance_role` para entornos con naming/politica distinta.
- El replay reinicia estado de forma segura: `status='pending'`, `attempts=0`, `next_attempt_at=NOW()`, limpia `processing_owner`/`lease_expires_at`, limpia `failed_at`/`last_error` y actualiza `updated_at`.
- Operar en ventanas acotadas y confirmar descenso de `failed_exhausted` + estabilidad de `AuthEmailOutboxDispatchFailureRatioHigh` tras cada lote.

## Runbook operativo: rollout de compliance para `outbox_replay_audit`

- Script principal: `scripts/outbox-replay-audit-compliance-tool.sh`.
- Query snippets parametrizados: `scripts/sql/outbox-replay-audit-compliance-queries.sql`.
- Setup SQL de rol least-privilege: `scripts/sql/outbox-replay-audit-maintenance-role-setup.sql`.
- Objetivo: limpiar historico no conforme antes de `VALIDATE CONSTRAINT outbox_replay_audit_apply_actor_ticket_ck`.
- Gate operativo recomendado pre-release/auditoria: `status` (texto o JSON) para posture rapido.
- Workflow manual para evidence/gate en CI: `.github/workflows/replay-audit-compliance-manual.yml`.

### Setup least-privilege del break-glass

1. **Crear rol dedicado de mantenimiento (NOLOGIN)**
   - `CREATE ROLE outbox_replay_maintainer NOLOGIN;`
   - Alternativa estandarizada: ejecutar `scripts/sql/outbox-replay-audit-maintenance-role-setup.sql` con `-v maintenance_role='outbox_replay_maintainer'`.
2. **Conceder membresia solo a roles operadores aprobados**
   - `GRANT outbox_replay_maintainer TO ops_replay_oncall;`
   - Repetir por rol operativo necesario; evitar grants directos a roles de aplicacion.
3. **Verificar separacion de privilegios (runtime app fuera del rol)**
   - `REVOKE outbox_replay_maintainer FROM auth_app_runtime;`
   - Verificar: `SELECT pg_has_role('auth_app_runtime', 'outbox_replay_maintainer', 'MEMBER');` debe devolver `false`.
4. **Uso temporal de override en sesion controlada**
   - Dentro de una unica transaccion: `SET LOCAL auth.outbox_replay_audit_maintenance_override = on` + `SET LOCAL auth.outbox_replay_audit_maintenance_actor = '<operador>'` + `SET LOCAL auth.outbox_replay_audit_maintenance_ticket = '<ticket>'`.
   - Solo cuando la politica use otro nombre de rol: agregar `SET LOCAL auth.outbox_replay_audit_maintenance_role = '<rol_mantenimiento_existente>'`.
   - Fuera de esa transaccion, no debe quedar override persistente.

### Flujo recomendado (inspect -> remediate -> validate)

1. **Inspeccion inicial (read-only)**
   - `scripts/outbox-replay-audit-compliance-tool.sh inspect-noncompliant --limit 100`
   - Para blast radius controlado, acotar por `--created-after/--created-before` o `--id-after/--id-before`.
2. **Remediacion por lotes (dry-run por defecto)**
   - Dry-run: `scripts/outbox-replay-audit-compliance-tool.sh remediate-noncompliant --created-after '2026-03-01T00:00:00Z' --limit 50`
   - Apply: `scripts/outbox-replay-audit-compliance-tool.sh remediate-noncompliant --created-after '2026-03-01T00:00:00Z' --limit 50 --apply --actor oncall.sre --ticket INC-9001 --set-actor migration.legacy --set-ticket LEGACY-IMPORT`
   - En apply, `--actor` y `--ticket` son obligatorios; `--ticket` y `--set-ticket` se validan con `OUTBOX_REPLAY_TICKET_PATTERN`; la ejecucion registra una fila de auditoria en `outbox_replay_audit` para trazabilidad de cambio (`operation_type='requeue'` + marcador `template_filter='compliance_remediate_noncompliant'`).
   - Seguridad operacional: antes de mutar informa `scope_noncompliant_total`; luego muestra warnings claros de APPLY, actor/ticket, y declara override break-glass (`auth.outbox_replay_audit_maintenance_*`) acotado a la transaccion de remediacion.
3. **Validacion del constraint (dry-run primero)**
   - Pre-check: `scripts/outbox-replay-audit-compliance-tool.sh validate-constraint`
   - Validar en ventana controlada: `scripts/outbox-replay-audit-compliance-tool.sh validate-constraint --apply --lock-timeout-ms 10000 --statement-timeout-ms 900000`
4. **Posture report (single-command gate)**
     - Operador: `scripts/outbox-replay-audit-compliance-tool.sh status`
     - Verificacion de drift (runtime app fuera de maintenance + operadores dentro): `scripts/outbox-replay-audit-compliance-tool.sh status --app-role auth_app_runtime --operator-role ops_replay_oncall --operator-role ops_replay_admin`
     - Alternativa con lista CSV de operadores: `scripts/outbox-replay-audit-compliance-tool.sh status --format json --app-role auth_app_runtime --operator-role ops_replay_oncall,ops_replay_admin`
     - CI/manual gate: `scripts/outbox-replay-audit-compliance-tool.sh status --format json`
      - Gate estricto (exit no-cero si no cumple readiness): `scripts/outbox-replay-audit-compliance-tool.sh status --format json --require-release-ready`
      - Campos esperados: `constraint_exists`, `constraint_validated`, `append_only_triggers_present`, `historical_noncompliant_total`, `recent_apply_total`, `maintenance_role_name`, `maintenance_role_exists`, `current_user_is_maintenance_member`, `app_role_checked`, `app_role_is_maintenance_member`, `operator_roles_checked`, `operator_roles_missing_membership_count`, `operator_roles_missing_membership` (CSV legacy), `operator_roles_missing_membership_list` (JSON array), `release_ready`.
      - Ejemplo de drift accionable:
        - Texto: `operator_roles_missing_membership_count=2` + `operator_roles_missing_membership=ops_replay_admin,ops_replay_oncall`
        - JSON: `"operator_roles_missing_membership_count": 2, "operator_roles_missing_membership": "ops_replay_admin,ops_replay_oncall", "operator_roles_missing_membership_list": ["ops_replay_admin", "ops_replay_oncall"]`
     - Regla de `release_ready` sin flags nuevas: mantiene compatibilidad historica (tabla/constraint/triggers/historico conforme y `maintenance_role_exists=true`; `current_user_is_maintenance_member` se reporta separado).
     - Regla de `release_ready` con `--app-role`/`--operator-role`: ademas exige que `app_role_is_maintenance_member=false` y `operator_roles_missing_membership_count=0`.
      - Compatibilidad: sin `--require-release-ready`, el comando mantiene el comportamiento historico.
      - Workflow manual: ejecutar `replay-audit-compliance-manual` y proveer DB via input `database_url` o secret `OUTBOX_REPLAY_AUDIT_DATABASE_URL`; siempre adjunta `status.json` + `status.log` como artifact.
      - Inputs opcionales del workflow para governance estricto: `app_role` -> `--app-role`, `operator_roles` (CSV) -> `--operator-role`, `maintenance_role` -> `PGOPTIONS='-c auth.outbox_replay_audit_maintenance_role=<role>'`.
      - Ejemplo dispatch estricto: `gh workflow run replay-audit-compliance-manual.yml -f strict_gate=true -f app_role=auth_app_runtime -f operator_roles=ops_replay_oncall,ops_replay_admin -f maintenance_role=outbox_replay_maintainer`.
5. **Post-validacion**
   - Confirmar `convalidated=true` y `noncompliant_total=0`.
   - Conservar evidencia (salidas de inspect/remediate/validate + ticket de cambio).

### Abort / rollback guidance

- Si hay filas no conformes, abortar validacion y volver a remediar por lotes pequenos.
- Si falla por lock timeout, cancelar ventana y reintentar fuera de pico (o ampliar timeout).
- Si un remediate apply uso valores incorrectos, revertir con update acotado por IDs/ventana (siempre con override break-glass explicito en transaccion controlada) y repetir `inspect-noncompliant` antes de validar.

Nota: el motivo exacto `token_rotation_error` vive en auditoria (`audit_events`). En Prometheus, la señal equivalente de runtime se agrega como `reason="internal"`.

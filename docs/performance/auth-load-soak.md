# Auth load/soak evidence (manual)

Artifacts para generar evidencia reproducible de rendimiento/soak alineada al PRD, sin agregar carga pesada al pipeline de CI por defecto.

## Cobertura de escenarios

- `POST /v1/auth/login`
- `POST /v1/auth/token/refresh`
- `GET /v1/auth/me` (antes y despues de refresh con token autenticado)

Cada iteracion ejecuta el flujo critico:

1. login valido,
2. `me` autenticado con access token inicial,
3. refresh rotatorio,
4. `me` autenticado con access token rotado.

## KPI gates

Los umbrales por defecto se toman del PRD cuando existen:

- `login_p95_ms <= 300` (`PRD` seccion 3 y 14.4).
- `refresh_p95_ms <= 200` (`PRD` seccion 3 y 14.4).
- `error_rate <= 0.01` (`PRD` seccion 3).
- `throughput_rps >= 200` (`PRD` seccion 9 y 14.4).
- `me_p95_ms <= 250` (guardrail operativo para el flujo critico, no KPI explicito del PRD).

Puedes sobreescribir todos los umbrales por variables de entorno para calibrar por entorno:

- `AUTH_PERF_LOGIN_P95_MS`
- `AUTH_PERF_REFRESH_P95_MS`
- `AUTH_PERF_ME_P95_MS`
- `AUTH_PERF_MAX_ERROR_RATE`
- `AUTH_PERF_MIN_THROUGHPUT_RPS`

## Requisitos

- `k6`
- `python3`
- API de auth corriendo y accesible desde `AUTH_BASE_URL`
- Usuario de prueba valido sin MFA obligatorio

Variables requeridas:

- `AUTH_BASE_URL` (ej. `http://127.0.0.1:8080`)
- `AUTH_PERF_EMAIL`
- `AUTH_PERF_PASSWORD`

## Ejecucion

Load nominal (default):

```bash
AUTH_BASE_URL=http://127.0.0.1:8080 \
AUTH_PERF_EMAIL=perf.user@example.com \
AUTH_PERF_PASSWORD='replace_me' \
scripts/perf/run-auth-load-soak.sh load
```

Soak:

```bash
AUTH_BASE_URL=http://127.0.0.1:8080 \
AUTH_PERF_EMAIL=perf.user@example.com \
AUTH_PERF_PASSWORD='replace_me' \
scripts/perf/run-auth-load-soak.sh soak
```

Ambos:

```bash
AUTH_BASE_URL=http://127.0.0.1:8080 \
AUTH_PERF_EMAIL=perf.user@example.com \
AUTH_PERF_PASSWORD='replace_me' \
scripts/perf/run-auth-load-soak.sh both
```

## Salidas (evidencia)

Por defecto en `artifacts/perf/`:

- `k6-summary-load.json` y/o `k6-summary-soak.json`: salida raw de k6.
- `kpi-summary-load.json` y/o `kpi-summary-soak.json`: evaluacion por modo.
- `kpi-summary.json`: consolidado final con `overall_pass`.

El script retorna `exit 0` solo cuando todos los checks del modo solicitado pasan.

## Modos y configuracion de carga

Valores por defecto:

- load: `3m`, `200 req/s`, `preAllocatedVUs=200`, `maxVUs=600`.
- soak: `30m`, `80 req/s`, `preAllocatedVUs=100`, `maxVUs=300`.

Variables para ajustar por entorno:

- Load: `AUTH_PERF_LOAD_DURATION`, `AUTH_PERF_LOAD_RATE`, `AUTH_PERF_LOAD_PREALLOCATED_VUS`, `AUTH_PERF_LOAD_MAX_VUS`.
- Soak: `AUTH_PERF_SOAK_DURATION`, `AUTH_PERF_SOAK_RATE`, `AUTH_PERF_SOAK_PREALLOCATED_VUS`, `AUTH_PERF_SOAK_MAX_VUS`.

## CI seguro (manual/opt-in)

Se agrega workflow manual (`workflow_dispatch`) para evidencias bajo demanda:

- `.github/workflows/perf-evidence-manual.yml`

Este workflow no forma parte de `ci.yml` ni de gates obligatorios por PR.

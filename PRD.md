# PRD: API de Autenticacion Completa y Segura en Rust

- Version: `1.0`
- Estado: `Listo para refinamiento tecnico`
- Idioma: `ES`

## 1) Contexto y problema

La plataforma necesita un sistema de login robusto que cubra ciclo completo de identidad, no solo autenticacion basica. Los riesgos de una implementacion incompleta incluyen account takeover, secuestro de sesion, reuse de refresh token sin deteccion y falta de trazabilidad.

## 2) Objetivo del producto

- Proveer una API de autenticacion para web y mobile con flujos end-to-end.
- Reducir riesgo de compromiso de cuenta con controles preventivos y detectivos.
- Habilitar decisiones de release con gates tecnicos verificables (`Go/No-Go`).

## 3) Objetivos medibles (KPIs)

- Tasa de login exitoso en usuarios validos: `>98%`.
- Latencia p95 `POST /v1/auth/login`: `<300ms`.
- Latencia p95 `POST /v1/auth/token/refresh`: `<200ms`.
- Error rate en carga nominal: `<1%`.
- Vulnerabilidades abiertas `High/Critical` en auth al release: `0`.
- Cobertura de pruebas en auth core: `>=85%` lineas y `>=95%` en tokens/sesiones.

## 4) Alcance

### Incluye

- Registro con email y password.
- Verificacion de email.
- Login con password.
- MFA con TOTP y backup codes.
- Access token corto + refresh token rotatorio.
- Deteccion de reuse de refresh token.
- Logout actual y logout global.
- Forgot/reset/change password.
- Gestion de sesiones por dispositivo.
- Auditoria de eventos y alertas de seguridad.

### No incluye en v1

- Login social OAuth.
- Passkeys/WebAuthn.
- SSO empresarial (SAML/OIDC IdP).
- Motor de riesgo con ML.

## 5) Actores

- Usuario final.
- Cliente web/mobile.
- Equipo de soporte y seguridad.
- Proveedor de correo transaccional.
- Sistema de observabilidad/SIEM.

## 6) Flujos completos (end-to-end)

### F1 Registro y verificacion de email

1. Usuario envia `email + password` a `POST /v1/auth/register`.
2. Sistema crea cuenta en estado `PENDING_VERIFICATION`.
3. Sistema envia token de verificacion de un solo uso (TTL `24h`).
4. Usuario confirma en `POST /v1/auth/verify-email`.
5. Cuenta pasa a `ACTIVE`.

### F2 Login con password

1. Usuario envia credenciales a `POST /v1/auth/login`.
2. Sistema valida password, estado de cuenta, rate limit y lockout.
3. Si MFA no esta habilitado, emite tokens.
4. Si MFA esta habilitado, retorna challenge para paso adicional.

### F3 MFA (TOTP) onboarding

1. Usuario autenticado inicia enrolamiento MFA (`POST /v1/auth/mfa/enroll`).
2. API retorna secreto TOTP y metadata de setup.
3. Usuario confirma codigo (`POST /v1/auth/mfa/activate`).
4. API activa factor y entrega backup codes de un solo uso.

### F4 Login con MFA

1. Login valido con MFA habilitado retorna `mfa_required` + `challenge_id`.
2. Usuario envia TOTP o backup code a `POST /v1/auth/mfa/verify`.
3. API valida challenge y emite tokens.

### F5 Refresh rotatorio y deteccion de reuse

1. Cliente llama `POST /v1/auth/token/refresh` con refresh token vigente.
2. Sistema valida token, sesion y contexto.
3. Sistema invalida refresh actual y emite nuevo par de tokens.
4. Si detecta reuse de refresh invalidado, marca `COMPROMISED`, revoca sesiones y registra evento critico.

### F6 Logout y sesiones

1. `POST /v1/auth/logout` revoca sesion actual.
2. `POST /v1/auth/logout-all` revoca todas las sesiones activas.
3. `GET /v1/auth/sessions` lista sesiones por dispositivo.
4. `DELETE /v1/auth/sessions/{session_id}` revoca sesion especifica.

### F7 Recuperacion y cambio de password

1. `POST /v1/auth/password/forgot` responde de forma neutra.
2. Sistema envia token de reset de un solo uso (TTL `15m`).
3. `POST /v1/auth/password/reset` actualiza password.
4. `POST /v1/auth/password/change` requiere password actual valida.
5. Reset/cambio invalida sesiones segun politica.

### F8 Respuesta a incidentes

1. Lock temporal tras intentos fallidos repetidos.
2. Alertas por login sospechoso, cambio de password y compromiso de sesion.
3. Auditoria obligatoria para eventos criticos con `trace_id`.

## 7) Requisitos funcionales

- `RF-01`: Registro con email unico y password fuerte.
- `RF-02`: Verificacion de email obligatoria para login.
- `RF-03`: Login seguro con mensajes anti-enumeracion.
- `RF-04`: Soporte de MFA TOTP con onboarding y desactivacion segura.
- `RF-05`: Backup codes de un solo uso.
- `RF-06`: Emision de access token corto + refresh token rotatorio.
- `RF-07`: Rotacion atomica de refresh token.
- `RF-08`: Deteccion y manejo de reuse de refresh token.
- `RF-09`: Logout de sesion actual y logout global.
- `RF-10`: Forgot/reset password con tokens one-time.
- `RF-11`: Cambio de password autenticado.
- `RF-12`: Gestion de sesiones por dispositivo.
- `RF-13`: Auditoria de eventos criticos con `trace_id`.
- `RF-14`: Rate limiting por IP y por cuenta.
- `RF-15`: Lockout temporal y backoff progresivo.
- `RF-16`: Contrato de error consistente.
- `RF-17`: Versionado de API (`/v1`).

## 8) Requisitos de seguridad

- Password hashing con `Argon2id` + salt unico + pepper en secreto de servidor.
- Access token JWT firmado (`EdDSA` o `ES256`), TTL `10-15 min`.
- Refresh token opaco aleatorio (`>=256 bits`), hasheado en DB, un solo uso.
- Rotacion obligatoria con deteccion de reuse.
- Cookies web: `HttpOnly`, `Secure`, `SameSite` segun politica.
- Proteccion CSRF en refresh/logout si se usan cookies.
- TLS obligatorio y secretos cifrados en reposo.
- Rotacion de claves y segregacion por entorno.
- Auditoria inmutable de eventos de auth.
- Baseline recomendado: OWASP ASVS L2.

## 9) Requisitos no funcionales

- Disponibilidad objetivo: `99.9%`.
- Escalabilidad minima: `200 req/s` sostenidos en endpoints criticos.
- Consistencia fuerte para revocacion de sesiones/tokens.
- Observabilidad con metricas, logs estructurados y trazas distribuidas.
- Compatibilidad backward en contratos de `v1`.

## 10) Arquitectura de referencia (alto nivel)

- API: `Rust + Axum + Tokio`.
- Dominio: reglas de autenticacion/sesion/MFA desacopladas de transporte.
- Persistencia: `PostgreSQL` para identidad, sesiones, tokens y auditoria.
- Cache y controles efimeros: `Redis` para rate limit y short-lived state.
- Correo transaccional para verificacion y reset.
- Observabilidad: `OpenTelemetry + tracing`.

## 11) Contrato API v1

| Metodo | Endpoint | Proposito |
|---|---|---|
| POST | `/v1/auth/register` | Registro de usuario |
| POST | `/v1/auth/verify-email` | Verificacion de email |
| POST | `/v1/auth/login` | Login inicial |
| POST | `/v1/auth/mfa/enroll` | Iniciar enrolamiento MFA |
| POST | `/v1/auth/mfa/activate` | Activar MFA |
| POST | `/v1/auth/mfa/verify` | Resolver challenge MFA |
| POST | `/v1/auth/mfa/disable` | Desactivar MFA con step-up |
| POST | `/v1/auth/token/refresh` | Rotar tokens |
| POST | `/v1/auth/logout` | Cerrar sesion actual |
| POST | `/v1/auth/logout-all` | Cerrar todas las sesiones |
| GET | `/v1/auth/sessions` | Listar sesiones activas |
| DELETE | `/v1/auth/sessions/{session_id}` | Revocar sesion especifica |
| POST | `/v1/auth/password/forgot` | Solicitar reset |
| POST | `/v1/auth/password/reset` | Ejecutar reset |
| POST | `/v1/auth/password/change` | Cambiar password autenticado |
| GET | `/v1/auth/me` | Estado de sesion actual |

### Codigos de respuesta esperados

- `200/201`: exito.
- `400`: validacion.
- `401`: no autenticado/token invalido.
- `403`: no autorizado por estado/politica.
- `404`: recurso no encontrado.
- `409`: conflicto.
- `429`: rate limited.
- `500`: error interno con `trace_id`.

## 12) Modelo de datos minimo

- `users`: id, email, status, email_verified_at, created_at.
- `credentials`: user_id, password_hash, password_changed_at.
- `mfa_factors`: user_id, type, secret_encrypted, enabled_at.
- `mfa_backup_codes`: user_id, code_hash, used_at.
- `sessions`: id, user_id, device_info, ip, status, last_seen_at.
- `refresh_tokens`: session_id, token_hash, expires_at, revoked_at, replaced_by.
- `verification_tokens`: user_id, token_hash, expires_at, used_at.
- `password_reset_tokens`: user_id, token_hash, expires_at, used_at.
- `audit_events`: actor, event_type, metadata, created_at, trace_id.

## 13) Observabilidad y operacion

- Logs estructurados por evento con actor, resultado, IP y user-agent.
- Metricas por endpoint: throughput, latencia p95, error rate.
- Metricas de seguridad: intentos fallidos, lockouts, reuse detectado, reset events.
- Trazabilidad end-to-end con `trace_id`.
- Alertas para picos de `401/429`, reuse events y degradacion p95.

## 14) Plan de pruebas (obligatorio)

- Objetivo: validar seguridad, correctitud funcional, resiliencia y rendimiento de toda la API de autenticacion antes de liberar.
- Enfoque: piramide de pruebas con mayor peso en unitarias e integracion, y E2E selectivo en flujos criticos.
- Criterio rector: ningun cambio de auth se libera si falla una prueba `P0` de seguridad o sesion.

### 14.1 Estrategia por capas

- Unitarias (servicios de dominio): validacion de passwords, estados de cuenta, expiracion de tokens, lockout.
- Integracion (API + DB + Redis + correo fake): flujos completos en entorno controlado.
- Contrato (OpenAPI): request/response, codigos de error y backward compatibility.
- E2E (cliente simulado): journeys completos de usuario.
- Seguridad (SAST/DAST + pruebas manuales focalizadas): abuso y ataque.
- No funcionales: carga, estres, soak y resiliencia.

### 14.2 Cobertura minima por flujo (P0/P1)

#### F1 Registro + verificacion

- P0: registro valido crea usuario `PENDING_VERIFICATION`.
- P0: token de verificacion expira y no puede reutilizarse.
- P1: reenvio de verificacion con rate-limit.

#### F2 Login + MFA

- P0: login valido emite tokens (sin MFA).
- P0: login con MFA retorna challenge y exige verificacion.
- P0: error generico para credenciales invalidas (no enumera usuarios).

#### F3 Refresh rotatorio

- P0: refresh valido rota token y revoca anterior.
- P0: reuse de refresh revocado marca sesion comprometida y fuerza revocacion.

#### F4 Logout

- P0: logout actual invalida refresh/sesion actual.
- P0: logout-all invalida todas las sesiones activas.

#### F5 Forgot/Reset

- P0: forgot responde neutro exista o no el email.
- P0: reset valido invalida sesiones previas.

#### F6 Change password

- P0: requiere password actual valida.
- P0: password nueva cumple politica y actualiza hash.

#### F7 Sesiones

- P1: listar sesiones devuelve metadatos esperados.
- P1: revocacion por `session_id` bloquea uso posterior.

#### F8 Respuesta a incidentes

- P0: lock temporal tras intentos fallidos repetidos.
- P0: evento de auditoria obligatorio en login, reset, cambio de password, revoke y compromise.

### 14.3 Pruebas de seguridad (minimo release gate)

- Brute force y credential stuffing (rate-limit + lockout efectivos).
- Replay y reuse de refresh token.
- CSRF en refresh/logout si se usan cookies.
- Fijacion de sesion y secuestro de token.
- SQLi/NoSQLi, validacion de inputs y cabeceras.
- Verificacion de configuracion de cookies (`HttpOnly`, `Secure`, `SameSite`).
- Revision de criptografia: `Argon2id`, parametros vigentes, rotacion de secretos y manejo de claves.
- Mapeo contra OWASP ASVS L2 (checklist trazable por requisito).

### 14.4 Pruebas no funcionales

- Rendimiento:
  - p95 `POST /auth/login` `<300ms`.
  - p95 `POST /auth/token/refresh` `<200ms`.
- Carga sostenida: al menos `200 req/s` en endpoints criticos con error rate `<1%`.
- Estres: identificar punto de degradacion controlada.
- Soak (`8-24h`): detectar fugas de memoria, crecimiento de latencia o inestabilidad.
- Resiliencia:
  - caida temporal de Redis (degradacion controlada);
  - fallo de proveedor de correo (reintentos/idempotencia);
  - desfase de reloj entre nodos (tolerancia de validacion JWT).

### 14.5 Automatizacion CI/CD

- En cada PR:
  - unitarias + integracion + contrato OpenAPI;
  - SAST + scan de dependencias con bloqueo en `High/Critical`;
  - cobertura minima recomendada en auth core: `>=85%` lineas y `>=95%` en logica de tokens/sesiones.
- Nightly:
  - E2E completos;
  - DAST;
  - carga basica de regresion.
- Pre-release:
  - suite P0 completa + seguridad + benchmark de latencia.

### 14.6 Criterios de salida (Go/No-Go)

- Go solo si:
  - `100%` pruebas `P0` en verde;
  - `0` vulnerabilidades `Critical/High` sin mitigacion aprobada;
  - KPIs de latencia y error-rate cumplidos;
  - auditoria/traceabilidad verificadas.
- No-Go si falla cualquier control de rotacion/revocacion/reuse de tokens.

### 14.7 Validacion de completitud del flujo (MVP vs Parcial vs Completa-Segura)

- Cada flujo `F1..F8` debe tener 4 evidencias:
  1. endpoint implementado,
  2. prueba automatizada passing,
  3. evento de auditoria emitido,
  4. control `P0` validado.
- Clasificacion `MVP`: cubre flujos base, pero faltan controles avanzados o cobertura total.
- Clasificacion `Parcial`: cubre mas que MVP, pero falla algun control critico o falta evidencia de flujo.
- Clasificacion `Completa-Segura`: `100%` `F1..F8` + `100%` P0 + `0` hallazgos `High/Critical`.
- Regla de release: si falta evidencia en cualquier flujo critico, estado `NO_GO`.

### 14.8 Matriz QA ejecutable minima (base para CI)

| ID | Tipo | Flujo | Resultado esperado |
|---|---|---|---|
| E2E-AUTH-001 | E2E | F1->F8 | Journey completo exitoso con auditoria en cada hito |
| INT-AUTH-010 | Integracion | F1 | Registro crea `PENDING_VERIFICATION` |
| INT-AUTH-011 | Integracion | F1 | Verificacion activa cuenta |
| INT-AUTH-020 | Integracion | F2 | Login valido emite tokens |
| INT-AUTH-021 | Integracion | F2 | Login invalido no enumera usuario |
| INT-AUTH-030 | Integracion | F3 | Refresh rota token correctamente |
| INT-AUTH-031 | Integracion | F3 | Reuse detectado revoca sesiones |
| INT-AUTH-040 | Integracion | F4 | Logout actual invalida sesion |
| INT-AUTH-041 | Integracion | F4 | Logout-all revoca todas |
| INT-AUTH-050 | Integracion | F5 | Forgot respuesta neutra |
| INT-AUTH-051 | Integracion | F5 | Reset invalida sesiones previas |
| INT-AUTH-060 | Integracion | F6 | Change password exige password actual |
| INT-AUTH-070 | Integracion | F7 | Listado y revoke por `session_id` |
| SEC-AUTH-100 | Seguridad | F2/F8 | Rate-limit y lockout efectivos |
| SEC-AUTH-101 | Seguridad | F3 | Replay/reuse bloqueado |
| SEC-AUTH-102 | Seguridad | F3/F4 | CSRF mitigado en flujos cookie-based |
| PERF-AUTH-200 | Performance | F2 | p95 login en umbral |
| PERF-AUTH-201 | Performance | F3 | p95 refresh en umbral |

## 15) Roadmap sugerido

- Fase 1 (MVP seguro): F1, F2, F3 basico, F4, F5, F6 + observabilidad base.
- Fase 2 (Hardening): MFA completo, sesiones por dispositivo, reuse detection robusto, alertas.
- Fase 3 (Completa-Segura): cobertura total F1..F8, resiliencia avanzada, gates 14.6 + 14.7.

## 16) Riesgos y mitigaciones

- Riesgo: complejidad de rotacion/revocacion atomica de refresh token.
  - Mitigacion: pruebas de concurrencia y transacciones con garantias.
- Riesgo: lockouts falsos en IP compartidas.
  - Mitigacion: rate-limit combinado por IP + cuenta + reputacion.
- Riesgo: deuda en trazabilidad de incidentes.
  - Mitigacion: eventos de auditoria obligatorios desde sprint 1.

## 17) Definition of Done del PRD

- Flujos `F1..F8` definidos y trazables a requisitos.
- Contrato API `v1` definido funcionalmente.
- Requisitos de seguridad y no funcionales medibles.
- Plan de pruebas `14` y validacion de completitud `14.7` aprobados.
- Matriz QA base lista para automatizacion en CI.

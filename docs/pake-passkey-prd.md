# PAKE + Passkeys PRD

## Vision

- Migrar auth a un modelo challenge-based donde password nunca viaje como secreto reusable y donde passkeys sean el camino passwordless recomendado, pero opt-in.
- Mantener compatibilidad operacional con la plataforma actual: sesiones, refresh rotation, auditoria, controles anti-abuso, riesgo y observabilidad ya presentes en el repo.
- Llegar a una arquitectura donde `GET /v2/auth/methods` descubra el mejor metodo por cuenta/dispositivo y donde password clasica quede solo como fallback temporal.

Docs complementarios para implementacion:

- `docs/pake-passkey-api-spec.md`
- `docs/pake-passkey-schema-and-ports.md`
- `docs/pake-passkey-rollout-and-operations.md`

## Problema

- Hoy `POST /v1/auth/login` sigue siendo password clasica request/response: el cliente manda `email + password` y el servidor valida Argon2 localmente en `src/api/handlers.rs:691` y `src/modules/auth/application.rs:1352`.
- El modelo actual depende de `credentials.password_hash` (`migrations/0002_add_credentials.sql:1`) y de un `INNER JOIN` obligatorio para leer usuarios desde auth (`src/adapters/postgres.rs:159`), o sea: password hash es parte estructural del login vigente.
- Ya existen passkeys en `/v1/auth/passkey/*` (`src/main.rs:443`) con persistencia de `passkey_credentials` y `passkey_challenges` (`migrations/0017_add_passkey_credentials.sql:1`, `migrations/0018_add_passkey_challenges.sql:1`), pero estan separadas del login password y no hay discovery unificado de metodos.
- El riesgo actual es pragmatico pero basico: reglas configurables por CIDR, user-agent y dominio (`src/adapters/risk.rs:25`), no un flujo challenge-based moderno para password.

## Objetivos

- Introducir password login basado en OPAQUE o PAKE moderno equivalente, con handshake `start/finish` y secreto resistente a phishing/replay en el transporte de credenciales.
- Unificar descubrimiento de metodos de autenticacion para password challenge-based y passkeys opt-in.
- Reusar sesiones, refresh tokens, auditoria y controles de riesgo sin rehacer toda la plataforma.
- Mantener rollout incremental con compatibilidad v1 mientras se migra cliente, observabilidad y soporte.
- Reducir exposicion de password clasica hasta poder deprecar `POST /v1/auth/login`.

## No objetivos

- Reescribir el stack completo de identidad o cambiar JWT/refresh rotation.
- Hacer passkeys obligatorias para todas las cuentas desde el dia 1.
- Implementar crypto casera. Si se adopta OPAQUE, debe ser via libreria/servicio auditado, no inventando protocolo en `src/modules/auth/application.rs`.
- Romper contratos v1 existentes durante las primeras fases.

## Stakeholders

- Backend/auth: dueno de `src/modules/auth`, `src/api`, `src/adapters`.
- Frontend/web-mobile: clientes que hoy consumen `/v1/auth/login` y `/v1/auth/passkey/*`.
- Security/platform: responsables de decisiones criptograficas, rollout, runbooks y posture.
- SRE/observabilidad: responsables de readiness, metricas y alertas ya documentadas en `docs/observability-auth-refresh.md`.
- Support/ops: manejo de edge cases de cuentas legacy, recovery y deprecacion gradual.

## Estado actual basado en el repo

### Endpoints y runtime

- `POST /v1/auth/login` esta expuesto en `src/main.rs:438` y resuelve password directa en `src/api/handlers.rs:691`.
- Passkeys ya existen como feature flag con `PASSKEY_ENABLED`, `PASSKEY_RP_ID` y `PASSKEY_RP_ORIGIN` (`src/config.rs:167`, `src/main.rs:491`).
- El runtime ya soporta estado transitorio server-side para ceremonias multi-instancia con `passkey_challenges` y janitor (`src/adapters/postgres.rs:968`, `src/main.rs:323`, `src/health.rs:154`).

### Dominio y persistencia

- `users` guarda estado de cuenta y `credentials` guarda `password_hash` (`migrations/0001_init_auth_core.sql:1`, `migrations/0002_add_credentials.sql:1`).
- `UserRepository` expone `find_by_email`, `find_by_id`, `create_pending_user` y `update_password`, todos pensados alrededor de password hash (`src/modules/auth/ports.rs:11`).
- Passkeys tienen puertos separados: `PasskeyCredentialRepository` y `PasskeyChallengeRepository` (`src/modules/auth/ports.rs:175`, `src/modules/auth/ports.rs:215`).

### Flujo de login actual

- Login password verifica lockout/abuse, busca usuario, parsea hash Argon2 y compara password (`src/modules/auth/application.rs:1361`).
- Si la cuenta esta activa, reusa `evaluate_login_risk_policy`, MFA challenge y emision de sesion/refresh (`src/modules/auth/application.rs:1403`, `src/modules/auth/application.rs:1499`, `src/modules/auth/application.rs:1560`).
- Login passkey ya es challenge-based: `passkey_login_start` emite `flow_id + options` y `passkey_login_finish` consume el challenge one-time (`src/modules/auth/application.rs:1130`, `src/modules/auth/application.rs:1213`).

### Observabilidad disponible

- Ya existen eventos de auditoria y metricas para passkeys, refresh y riesgo (`README.md:342`, `docs/observability-auth-refresh.md:37`).
- Esto habilita medir rollout de v2 sin arrancar de cero, pero faltan metricas equivalentes para password PAKE.

## Arquitectura objetivo

- `v2 auth` expone discovery de metodos por identificador y devuelve capacidades: `password_pake`, `passkey`, `mfa_required`, `account_recovery`.
- Password deja de usar `email + password` en un solo POST y pasa a handshake `start/finish` con estado transitorio persistido en `auth_flows`.
- El secreto de password se representa como credencial OPAQUE/PAKE en `opaque_credentials`, separada de `credentials` para permitir convivencia y rollback.
- Passkeys siguen usando WebAuthn, pero se integran al mismo discovery y al mismo concepto de `auth_flows` para observabilidad, TTL y consumo one-time.
- Riesgo, lockout y auditoria se ejecutan en ambos caminos antes de emitir sesion, no despues.
- La emision final de tokens sigue reusando `issue_session_tokens` o equivalente para no romper `sessions`, `refresh_tokens` ni JWKS (`src/modules/auth/application.rs:1560`, `migrations/0001_init_auth_core.sql:10`).

## Requerimientos funcionales

- El cliente debe poder consultar metodos disponibles por cuenta/canal sin revelar mas estado del necesario.
- El cliente debe poder iniciar login password challenge-based sin enviar password reusable al endpoint final.
- El servidor debe persistir estado de handshake con TTL, consumo one-time, trazabilidad y soporte multi-instancia.
- Debe coexistir con passkeys opt-in ya registradas en `passkey_credentials`.
- Debe soportar upgrade progresivo: cuenta con password legacy puede seguir en v1 o convertirse a `opaque_credentials` al primer login/cambio de password, segun fase.
- Debe mantener compatibilidad con MFA step-up y riesgo existente.
- Debe emitir auditoria y metricas por `methods`, `start`, `finish`, `upgrade`, `fallback_v1`, `deprecated_v1`.

## Requerimientos no funcionales

- Nada de crypto custom. Libreria o boundary criptografico auditado, con decision documentada y threat model minimo.
- Latencia objetivo similar al baseline actual del repo: `POST /v1/auth/login` ya tiene objetivo p95 `<300ms` en `PRD.md:19`; v2 no puede romper ese orden de magnitud sin justificacion.
- Multi-instancia desde el dia 1, igual que passkeys hoy.
- Contratos anti-enumeracion consistentes entre `methods`, `start` y `finish`.
- Rollout reversible: feature flags, canary por cliente y fallback controlado a v1.
- Observabilidad operable: dashboards, alertas y readiness sin inventar otro stack paralelo.

## KPIs y SLOs

- Adopcion v2: porcentaje de logins que entran por `/v2/auth/*` sobre total.
- Adopcion passkey opt-in: porcentaje de usuarios activos con al menos una fila en `passkey_credentials` y porcentaje de logins exitosos por passkey.
- Migracion password moderna: porcentaje de cuentas activas con `opaque_credentials` sobre cuentas con password habilitada.
- Calidad de login: success rate >= baseline actual del producto; objetivo inicial `>98%` alineado con `PRD.md:19`.
- Performance: p95 de `password/login/start` y `password/login/finish` dentro de presupuesto combinado <= 350 ms como meta inicial de rollout; ajustar tras evidencia real.
- Disponibilidad auth v2: SLO mensual >= 99.95% sin degradar el objetivo general de auth.
- Seguridad operacional: 0 incidentes de downgrade silencioso a password clasica fuera de politicas aprobadas.

## Riesgos y decisiones

- Decision: separar `opaque_credentials` de `credentials` para evitar migracion big-bang y conservar rollback rapido.
- Decision: generalizar estado transitorio a `auth_flows` en vez de seguir agregando tablas por ceremonia; si no, el repo termina con un quilombo de tablas efimeras por feature.
- Riesgo: libreria OPAQUE en Rust puede no tener madurez/ergonomia suficiente para produccion; alternativa pragmatica es SRP/PAKE moderno auditado o boundary externo dedicado. Tradeoff: mas simplicidad operativa versus mayor superficie de integracion.
- Riesgo: discovery de metodos puede filtrar existencia de cuenta si el contrato no es neutro. Hay que mantener el mismo criterio anti-enumeracion ya usado en register/forgot-password.
- Riesgo: usuarios con MFA habilitado pero sin passkey pueden experimentar mas friccion si riesgo exige challenge. Hoy ya existe el caso `challenge_without_mfa` que termina bloqueando (`src/modules/auth/application.rs:1530`); v2 debe resolver esto con una politica mas clara.
- Riesgo: migrar password sin story de recovery y cambio de password deja cuentas legacy atrapadas.

## Roadmap resumido

### 0-2 semanas

- Acordar decision criptografica y shape de tablas `opaque_credentials` + `auth_flows`.
- Definir contratos `GET /v2/auth/methods`, `POST /v2/auth/password/login/start`, `POST /v2/auth/password/login/finish`.
- Instrumentar eventos/metricas nuevas y feature flags de rollout.

### 30 dias

- Implementar persistencia, puertos y runtime v2 detras de flag.
- Integrar discovery de metodos y login PAKE para clientes piloto.
- Reusar auditoria, lockout, riesgo, MFA y sesiones existentes.

### 60-90 dias

- Migrar clientes principales a v2.
- Habilitar upgrade de cuentas password legacy hacia `opaque_credentials`.
- Empezar deprecacion de `POST /v1/auth/login` cuando adopcion, SLOs y recovery esten en verde.

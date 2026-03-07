# PAKE + Passkeys Migration Plan

Docs complementarios de detalle:

- `docs/pake-passkey-api-spec.md`
- `docs/pake-passkey-schema-and-ports.md`
- `docs/pake-passkey-rollout-and-operations.md`

## Principios de migracion

- Sin big-bang. v1 y v2 conviven hasta que haya evidencia de adopcion y estabilidad.
- Reusar lo que ya funciona: `sessions`, `refresh_tokens`, auditoria, lockout, riesgo, passkeys y health checks.
- No meter crypto casera. OPAQUE/PAKE vive atras de un boundary testeable y auditable.
- Mantener anti-enumeracion en discovery, start y finish.
- Persistir todo challenge server-side para despliegues multi-instancia, igual que hoy con `passkey_challenges`.
- Hacer cambios minimos y reversibles sobre tablas actuales; migracion aditiva primero, remocion despues.

## Modelo de datos propuesto

### Nueva tabla `opaque_credentials`

Objetivo: desacoplar password moderna de `credentials`.

Columnas sugeridas:

- `user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE`
- `protocol TEXT NOT NULL` - `opaque_v1` o equivalente para versionar handshake.
- `credential_envelope BYTEA NOT NULL` - sobre OPAQUE real esto guarda envelope/export key material serializado; si la libreria usa otro formato, no improvisar.
- `server_public_key BYTEA NULL` - solo si la libreria/protocolo lo requiere.
- `kms_key_id TEXT NULL` - opcional si parte del material se protege con envelope encryption.
- `created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`
- `updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`
- `migrated_from_credentials_at TIMESTAMPTZ NULL`
- `last_verified_at TIMESTAMPTZ NULL`
- `deprecated_legacy_password_at TIMESTAMPTZ NULL`

Indices:

- PK por `user_id` alcanza para lookup principal.
- Index opcional por `updated_at` para reporting de migracion.

### Nueva tabla `auth_flows`

Objetivo: unificar estado transitorio para password PAKE y, en una segunda iteracion, tambien para passkeys.

Columnas sugeridas:

- `flow_id TEXT PRIMARY KEY`
- `user_id UUID NULL REFERENCES users(id) ON DELETE CASCADE`
- `flow_kind TEXT NOT NULL` - `password_login`, `passkey_login`, `passkey_register`, futuro `recovery`, etc.
- `protocol TEXT NOT NULL` - `opaque_v1`, `webauthn_v1`, etc.
- `state JSONB NOT NULL`
- `status TEXT NOT NULL DEFAULT 'pending'` - `pending`, `consumed`, `expired`, `cancelled`
- `expires_at TIMESTAMPTZ NOT NULL`
- `consumed_at TIMESTAMPTZ NULL`
- `trace_id TEXT NULL`
- `client_fingerprint TEXT NULL`
- `created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`
- `updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`

Indices sugeridos:

- `(user_id, flow_kind, status)`
- `(expires_at)`
- `(flow_kind, created_at)`

### Cambios minimos a tablas actuales

- `credentials`: mantenerla intacta en fases 1-2. Agregar solo metadatos si hace falta reporting (`legacy_login_allowed`, `legacy_deprecation_at`), pero NO mezclar envelope OPAQUE aca.
- `passkey_challenges`: mantenerla como esta al inicio para no frenar rollout. Fase posterior: migrar gradualmente a `auth_flows`.
- `passkey_credentials`: sin cambios funcionales fuertes; opcional agregar `last_used_at` si hace falta KPI fino de adopcion.
- `users`: opcional agregar `preferred_auth_method` mas adelante; no es prerequisito para empezar.

## Puertos e interfaces nuevos sugeridos

Siguiendo el estilo hexagonal de `src/modules/auth/ports.rs`:

- `OpaqueCredentialRepository`
  - `find_by_user_id(user_id)`
  - `upsert_for_user(user_id, opaque_record, now)`
  - `mark_legacy_deprecated(user_id, now)`

- `AuthFlowRepository`
  - `issue(flow)`
  - `consume(flow_id, now)`
  - `cancel_for_user(user_id, flow_kind)`
  - `prune_expired(now)`

- `PasswordVerifierModern`
  - `start_login(account_context, client_capabilities)`
  - `finish_login(server_state, client_message)`
  - `create_or_upgrade_credential(password)`

- `AuthMethodDiscoveryService`
  - devuelve metodos/capacidades por identificador sin acoplar handlers a reglas de negocio.

- `LegacyPasswordFallbackPolicy`
  - decide cuando se permite seguir usando `credentials.password_hash`.

## Contrato API base v2

Los contratos son base; no hacen falta detalles binarios del protocolo en este doc, pero si el shape operativo.

### `GET /v2/auth/methods`

Objetivo: discovery de metodos disponibles para una identidad y un cliente.

Request sugerido:

```http
GET /v2/auth/methods?identifier=user@example.com
```

Response 200 sugerida:

```json
{
  "identifier_hint": "u***@example.com",
  "methods": [
    {
      "type": "password_pake",
      "version": "opaque_v1",
      "available": true
    },
    {
      "type": "passkey",
      "version": "webauthn_v1",
      "available": true
    }
  ],
  "recommended_method": "passkey",
  "legacy_v1_password_allowed": true
}
```

Notas:

- Si no se puede garantizar anti-enumeracion con `GET`, usar `POST` con body neutro y misma semantica.
- El contrato externo debe ser neutro para cuentas inexistentes o inactivas.

### `POST /v2/auth/password/login/start`

Objetivo: iniciar handshake PAKE y persistir flow.

Request sugerido:

```json
{
  "identifier": "user@example.com",
  "client_capabilities": {
    "supports_passkeys": true,
    "supports_pake": true
  }
}
```

Response 200 sugerida:

```json
{
  "flow_id": "9b2d...",
  "protocol": "opaque_v1",
  "server_message": {
    "opaque_message": "base64url..."
  },
  "expires_in": 300,
  "allowed_next": ["password_finish", "passkey"]
}
```

Notas:

- Debe aplicar lockout y riesgo basico antes de emitir challenge, igual que hoy en `src/modules/auth/application.rs:1361` y `src/modules/auth/application.rs:1139`.
- Si la cuenta no existe o no esta lista para v2, responder contrato neutro y decidir internamente si el finish terminara en error generico o en fallback controlado.

### `POST /v2/auth/password/login/finish`

Objetivo: cerrar handshake y, si corresponde, emitir sesion o MFA challenge.

Request sugerido:

```json
{
  "flow_id": "9b2d...",
  "client_message": {
    "opaque_message": "base64url..."
  },
  "device_info": "Firefox on Linux"
}
```

Response 200 autenticado:

```json
{
  "authenticated": true,
  "access_token": "...",
  "refresh_token": "...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

Response 200 con step-up:

```json
{
  "authenticated": false,
  "mfa_required": true,
  "challenge_id": "...",
  "message": "Additional verification required"
}
```

Errores esperados:

- `400/401` genericos para `invalid_or_expired_flow`, `invalid_credentials`, `invalid_client_message`.
- `429` para lockout.
- `503` solo si el boundary criptografico o storage no esta sano y la politica no permite fallback.

## Estrategia de compatibilidad con v1

- Mantener `POST /v1/auth/login` intacto al comienzo (`src/main.rs:438`).
- Introducir feature flags por cliente/canal para decidir si se usa `v2 methods + start/finish` o v1.
- Reusar exactamente la misma emision de sesiones/refresh al final del flujo exitoso para no duplicar semantica.
- Mantener passkeys v1 operativas mientras se define si se conservan sus endpoints o se agregan equivalentes `/v2/auth/passkey/*`.
- Permitir fallback explicito a v1 solo para cuentas/clientes aprobados; cada fallback debe quedar auditado.
- No tocar `credentials` ni borrar hashes legacy hasta cumplir criterios de salida.

## Fases de implementacion

### Primeras 2 semanas

- Cerrar decision criptografica: OPAQUE real o alternativa PAKE moderna viable en Rust con evidencia de mantenimiento.
- Diseñar migraciones DB para `opaque_credentials` y `auth_flows`.
- Crear puertos nuevos y contratos HTTP v2.
- Definir eventos de auditoria y metricas: `auth.password_pake.methods.*`, `start.*`, `finish.*`, `upgrade.*`, `fallback_v1.*`.
- Agregar documentacion operativa inicial y runbook de rollback.

### 30 dias

- Implementar adapters Postgres para `opaque_credentials` y `auth_flows`.
- Implementar servicio de discovery y login PAKE detras de flag.
- Integrar riesgo, lockout, MFA y emision de tokens reutilizando caminos existentes.
- Exponer `/v2/auth/methods`, `/v2/auth/password/login/start`, `/v2/auth/password/login/finish` para clientes piloto.
- Medir latencia, error rate y ratio de fallback a v1.

### 60-90 dias

- Migrar clientes web/mobile principales a v2.
- Habilitar upgrade progresivo de credenciales legacy a `opaque_credentials` en login exitoso, password change o forced re-auth.
- Integrar passkeys al discovery y, si suma claridad, mover challenges WebAuthn a `auth_flows`.
- Empezar bloqueo gradual de v1 por segmento, empezando por clientes internos/canary.
- Preparar comunicado de deprecacion y fecha limite para password clasica.

## Riesgos y edge cases

- Cuentas existentes sin `opaque_credentials` pero con `credentials.password_hash`: necesitan fallback o bootstrap de upgrade.
- Cuentas con MFA habilitado y riesgo `challenge` pero sin factor utilizable: hoy eso termina en bloqueo (`src/modules/auth/application.rs:1530`); v2 debe definir UX y recovery concretos.
- Flows expirados/reintentados/replayed: `auth_flows` debe ser one-time y auditable, igual que `passkey_challenges` hoy se consumen con `DELETE ... RETURNING` (`src/adapters/postgres.rs:1017`, `src/adapters/postgres.rs:1108`).
- Multi-tab y multi-device: iniciar un flow nuevo no debe invalidar de forma sorpresiva otros flows legitimos salvo politica explicita por usuario/metodo.
- Fallback silencioso a v1: es peligroso porque maquilla bugs en v2. Tiene que ser medido, auditado y acotado.
- Recovery/password reset: si se moderniza login pero reset sigue recreando `credentials` legacy sin `opaque_credentials`, vas a meter deuda nueva. Hay que alinear ambos caminos.
- Libreria/protocolo elegido: si la ergonomia o mantenimiento no da, mejor frenar y elegir alternativa seria antes que empujar crypto mediocre a produccion.

## Criterios de salida para deprecar password clasica

- >= 90% de logins password de clientes target entran por v2 durante al menos 30 dias.
- >= 95% de cuentas activas con password habilitada tienen `opaque_credentials`.
- Error rate de `password/login/finish` no supera baseline v1 durante 4 semanas consecutivas.
- Latencia combinada `start + finish` dentro de presupuesto acordado por 4 semanas.
- Fallback a v1 < 2% y justificado solo por clientes legacy identificados.
- Password reset/change ya crean o actualizan `opaque_credentials` por defecto.
- Dashboards, alertas, runbooks y soporte on-call estan en verde.
- Fecha de sunset de `POST /v1/auth/login` comunicada y con kill-switch reversible por ventana acotada.

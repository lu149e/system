# PAKE + Passkeys Schema and Ports

## Scope and status

- This is a target-state persistence and boundary spec, not a claim that the repo already has it.
- Current state still uses `users` + `credentials` for password login (`migrations/0001_init_auth_core.sql:1`, `migrations/0002_add_credentials.sql:1`) and separate `passkey_credentials` + `passkey_challenges` for WebAuthn (`migrations/0017_add_passkey_credentials.sql:1`, `migrations/0018_add_passkey_challenges.sql:1`).
- Current `UserRepository` is coupled to password hash joins in `src/adapters/postgres.rs:157`-`src/adapters/postgres.rs:195`. That must be decoupled before auth v2 becomes clean.

## Design goals

- Keep migrations additive first, destructive later.
- Separate account identity from credential material.
- Support coexistence of legacy password hash, OPAQUE credential, and passkeys during rollout.
- Centralize ephemeral challenge state so this does not devolve into one table per auth ceremony.
- Preserve the existing session, refresh, audit, and readiness model already present in the repo.

## Target data boundaries

### Account boundary

- Owns user identity and account status.
- Maps to `users` today.
- Must not require a password record to load an account.

### Legacy password boundary

- Owns Argon2 password hash and deprecation metadata.
- Maps to `credentials` today.
- Must remain separately addressable while v1 is still alive.

### OPAQUE credential boundary

- Owns modern password credential material.
- New table: `opaque_credentials`.
- No mixing with legacy hash columns.

### Flow store boundary

- Owns discovery tokens, PAKE login state, passkey challenges, and upgrade tickets.
- New table: `auth_flows`.
- Replaces the long-term need for specialized ephemeral tables like `passkey_challenges`.

### Session issuer boundary

- Owns session creation and refresh token issuance.
- Already lives across `sessions` and `refresh_tokens`; the v2 work should reuse it, not clone it.

## Proposed schema changes

## 1) New table: `opaque_credentials`

### Purpose

- Store the password credential representation produced by the chosen PAKE implementation.
- Keep it isolated from `credentials.password_hash` to allow rollback and reporting.

### DDL sketch

```sql
CREATE TABLE opaque_credentials (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    protocol TEXT NOT NULL,
    credential_blob BYTEA NOT NULL,
    server_key_ref TEXT,
    envelope_kms_key_id TEXT,
    state TEXT NOT NULL DEFAULT 'active',
    migrated_from_legacy_at TIMESTAMPTZ,
    last_verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_opaque_protocol CHECK (protocol IN ('opaque_v1')),
    CONSTRAINT chk_opaque_state CHECK (state IN ('active', 'superseded', 'revoked'))
);

CREATE INDEX idx_opaque_credentials_state_updated
    ON opaque_credentials(state, updated_at DESC);
```

### Notes

- `credential_blob` is intentionally opaque. Do not decompose protocol internals into random columns unless the chosen library requires it.
- `server_key_ref` is for a server key identifier if the implementation needs one.
- `envelope_kms_key_id` is optional and only makes sense if envelope protection is actually used.

## 2) New table: `auth_flows`

### Purpose

- Unified transient state for discovery, password login, password upgrade, and passkey flows.
- This is the production-grade replacement for the current specialized `passkey_challenges` table.

### DDL sketch

```sql
CREATE TABLE auth_flows (
    flow_id TEXT PRIMARY KEY,
    subject_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    subject_identifier_hash TEXT,
    flow_kind TEXT NOT NULL,
    protocol TEXT NOT NULL,
    state JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    rollout_channel TEXT,
    fallback_policy TEXT,
    trace_id TEXT,
    issued_ip INET,
    issued_user_agent TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_auth_flows_kind CHECK (
        flow_kind IN (
            'methods_discovery',
            'password_login',
            'password_upgrade',
            'passkey_login',
            'passkey_register'
        )
    ),
    CONSTRAINT chk_auth_flows_status CHECK (
        status IN ('pending', 'consumed', 'expired', 'cancelled')
    ),
    CONSTRAINT chk_auth_flows_attempt_count CHECK (attempt_count >= 0),
    CONSTRAINT chk_auth_flows_identity CHECK (
        subject_user_id IS NOT NULL OR subject_identifier_hash IS NOT NULL
    )
);

CREATE INDEX idx_auth_flows_subject_kind_status
    ON auth_flows(subject_user_id, flow_kind, status);

CREATE INDEX idx_auth_flows_identifier_kind_status
    ON auth_flows(subject_identifier_hash, flow_kind, status);

CREATE INDEX idx_auth_flows_expires_at
    ON auth_flows(expires_at);

CREATE INDEX idx_auth_flows_kind_created_at
    ON auth_flows(flow_kind, created_at DESC);
```

### Notes

- `subject_identifier_hash` should be a normalized, peppered hash of the identifier for lookup/reporting without dumping raw email into ephemeral state.
- `state` holds serialized protocol state only; do not shove whole request payloads or secrets in there without explicit need.
- `attempt_count` helps triage flow abuse and broken clients.

## 3) Changes to existing table: `credentials`

### Why

- Current `credentials` only stores the hash. That is not enough for rollout control and reporting.

### DDL sketch

```sql
ALTER TABLE credentials
    ADD COLUMN legacy_login_allowed BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN migrated_to_opaque_at TIMESTAMPTZ,
    ADD COLUMN last_legacy_verified_at TIMESTAMPTZ,
    ADD COLUMN legacy_deprecation_at TIMESTAMPTZ;

CREATE INDEX idx_credentials_legacy_login_allowed
    ON credentials(legacy_login_allowed)
    WHERE legacy_login_allowed = TRUE;

CREATE INDEX idx_credentials_migrated_to_opaque_at
    ON credentials(migrated_to_opaque_at);
```

### Notes

- Keep `password_hash` until v1 sunset criteria are met.
- `legacy_login_allowed` is operational policy, not business truth.

## 4) Changes to existing table: `passkey_credentials`

### Why

- Current table is enough for basic storage but too thin for rollout KPIs and support diagnostics.

### DDL sketch

```sql
ALTER TABLE passkey_credentials
    ADD COLUMN friendly_name TEXT,
    ADD COLUMN last_used_at TIMESTAMPTZ,
    ADD COLUMN transports TEXT[],
    ADD COLUMN aaguid TEXT,
    ADD COLUMN backup_eligible BOOLEAN,
    ADD COLUMN backup_state BOOLEAN;

CREATE INDEX idx_passkey_credentials_last_used_at
    ON passkey_credentials(last_used_at DESC);
```

### Notes

- `passkey_data JSONB` stays the canonical serialized WebAuthn credential.
- Extra columns are for reporting and policy, not for duplicating the whole payload.

## 5) Transitional handling of `passkey_challenges`

### Current state

- `passkey_challenges` is already production-useful for server-side challenge storage (`migrations/0018_add_passkey_challenges.sql:1` and `src/adapters/postgres.rs:968`-`src/adapters/postgres.rs:1159`).

### Target

- Keep it in phase 1 if that reduces migration risk.
- In phase 2, move new writes to `auth_flows`.
- In phase 3, drain remaining reads and delete `passkey_challenges` only after parity dashboards are green.

## Repository and port refactor

## Current coupling to break

- `UserRepository::find_by_email` and `find_by_id` currently require a credential join and return `password_hash` embedded in `User` via `src/adapters/postgres.rs:157`-`src/adapters/postgres.rs:195`.
- That coupling blocks accounts without legacy hashes, accounts with OPAQUE only, and any sane credential pluralism.

## Proposed target ports

The names below follow the same hexagonal style used in `src/modules/auth/ports.rs`.

### `AccountRepository`

```rust
#[async_trait]
pub trait AccountRepository: Send + Sync {
    async fn find_by_email(&self, email: &str) -> Option<AccountRecord>;
    async fn find_by_id(&self, user_id: &str) -> Option<AccountRecord>;
    async fn create_pending(&self, email: &str, now: DateTime<Utc>) -> Result<Option<AccountRecord>, String>;
    async fn activate(&self, user_id: &str, now: DateTime<Utc>) -> Result<(), String>;
}
```

### `LegacyPasswordRepository`

```rust
#[async_trait]
pub trait LegacyPasswordRepository: Send + Sync {
    async fn find_by_user_id(&self, user_id: &str) -> Result<Option<LegacyPasswordRecord>, String>;
    async fn upsert_hash(&self, user_id: &str, password_hash: &str, now: DateTime<Utc>) -> Result<(), String>;
    async fn mark_verified(&self, user_id: &str, now: DateTime<Utc>) -> Result<(), String>;
    async fn set_legacy_login_allowed(&self, user_id: &str, allowed: bool, now: DateTime<Utc>) -> Result<(), String>;
}
```

### `OpaqueCredentialRepository`

```rust
#[async_trait]
pub trait OpaqueCredentialRepository: Send + Sync {
    async fn find_by_user_id(&self, user_id: &str) -> Result<Option<OpaqueCredentialRecord>, String>;
    async fn upsert_for_user(&self, record: OpaqueCredentialRecord) -> Result<(), String>;
    async fn mark_verified(&self, user_id: &str, now: DateTime<Utc>) -> Result<(), String>;
    async fn revoke_for_user(&self, user_id: &str, now: DateTime<Utc>) -> Result<(), String>;
}
```

### `AuthFlowRepository`

```rust
#[async_trait]
pub trait AuthFlowRepository: Send + Sync {
    async fn issue(&self, flow: AuthFlowRecord) -> Result<(), String>;
    async fn consume(&self, flow_id: &str, now: DateTime<Utc>) -> Result<AuthFlowConsumeState, String>;
    async fn increment_attempts(&self, flow_id: &str, now: DateTime<Utc>) -> Result<(), String>;
    async fn cancel_active_for_subject(
        &self,
        subject_user_id: Option<&str>,
        subject_identifier_hash: Option<&str>,
        flow_kind: &str,
        now: DateTime<Utc>,
    ) -> Result<u64, String>;
    async fn prune_expired(&self, now: DateTime<Utc>) -> Result<u64, String>;
}
```

### `PasswordPakeService`

This is not storage. It is the cryptographic boundary.

```rust
#[async_trait]
pub trait PasswordPakeService: Send + Sync {
    async fn start_login(&self, credential: PakeLoginCredentialView, request: PakeStartRequest)
        -> Result<PakeStartResult, String>;
    async fn finish_login(&self, server_state: PakeServerState, client_message: PakeClientMessage)
        -> Result<PakeFinishResult, String>;
    async fn start_registration(&self, user_id: &str, request: PakeRegistrationStartRequest)
        -> Result<PakeRegistrationStartResult, String>;
    async fn finish_registration(
        &self,
        server_state: PakeRegistrationServerState,
        client_message: PakeRegistrationClientMessage,
    ) -> Result<PakeRegistrationFinishResult, String>;
}
```

### `AuthMethodDiscoveryService`

```rust
#[async_trait]
pub trait AuthMethodDiscoveryService: Send + Sync {
    async fn discover(&self, request: AuthMethodDiscoveryRequest)
        -> Result<AuthMethodDiscoveryResult, String>;
}
```

### `SessionIssuer`

This is a small but important seam so password v1, password v2, and passkey login all terminate in the same token issuance path.

```rust
#[async_trait]
pub trait SessionIssuer: Send + Sync {
    async fn issue_authenticated_session(
        &self,
        user_id: &str,
        device_info: Option<String>,
        ctx: RequestContext,
        now: DateTime<Utc>,
    ) -> Result<(AuthTokens, Principal), String>;
}
```

## Transitional mapping to the current repo

- `AccountRepository` replaces the account lookup responsibility currently buried in `UserRepository`.
- `LegacyPasswordRepository` takes over hash operations currently mixed into `UserRepository::update_password` and login lookups.
- `OpaqueCredentialRepository` is new.
- `AuthFlowRepository` absorbs the general pattern already proven by `PasskeyChallengeRepository`.
- `SessionIssuer` is a facade over the logic now implemented directly in `AuthService::issue_session_tokens`.

## Data model sketches

### `AccountRecord`

```rust
pub struct AccountRecord {
    pub id: String,
    pub email: String,
    pub status: AccountStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
```

### `LegacyPasswordRecord`

```rust
pub struct LegacyPasswordRecord {
    pub user_id: String,
    pub password_hash: String,
    pub legacy_login_allowed: bool,
    pub migrated_to_opaque_at: Option<DateTime<Utc>>,
    pub last_legacy_verified_at: Option<DateTime<Utc>>,
    pub legacy_deprecation_at: Option<DateTime<Utc>>,
}
```

### `OpaqueCredentialRecord`

```rust
pub struct OpaqueCredentialRecord {
    pub user_id: String,
    pub protocol: String,
    pub credential_blob: Vec<u8>,
    pub server_key_ref: Option<String>,
    pub envelope_kms_key_id: Option<String>,
    pub state: OpaqueCredentialState,
    pub migrated_from_legacy_at: Option<DateTime<Utc>>,
    pub last_verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
```

### `AuthFlowRecord`

```rust
pub struct AuthFlowRecord {
    pub flow_id: String,
    pub subject_user_id: Option<String>,
    pub subject_identifier_hash: Option<String>,
    pub flow_kind: AuthFlowKind,
    pub protocol: String,
    pub state: serde_json::Value,
    pub status: AuthFlowStatus,
    pub rollout_channel: Option<String>,
    pub fallback_policy: Option<String>,
    pub trace_id: Option<String>,
    pub issued_ip: Option<String>,
    pub issued_user_agent: Option<String>,
    pub attempt_count: u32,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
```

## Query and constraint guidance

- Account reads must no longer depend on a credential join.
- Credential writes should happen in a transaction when upgrade completes.
- Flow consumption should use a single atomic statement, same pattern as current passkey challenge consume.
- Expiration pruning should be batched and observable.
- Use partial indexes for active/pending rows where possible; otherwise the janitor will become a hidden tax.

## Migration order

1. Create `opaque_credentials`.
2. Create `auth_flows`.
3. Add rollout metadata columns to `credentials`.
4. Add reporting columns to `passkey_credentials`.
5. Refactor repositories so account lookup no longer requires `credentials`.
6. Start writing PAKE flows to `auth_flows`.
7. Optionally move passkey flows to `auth_flows` after parity checks.
8. Only after v1 sunset: consider dropping `credentials.password_hash` or the entire table.

## Production-readiness notes

- Flow pruning must have metrics, readiness signal, and audit breadcrumbs like the current passkey challenge janitor does.
- Any encrypted-at-rest decision for `opaque_credentials` must be documented with key rotation/runbook impact before implementation.
- If the chosen OPAQUE library needs binary blobs larger than expected, validate PostgreSQL row size and index usage before pretending this is free.

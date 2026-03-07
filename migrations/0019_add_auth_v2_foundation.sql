CREATE TABLE IF NOT EXISTS opaque_credentials (
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

CREATE INDEX IF NOT EXISTS idx_opaque_credentials_state_updated
ON opaque_credentials(state, updated_at DESC);

CREATE TABLE IF NOT EXISTS auth_flows (
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

CREATE INDEX IF NOT EXISTS idx_auth_flows_subject_kind_status
ON auth_flows(subject_user_id, flow_kind, status);

CREATE INDEX IF NOT EXISTS idx_auth_flows_identifier_kind_status
ON auth_flows(subject_identifier_hash, flow_kind, status);

CREATE INDEX IF NOT EXISTS idx_auth_flows_expires_at
ON auth_flows(expires_at);

CREATE INDEX IF NOT EXISTS idx_auth_flows_kind_created_at
ON auth_flows(flow_kind, created_at DESC);

ALTER TABLE credentials
    ADD COLUMN IF NOT EXISTS legacy_login_allowed BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS migrated_to_opaque_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_legacy_verified_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS legacy_deprecation_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_credentials_legacy_login_allowed
ON credentials(legacy_login_allowed)
WHERE legacy_login_allowed = TRUE;

CREATE INDEX IF NOT EXISTS idx_credentials_migrated_to_opaque_at
ON credentials(migrated_to_opaque_at);

ALTER TABLE passkey_credentials
    ADD COLUMN IF NOT EXISTS friendly_name TEXT,
    ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS transports TEXT[],
    ADD COLUMN IF NOT EXISTS aaguid TEXT,
    ADD COLUMN IF NOT EXISTS backup_eligible BOOLEAN,
    ADD COLUMN IF NOT EXISTS backup_state BOOLEAN;

CREATE INDEX IF NOT EXISTS idx_passkey_credentials_last_used_at
ON passkey_credentials(last_used_at DESC);

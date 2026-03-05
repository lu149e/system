CREATE TABLE IF NOT EXISTS passkey_credentials (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL,
    passkey_data JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, credential_id),
    UNIQUE (credential_id)
);

CREATE INDEX IF NOT EXISTS idx_passkey_credentials_user_id
ON passkey_credentials(user_id);

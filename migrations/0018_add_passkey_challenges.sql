CREATE TABLE IF NOT EXISTS passkey_challenges (
    flow_id TEXT PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    challenge_type TEXT NOT NULL CHECK (challenge_type IN ('registration', 'authentication')),
    challenge_state JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_passkey_challenges_user_type
ON passkey_challenges(user_id, challenge_type);

CREATE INDEX IF NOT EXISTS idx_passkey_challenges_expires_at
ON passkey_challenges(expires_at);

CREATE TABLE IF NOT EXISTS outbox_replay_audit (
    id BIGSERIAL PRIMARY KEY,
    operation_type TEXT NOT NULL CHECK (operation_type IN ('requeue')),
    actor_identifier TEXT NOT NULL,
    provider_filter TEXT,
    template_filter TEXT,
    failed_after_filter TIMESTAMPTZ,
    failed_before_filter TIMESTAMPTZ,
    row_limit INTEGER NOT NULL CHECK (row_limit >= 1 AND row_limit <= 1000),
    allow_unfiltered BOOLEAN NOT NULL DEFAULT FALSE,
    is_apply BOOLEAN NOT NULL,
    selected_count BIGINT NOT NULL CHECK (selected_count >= 0),
    updated_count BIGINT NOT NULL CHECK (updated_count >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_outbox_replay_audit_created_at
ON outbox_replay_audit (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_outbox_replay_audit_actor_created_at
ON outbox_replay_audit (actor_identifier, created_at DESC);

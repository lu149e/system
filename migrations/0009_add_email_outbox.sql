CREATE TABLE IF NOT EXISTS email_outbox (
    id UUID PRIMARY KEY,
    status TEXT NOT NULL,
    provider TEXT NOT NULL,
    template TEXT NOT NULL,
    recipient_email TEXT NOT NULL,
    payload JSONB NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ,
    last_error TEXT,
    sent_at TIMESTAMPTZ,
    failed_at TIMESTAMPTZ,
    last_attempt_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (status IN ('pending', 'sent', 'failed'))
);

CREATE INDEX IF NOT EXISTS idx_email_outbox_dispatch_due
ON email_outbox (next_attempt_at)
WHERE status IN ('pending', 'failed');

CREATE INDEX IF NOT EXISTS idx_email_outbox_status_created
ON email_outbox (status, created_at DESC);

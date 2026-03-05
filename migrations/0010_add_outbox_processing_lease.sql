ALTER TABLE email_outbox
    ADD COLUMN IF NOT EXISTS processing_owner TEXT,
    ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ;

ALTER TABLE email_outbox
    DROP CONSTRAINT IF EXISTS email_outbox_status_check;

ALTER TABLE email_outbox
    ADD CONSTRAINT email_outbox_status_check
    CHECK (status IN ('pending', 'processing', 'sent', 'failed'));

CREATE INDEX IF NOT EXISTS idx_email_outbox_processing_lease
ON email_outbox (lease_expires_at)
WHERE status = 'processing';

ALTER TABLE outbox_replay_audit
ADD COLUMN IF NOT EXISTS change_ticket TEXT;

CREATE INDEX IF NOT EXISTS idx_outbox_replay_audit_ticket_created_at
ON outbox_replay_audit (change_ticket, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_refresh_rejected_reason_created_at
ON audit_events ((metadata->>'reason'), created_at)
WHERE event_type = 'auth.refresh.rejected';

CREATE INDEX IF NOT EXISTS idx_audit_refresh_success_created_at
ON audit_events (created_at)
WHERE event_type = 'auth.refresh.success';

CREATE INDEX IF NOT EXISTS idx_audit_refresh_reuse_created_at
ON audit_events (created_at)
WHERE event_type = 'auth.refresh.reuse_detected';

CREATE INDEX IF NOT EXISTS idx_audit_login_locked_created_at
ON audit_events (created_at)
WHERE event_type = 'auth.login.locked';

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'outbox_replay_audit_apply_actor_ticket_ck'
      AND conrelid = 'outbox_replay_audit'::regclass
  ) THEN
    ALTER TABLE outbox_replay_audit
      ADD CONSTRAINT outbox_replay_audit_apply_actor_ticket_ck
      CHECK (
        NOT is_apply
        OR (
          NULLIF(BTRIM(actor_identifier), '') IS NOT NULL
          AND LOWER(BTRIM(actor_identifier)) <> 'unknown'
          AND NULLIF(BTRIM(change_ticket), '') IS NOT NULL
          AND LOWER(BTRIM(change_ticket)) <> 'unknown'
        )
      ) NOT VALID;
  END IF;
END
$$;

COMMENT ON CONSTRAINT outbox_replay_audit_apply_actor_ticket_ck ON outbox_replay_audit IS
'Enforces actor/ticket quality only for apply rows; dry-run rows remain permissive.';

-- Intentionally no strict ticket regex constraint: ticket formats vary by org/tooling
-- (Jira, ServiceNow, Azure DevOps, internal cases), so pattern enforcement is handled
-- by operational process to avoid blocking valid legacy/external formats.

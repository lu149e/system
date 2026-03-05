DO $migration$
BEGIN
  IF to_regclass('public.outbox_replay_audit') IS NULL THEN
    RAISE NOTICE 'Skipping append-only hardening: table public.outbox_replay_audit does not exist';
    RETURN;
  END IF;

  CREATE OR REPLACE FUNCTION outbox_replay_audit_reject_mutation()
  RETURNS trigger
  LANGUAGE plpgsql
  AS $fn$
  BEGIN
    IF TG_OP = 'UPDATE' THEN
      RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'outbox_replay_audit is append-only; UPDATE is not allowed',
        HINT = 'Insert a new audit row instead of mutating existing rows.';
    ELSIF TG_OP = 'DELETE' THEN
      RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'outbox_replay_audit is append-only; DELETE is not allowed',
        HINT = 'Retain audit history; use scoped SELECT queries for operational views.';
    END IF;

    RETURN NULL;
  END
  $fn$;

  DROP TRIGGER IF EXISTS outbox_replay_audit_block_update ON outbox_replay_audit;
  CREATE TRIGGER outbox_replay_audit_block_update
  BEFORE UPDATE ON outbox_replay_audit
  FOR EACH ROW
  EXECUTE FUNCTION outbox_replay_audit_reject_mutation();

  DROP TRIGGER IF EXISTS outbox_replay_audit_block_delete ON outbox_replay_audit;
  CREATE TRIGGER outbox_replay_audit_block_delete
  BEFORE DELETE ON outbox_replay_audit
  FOR EACH ROW
  EXECUTE FUNCTION outbox_replay_audit_reject_mutation();
END
$migration$;

COMMENT ON FUNCTION outbox_replay_audit_reject_mutation() IS
'Guards outbox_replay_audit as append-only by rejecting UPDATE and DELETE operations.';

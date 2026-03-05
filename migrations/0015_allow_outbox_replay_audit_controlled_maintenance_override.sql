DO $migration$
BEGIN
  IF to_regclass('public.outbox_replay_audit') IS NULL THEN
    RAISE NOTICE 'Skipping append-only maintenance override hardening: table public.outbox_replay_audit does not exist';
    RETURN;
  END IF;

  CREATE OR REPLACE FUNCTION outbox_replay_audit_reject_mutation()
  RETURNS trigger
  LANGUAGE plpgsql
  AS $fn$
  DECLARE
    maintenance_override text := LOWER(COALESCE(current_setting('auth.outbox_replay_audit_maintenance_override', true), 'off'));
    maintenance_actor text := NULLIF(BTRIM(COALESCE(current_setting('auth.outbox_replay_audit_maintenance_actor', true), '')), '');
    maintenance_ticket text := NULLIF(BTRIM(COALESCE(current_setting('auth.outbox_replay_audit_maintenance_ticket', true), '')), '');
  BEGIN
    IF maintenance_override IN ('1', 'on', 'true') THEN
      IF maintenance_actor IS NULL OR maintenance_ticket IS NULL THEN
        RAISE EXCEPTION USING
          ERRCODE = '55000',
          MESSAGE = 'outbox_replay_audit maintenance override requires actor and ticket session settings',
          HINT = 'Set LOCAL auth.outbox_replay_audit_maintenance_actor and auth.outbox_replay_audit_maintenance_ticket before mutating rows.';
      END IF;

      IF TG_OP = 'UPDATE' THEN
        RETURN NEW;
      ELSIF TG_OP = 'DELETE' THEN
        RETURN OLD;
      END IF;
    END IF;

    IF TG_OP = 'UPDATE' THEN
      RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'outbox_replay_audit is append-only; UPDATE is not allowed',
        HINT = 'Break-glass only: SET LOCAL auth.outbox_replay_audit_maintenance_override = on (with actor/ticket session settings) inside a controlled maintenance transaction.';
    ELSIF TG_OP = 'DELETE' THEN
      RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'outbox_replay_audit is append-only; DELETE is not allowed',
        HINT = 'Break-glass only: SET LOCAL auth.outbox_replay_audit_maintenance_override = on (with actor/ticket session settings) inside a controlled maintenance transaction.';
    END IF;

    RETURN NULL;
  END
  $fn$;
END
$migration$;

COMMENT ON FUNCTION outbox_replay_audit_reject_mutation() IS
'Guards outbox_replay_audit as append-only; allows UPDATE/DELETE only in explicit maintenance transactions with session override + actor/ticket metadata.';

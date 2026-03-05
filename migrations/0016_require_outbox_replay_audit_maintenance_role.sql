DO $migration$
BEGIN
  IF to_regclass('public.outbox_replay_audit') IS NULL THEN
    RAISE NOTICE 'Skipping maintenance role enforcement: table public.outbox_replay_audit does not exist';
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
    maintenance_role text := NULLIF(BTRIM(COALESCE(current_setting('auth.outbox_replay_audit_maintenance_role', true), '')), '');
    effective_maintenance_role text;
    maintenance_role_exists boolean;
    caller_is_maintenance_member boolean;
  BEGIN
    IF maintenance_override IN ('1', 'on', 'true') THEN
      effective_maintenance_role := COALESCE(maintenance_role, 'outbox_replay_maintainer');

      SELECT EXISTS (
               SELECT 1
               FROM pg_roles r
               WHERE r.rolname = effective_maintenance_role
             )
      INTO maintenance_role_exists;

      IF NOT maintenance_role_exists THEN
        RAISE EXCEPTION USING
          ERRCODE = '55000',
          MESSAGE = format(
            'outbox_replay_audit maintenance override requires role "%s", but it does not exist',
            effective_maintenance_role
          ),
          HINT = format(
            'Create role "%s" and grant it to approved operator roles, or SET LOCAL auth.outbox_replay_audit_maintenance_role to an existing maintenance role for this controlled transaction.',
            effective_maintenance_role
          );
      END IF;

      SELECT pg_has_role(current_user, effective_maintenance_role, 'MEMBER')
      INTO caller_is_maintenance_member;

      IF NOT caller_is_maintenance_member THEN
        RAISE EXCEPTION USING
          ERRCODE = '55000',
          MESSAGE = format(
            'outbox_replay_audit maintenance override denied: role "%s" is required',
            effective_maintenance_role
          ),
          HINT = format(
            'Grant role "%s" to current user "%s" (or its parent role) before using auth.outbox_replay_audit_maintenance_override.',
            effective_maintenance_role,
            current_user
          );
      END IF;

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
        HINT = 'Break-glass only: SET LOCAL auth.outbox_replay_audit_maintenance_override = on (with role membership + actor/ticket session settings) inside a controlled maintenance transaction.';
    ELSIF TG_OP = 'DELETE' THEN
      RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'outbox_replay_audit is append-only; DELETE is not allowed',
        HINT = 'Break-glass only: SET LOCAL auth.outbox_replay_audit_maintenance_override = on (with role membership + actor/ticket session settings) inside a controlled maintenance transaction.';
    END IF;

    RETURN NULL;
  END
  $fn$;
END
$migration$;

COMMENT ON FUNCTION outbox_replay_audit_reject_mutation() IS
'Guards outbox_replay_audit as append-only; allows UPDATE/DELETE only in explicit maintenance transactions with override + maintenance role membership + actor/ticket metadata.';

-- DBA reference snippets for outbox_replay_audit append-only enforcement.

-- 1) Verify mutation-guard triggers are installed.
SELECT trigger_name,
       event_manipulation,
       action_timing,
       action_statement
FROM information_schema.triggers
WHERE event_object_schema = 'public'
  AND event_object_table = 'outbox_replay_audit'
  AND trigger_name IN (
    'outbox_replay_audit_block_update',
    'outbox_replay_audit_block_delete'
  )
ORDER BY trigger_name;

-- 2) Verify guard function source and exception messages.
SELECT p.proname,
       pg_get_functiondef(p.oid) AS definition
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'public'
  AND p.proname = 'outbox_replay_audit_reject_mutation';

-- 3) Smoke test expected UPDATE rejection (run inside transaction and ROLLBACK).
BEGIN;
UPDATE outbox_replay_audit
SET actor_identifier = actor_identifier
WHERE id = (
  SELECT id
  FROM outbox_replay_audit
  ORDER BY id DESC
  LIMIT 1
);
ROLLBACK;

-- 4) Smoke test expected DELETE rejection (run inside transaction and ROLLBACK).
BEGIN;
DELETE FROM outbox_replay_audit
WHERE id = (
  SELECT id
  FROM outbox_replay_audit
  ORDER BY id DESC
  LIMIT 1
);
ROLLBACK;

-- 5) Smoke test controlled maintenance override (run inside transaction and ROLLBACK).
BEGIN;
-- Optional for non-default role policy:
-- SELECT set_config('auth.outbox_replay_audit_maintenance_role', 'custom_breakglass_role', true) AS maintenance_role;
SELECT set_config('auth.outbox_replay_audit_maintenance_override', 'on', true) AS maintenance_override_enabled;
SELECT set_config('auth.outbox_replay_audit_maintenance_actor', 'dba.breakglass', true) AS maintenance_actor;
SELECT set_config('auth.outbox_replay_audit_maintenance_ticket', 'CHG-0000', true) AS maintenance_ticket;
UPDATE outbox_replay_audit
SET actor_identifier = actor_identifier
WHERE id = (
  SELECT id
  FROM outbox_replay_audit
  ORDER BY id DESC
  LIMIT 1
)
RETURNING id, actor_identifier, change_ticket, created_at;
ROLLBACK;

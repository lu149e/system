-- Parameterized snippets for replay-audit compliance rollout.
-- Use with psql variables, for example:
--   psql "$DATABASE_URL" -v created_after='' -v created_before='' -v id_after='' -v id_before='' -v row_limit='100' -v actor_identifier='oncall.sre' -v ticket_identifier='INC-9001' -v set_actor_identifier='migration.legacy' -v set_ticket_identifier='LEGACY-123' -f scripts/sql/outbox-replay-audit-compliance-queries.sql

-- Noncompliant condition used by migration 0013 constraint:
-- is_apply
-- AND (
--   NULLIF(BTRIM(actor_identifier), '') IS NULL
--   OR LOWER(BTRIM(actor_identifier)) = 'unknown'
--   OR NULLIF(BTRIM(change_ticket), '') IS NULL
--   OR LOWER(BTRIM(change_ticket)) = 'unknown'
-- )

-- Inspect noncompliant rows (historical candidates before validate).
SELECT id,
       operation_type,
       actor_identifier,
       change_ticket,
       is_apply,
       created_at
FROM outbox_replay_audit
WHERE is_apply
  AND (
    NULLIF(BTRIM(actor_identifier), '') IS NULL
    OR LOWER(BTRIM(actor_identifier)) = 'unknown'
    OR NULLIF(BTRIM(change_ticket), '') IS NULL
    OR LOWER(BTRIM(change_ticket)) = 'unknown'
  )
  AND (NULLIF(:'created_after', '') IS NULL OR created_at >= :'created_after'::timestamptz)
  AND (NULLIF(:'created_before', '') IS NULL OR created_at < :'created_before'::timestamptz)
  AND (NULLIF(:'id_after', '') IS NULL OR id >= NULLIF(:'id_after', '')::bigint)
  AND (NULLIF(:'id_before', '') IS NULL OR id <= NULLIF(:'id_before', '')::bigint)
ORDER BY created_at ASC, id ASC
LIMIT GREATEST(1, LEAST(COALESCE(NULLIF(:'row_limit', '')::int, 100), 1000));

-- Count total remaining noncompliant rows (for validation readiness gate).
SELECT COUNT(*)::bigint AS noncompliant_total
FROM outbox_replay_audit
WHERE is_apply
  AND (
    NULLIF(BTRIM(actor_identifier), '') IS NULL
    OR LOWER(BTRIM(actor_identifier)) = 'unknown'
    OR NULLIF(BTRIM(change_ticket), '') IS NULL
    OR LOWER(BTRIM(change_ticket)) = 'unknown'
  );

-- Replay-audit compliance posture status (single row, operator gate helper).
-- Optional psql vars:
--   recent_window_days (default 7 in tooling)
--   app_role (expected NOT member of maintenance role)
--   operator_roles (comma-separated expected members)
WITH target AS (
  SELECT to_regclass('public.outbox_replay_audit') AS relid
),
constraint_state AS (
  SELECT EXISTS (
           SELECT 1
           FROM pg_constraint c
           CROSS JOIN target t
           WHERE c.conrelid = t.relid
             AND c.conname = 'outbox_replay_audit_apply_actor_ticket_ck'
         ) AS constraint_exists,
         COALESCE((
           SELECT c.convalidated
           FROM pg_constraint c
           CROSS JOIN target t
           WHERE c.conrelid = t.relid
             AND c.conname = 'outbox_replay_audit_apply_actor_ticket_ck'
           LIMIT 1
         ), false) AS constraint_validated
),
trigger_state AS (
  SELECT EXISTS (
           SELECT 1
           FROM pg_trigger tg
           CROSS JOIN target t
           WHERE tg.tgrelid = t.relid
             AND NOT tg.tgisinternal
             AND tg.tgenabled = 'O'
             AND tg.tgname = 'outbox_replay_audit_block_update'
         ) AS has_block_update_trigger,
         EXISTS (
           SELECT 1
           FROM pg_trigger tg
           CROSS JOIN target t
           WHERE tg.tgrelid = t.relid
             AND NOT tg.tgisinternal
             AND tg.tgenabled = 'O'
             AND tg.tgname = 'outbox_replay_audit_block_delete'
         ) AS has_block_delete_trigger
),
quality_state AS (
  SELECT CASE
           WHEN t.relid IS NULL THEN NULL::bigint
           ELSE (
             SELECT COUNT(*)::bigint
             FROM outbox_replay_audit
             WHERE is_apply
               AND (
                 NULLIF(BTRIM(actor_identifier), '') IS NULL
                 OR LOWER(BTRIM(actor_identifier)) = 'unknown'
                 OR NULLIF(BTRIM(change_ticket), '') IS NULL
                 OR LOWER(BTRIM(change_ticket)) = 'unknown'
               )
           )
         END AS historical_noncompliant_total,
         CASE
           WHEN t.relid IS NULL THEN NULL::bigint
           ELSE (
             SELECT COUNT(*)::bigint
             FROM outbox_replay_audit
             WHERE is_apply
               AND created_at >= NOW() - make_interval(days => GREATEST(1, COALESCE(NULLIF(:'recent_window_days', '')::int, 7)))
           )
         END AS recent_apply_total
  FROM target t
),
maintenance_state AS (
  SELECT COALESCE(
           NULLIF(BTRIM(current_setting('auth.outbox_replay_audit_maintenance_role', true)), ''),
           'outbox_replay_maintainer'
         ) AS maintenance_role_name,
         EXISTS (
           SELECT 1
           FROM pg_roles r
           WHERE r.rolname = COALESCE(
             NULLIF(BTRIM(current_setting('auth.outbox_replay_audit_maintenance_role', true)), ''),
             'outbox_replay_maintainer'
            )
          ) AS maintenance_role_exists
),
requested_roles AS (
  SELECT NULLIF(BTRIM(:'app_role'), '') AS app_role_name,
         NULLIF(BTRIM(:'operator_roles'), '') AS operator_roles_csv
),
operator_roles_list AS (
  SELECT DISTINCT BTRIM(role_name) AS role_name
  FROM requested_roles rr
  CROSS JOIN LATERAL regexp_split_to_table(COALESCE(rr.operator_roles_csv, ''), ',') AS role_name
  WHERE NULLIF(BTRIM(role_name), '') IS NOT NULL
),
operator_roles_missing AS (
  SELECT rl.role_name
  FROM operator_roles_list rl
  CROSS JOIN maintenance_state ms
  WHERE NOT (
    ms.maintenance_role_exists
    AND EXISTS (
      SELECT 1
      FROM pg_roles r
      WHERE r.rolname = rl.role_name
    )
    AND pg_has_role(rl.role_name, ms.maintenance_role_name, 'MEMBER')
  )
),
role_drift_state AS (
  SELECT (rr.app_role_name IS NOT NULL) AS app_role_checked,
         CASE
           WHEN rr.app_role_name IS NULL THEN NULL::boolean
           WHEN NOT ms.maintenance_role_exists THEN false
           WHEN NOT EXISTS (
             SELECT 1
             FROM pg_roles r
             WHERE r.rolname = rr.app_role_name
           ) THEN false
           ELSE pg_has_role(rr.app_role_name, ms.maintenance_role_name, 'MEMBER')
         END AS app_role_is_maintenance_member,
         (SELECT COUNT(*)::int FROM operator_roles_list) AS operator_roles_checked,
         (SELECT COUNT(*)::int FROM operator_roles_missing) AS operator_roles_missing_membership_count,
         COALESCE((
           SELECT string_agg(orm.role_name, ',' ORDER BY orm.role_name)
           FROM operator_roles_missing orm
         ), '') AS operator_roles_missing_membership
  FROM maintenance_state ms
  CROSS JOIN requested_roles rr
)
SELECT (t.relid IS NOT NULL) AS table_exists,
       cs.constraint_exists,
       cs.constraint_validated,
       ts.has_block_update_trigger,
       ts.has_block_delete_trigger,
       (ts.has_block_update_trigger AND ts.has_block_delete_trigger) AS append_only_triggers_present,
       qs.historical_noncompliant_total,
       GREATEST(1, COALESCE(NULLIF(:'recent_window_days', '')::int, 7)) AS recent_apply_window_days,
       qs.recent_apply_total,
       ms.maintenance_role_name,
       ms.maintenance_role_exists,
       (
         ms.maintenance_role_exists
         AND pg_has_role(current_user, ms.maintenance_role_name, 'MEMBER')
       ) AS current_user_is_maintenance_member,
       rds.app_role_checked,
       rds.app_role_is_maintenance_member,
       rds.operator_roles_checked,
       rds.operator_roles_missing_membership_count,
       rds.operator_roles_missing_membership,
         (
           (t.relid IS NOT NULL)
          AND cs.constraint_exists
          AND cs.constraint_validated
          AND ts.has_block_update_trigger
          AND ts.has_block_delete_trigger
          AND COALESCE(qs.historical_noncompliant_total, 1) = 0
          AND ms.maintenance_role_exists
          AND (
            NOT rds.app_role_checked
            OR COALESCE(rds.app_role_is_maintenance_member, false) = false
          )
          AND rds.operator_roles_missing_membership_count = 0
        ) AS release_ready
FROM target t
CROSS JOIN constraint_state cs
CROSS JOIN trigger_state ts
CROSS JOIN quality_state qs
CROSS JOIN maintenance_state ms
CROSS JOIN role_drift_state rds;

-- Optional manual remediation pattern (break-glass only).
-- Required psql vars for apply: actor_identifier, ticket_identifier.
-- Always execute in a controlled transaction with explicit maintenance override.
BEGIN;
SELECT set_config('auth.outbox_replay_audit_maintenance_override', 'on', true) AS maintenance_override_enabled;
-- Optional: override maintenance role when policy uses a non-default role name.
-- SELECT set_config('auth.outbox_replay_audit_maintenance_role', 'custom_breakglass_role', true) AS maintenance_role;
SELECT set_config('auth.outbox_replay_audit_maintenance_actor', NULLIF(:'actor_identifier', ''), true) AS maintenance_actor;
SELECT set_config('auth.outbox_replay_audit_maintenance_ticket', NULLIF(:'ticket_identifier', ''), true) AS maintenance_ticket;
WITH candidates AS (
  SELECT id
  FROM outbox_replay_audit
  WHERE is_apply
    AND (
      NULLIF(BTRIM(actor_identifier), '') IS NULL
      OR LOWER(BTRIM(actor_identifier)) = 'unknown'
      OR NULLIF(BTRIM(change_ticket), '') IS NULL
      OR LOWER(BTRIM(change_ticket)) = 'unknown'
    )
    AND (NULLIF(:'created_after', '') IS NULL OR created_at >= :'created_after'::timestamptz)
    AND (NULLIF(:'created_before', '') IS NULL OR created_at < :'created_before'::timestamptz)
    AND (NULLIF(:'id_after', '') IS NULL OR id >= NULLIF(:'id_after', '')::bigint)
    AND (NULLIF(:'id_before', '') IS NULL OR id <= NULLIF(:'id_before', '')::bigint)
  ORDER BY created_at ASC, id ASC
  LIMIT GREATEST(1, LEAST(COALESCE(NULLIF(:'row_limit', '')::int, 100), 1000))
  FOR UPDATE SKIP LOCKED
)
UPDATE outbox_replay_audit AS audit
SET actor_identifier = CASE
                         WHEN NULLIF(BTRIM(audit.actor_identifier), '') IS NULL
                              OR LOWER(BTRIM(audit.actor_identifier)) = 'unknown'
                         THEN NULLIF(:'set_actor_identifier', '')
                         ELSE audit.actor_identifier
                       END,
    change_ticket = CASE
                      WHEN NULLIF(BTRIM(audit.change_ticket), '') IS NULL
                           OR LOWER(BTRIM(audit.change_ticket)) = 'unknown'
                      THEN NULLIF(:'set_ticket_identifier', '')
                      ELSE audit.change_ticket
                    END
FROM candidates
WHERE audit.id = candidates.id
RETURNING audit.id,
          audit.operation_type,
          audit.actor_identifier,
          audit.change_ticket,
          audit.is_apply,
          audit.created_at;
COMMIT;

-- Pre-validation check: constraint status + remaining violations.
SELECT c.conname,
       c.convalidated,
       pg_get_constraintdef(c.oid) AS definition
FROM pg_constraint c
WHERE c.conname = 'outbox_replay_audit_apply_actor_ticket_ck'
  AND c.conrelid = 'outbox_replay_audit'::regclass;

SELECT COUNT(*)::bigint AS noncompliant_total
FROM outbox_replay_audit
WHERE is_apply
  AND (
    NULLIF(BTRIM(actor_identifier), '') IS NULL
    OR LOWER(BTRIM(actor_identifier)) = 'unknown'
    OR NULLIF(BTRIM(change_ticket), '') IS NULL
    OR LOWER(BTRIM(change_ticket)) = 'unknown'
  );

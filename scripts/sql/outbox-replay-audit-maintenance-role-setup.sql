-- DBA setup for least-privilege replay-audit maintenance override role.
--
-- Optional psql vars:
--   maintenance_role  (default: outbox_replay_maintainer)
--   operator_role     (required for GRANT examples)
--   operator_roles    (optional comma list for verification snapshot)
--   app_runtime_role  (required for negative membership verification)

-- 1) Create dedicated maintenance role (NOLOGIN by default).
DO
$$
DECLARE
  role_name text := COALESCE(NULLIF(BTRIM(:'maintenance_role'), ''), 'outbox_replay_maintainer');
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
    EXECUTE format('CREATE ROLE %I NOLOGIN', role_name);
  END IF;
END
$$;

-- 2) Grant maintenance role to approved operator role(s).
-- Repeat as needed for each approved operator role.
DO
$$
DECLARE
  role_name text := COALESCE(NULLIF(BTRIM(:'maintenance_role'), ''), 'outbox_replay_maintainer');
  grantee_role text := NULLIF(BTRIM(:'operator_role'), '');
BEGIN
  IF grantee_role IS NULL THEN
    RAISE NOTICE 'Skipping GRANT because operator_role psql variable is empty';
    RETURN;
  END IF;

  EXECUTE format('GRANT %I TO %I', role_name, grantee_role);
END
$$;

-- 3) Ensure app runtime role is NOT a member.
DO
$$
DECLARE
  role_name text := COALESCE(NULLIF(BTRIM(:'maintenance_role'), ''), 'outbox_replay_maintainer');
  runtime_role text := NULLIF(BTRIM(:'app_runtime_role'), '');
BEGIN
  IF runtime_role IS NULL THEN
    RAISE NOTICE 'Skipping REVOKE because app_runtime_role psql variable is empty';
    RETURN;
  END IF;

  EXECUTE format('REVOKE %I FROM %I', role_name, runtime_role);
END
$$;

-- 4) Verification snapshot: role existence and role-drift checks.
--    operator_roles allows multiple entries (comma-separated) for drift count.
WITH effective AS (
  SELECT COALESCE(NULLIF(BTRIM(:'maintenance_role'), ''), 'outbox_replay_maintainer') AS maintenance_role_name
),
operator_roles_list AS (
  SELECT DISTINCT BTRIM(role_name) AS role_name
  FROM regexp_split_to_table(COALESCE(NULLIF(BTRIM(:'operator_roles'), ''), NULLIF(BTRIM(:'operator_role'), ''), ''), ',') AS role_name
  WHERE NULLIF(BTRIM(role_name), '') IS NOT NULL
),
operator_roles_missing AS (
  SELECT rl.role_name
  FROM operator_roles_list rl
  CROSS JOIN effective e
  WHERE NOT (
    EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname = e.maintenance_role_name)
    AND EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname = rl.role_name)
    AND pg_has_role(rl.role_name, e.maintenance_role_name, 'MEMBER')
  )
)
SELECT e.maintenance_role_name,
       EXISTS (
         SELECT 1
         FROM pg_roles r
         WHERE r.rolname = e.maintenance_role_name
       ) AS maintenance_role_exists,
       NULLIF(BTRIM(:'app_runtime_role'), '') AS app_runtime_role,
       (NULLIF(BTRIM(:'app_runtime_role'), '') IS NOT NULL) AS app_role_checked,
       CASE
         WHEN NULLIF(BTRIM(:'app_runtime_role'), '') IS NULL THEN NULL
         WHEN NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname = e.maintenance_role_name) THEN false
         WHEN NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname = NULLIF(BTRIM(:'app_runtime_role'), '')) THEN false
         ELSE pg_has_role(NULLIF(BTRIM(:'app_runtime_role'), ''), e.maintenance_role_name, 'MEMBER')
       END AS app_runtime_role_is_member,
       (SELECT COUNT(*)::int FROM operator_roles_list) AS operator_roles_checked,
       (SELECT COUNT(*)::int FROM operator_roles_missing) AS operator_roles_missing_membership_count,
       COALESCE((
         SELECT string_agg(orm.role_name, ',' ORDER BY orm.role_name)
         FROM operator_roles_missing orm
       ), '') AS operator_roles_missing_membership
FROM effective e;

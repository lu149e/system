#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Operational tooling for outbox replay-audit compliance rollout.

Usage:
  scripts/outbox-replay-audit-compliance-tool.sh <command> [options]

Commands:
  inspect-noncompliant   List historical rows that violate apply actor/ticket quality check
  remediate-noncompliant Remediate noncompliant rows (dry-run by default)
  backfill-noncompliant  Deprecated alias for remediate-noncompliant
  validate-constraint    Validate DB check constraint (dry-run by default)
  status                 Report replay-audit compliance posture for release/audit gates

Common options:
  --database-url <url>    PostgreSQL URL (default: DATABASE_URL)
  --created-after <ts>    Filter rows with created_at >= timestamp
  --created-before <ts>   Filter rows with created_at < timestamp
  --id-after <id>         Filter rows with id >= id
  --id-before <id>        Filter rows with id <= id
  --limit <n>             Max rows affected/listed (default: 100, clamped 1..1000)
  --format <text|json>    Output format for status command (default: text)

Status options:
  --recent-window-days <n>
                           Window for recent apply count in status (default: 7)
  --app-role <role>         Verify this role is NOT a member of maintenance role
  --operator-role <role>    Verify operator role membership in maintenance role
                            Repeat flag or pass comma-separated values
  --require-release-ready   Exit non-zero when release_ready=false (status only)

Remediation safety options:
  --apply                 Execute UPDATE via break-glass maintenance override (without this flag, command is dry-run)
  --actor <id>            Operator identifier (required with --apply)
  --ticket <id>           Change ticket/case identifier (required with --apply)
  --set-actor <id>        Replacement actor for invalid actor values (default: --actor)
  --set-ticket <id>       Replacement ticket for invalid ticket values (default: --ticket)
  --allow-unfiltered      Allow remediation without created/id filters

Ticket format policy (apply only):
  OUTBOX_REPLAY_TICKET_PATTERN
                          Optional ERE regex for --ticket/--set-ticket validation in --apply mode.
                          Default: ^((INC|CHG)[0-9]{5,}|CASE[-_ ]?[0-9]{1,12}|[A-Za-z][A-Za-z0-9]{1,14}-[0-9]{1,12})$

Validation options:
  --constraint <name>     Constraint name (default: outbox_replay_audit_apply_actor_ticket_ck)
  --lock-timeout-ms <ms>  SET LOCAL lock_timeout during validation (default: 5000)
  --statement-timeout-ms <ms>
                         SET LOCAL statement_timeout during validation (default: 600000)

Examples:
  scripts/outbox-replay-audit-compliance-tool.sh inspect-noncompliant --limit 50
  scripts/outbox-replay-audit-compliance-tool.sh remediate-noncompliant --created-after '2026-03-01T00:00:00Z' --limit 20
  scripts/outbox-replay-audit-compliance-tool.sh remediate-noncompliant --created-after '2026-03-01T00:00:00Z' --limit 20 --apply --actor oncall.sre --ticket INC-9001 --set-actor migration.legacy --set-ticket LEGACY-IMPORT
  scripts/outbox-replay-audit-compliance-tool.sh validate-constraint
  scripts/outbox-replay-audit-compliance-tool.sh validate-constraint --apply --lock-timeout-ms 10000 --statement-timeout-ms 900000
  scripts/outbox-replay-audit-compliance-tool.sh status
  scripts/outbox-replay-audit-compliance-tool.sh status --format json
  scripts/outbox-replay-audit-compliance-tool.sh status --app-role auth_app_runtime --operator-role ops_replay_oncall
  scripts/outbox-replay-audit-compliance-tool.sh status --format json --operator-role ops_replay_oncall,ops_replay_admin
  scripts/outbox-replay-audit-compliance-tool.sh status --format json --require-release-ready
EOF
}

require_psql() {
  if ! command -v psql >/dev/null 2>&1; then
    echo "ERROR: psql is required but was not found in PATH" >&2
    exit 1
  fi
}

trim_value() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

is_positive_int() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

normalize_role_list() {
  local raw="$1"
  local normalized=""
  local item=""

  IFS=',' read -r -a __role_items <<<"$raw"
  for item in "${__role_items[@]}"; do
    item="$(trim_value "$item")"
    if [[ -z "$item" ]]; then
      continue
    fi

    if [[ -z "$normalized" ]]; then
      normalized="$item"
    else
      normalized+=",$item"
    fi
  done

  printf '%s' "$normalized"
}

is_valid_ere_pattern() {
  local pattern="$1"
  local status=0
  printf '' | grep -E -- "$pattern" >/dev/null 2>&1 || status=$?
  [[ "$status" -ne 2 ]]
}

ticket_matches_pattern() {
  local value="$1"
  printf '%s\n' "$value" | grep -Eq -- "$ticket_pattern"
}

is_noncompliant_expression="
  is_apply
  AND (
    NULLIF(BTRIM(actor_identifier), '') IS NULL
    OR LOWER(BTRIM(actor_identifier)) = 'unknown'
    OR NULLIF(BTRIM(change_ticket), '') IS NULL
    OR LOWER(BTRIM(change_ticket)) = 'unknown'
  )
"

maintenance_override_guc="auth.outbox_replay_audit_maintenance_override"
maintenance_actor_guc="auth.outbox_replay_audit_maintenance_actor"
maintenance_ticket_guc="auth.outbox_replay_audit_maintenance_ticket"
maintenance_role_guc="auth.outbox_replay_audit_maintenance_role"
maintenance_role_default="outbox_replay_maintainer"

command="${1:-}"
if [[ -z "$command" || "$command" == "-h" || "$command" == "--help" ]]; then
  usage
  exit 0
fi
shift

database_url="${DATABASE_URL:-}"
created_after=""
created_before=""
id_after=""
id_before=""
limit="100"
apply="false"
allow_unfiltered="false"
actor=""
ticket=""
set_actor=""
set_ticket=""
constraint_name="outbox_replay_audit_apply_actor_ticket_ck"
lock_timeout_ms="5000"
statement_timeout_ms="600000"
output_format="text"
recent_window_days="7"
require_release_ready="false"
app_role=""
operator_roles=""
ticket_pattern_default='^((INC|CHG)[0-9]{5,}|CASE[-_ ]?[0-9]{1,12}|[A-Za-z][A-Za-z0-9]{1,14}-[0-9]{1,12})$'
ticket_pattern="${OUTBOX_REPLAY_TICKET_PATTERN:-$ticket_pattern_default}"

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --database-url)
      database_url="${2:-}"
      shift 2
      ;;
    --created-after)
      created_after="${2:-}"
      shift 2
      ;;
    --created-before)
      created_before="${2:-}"
      shift 2
      ;;
    --id-after)
      id_after="${2:-}"
      shift 2
      ;;
    --id-before)
      id_before="${2:-}"
      shift 2
      ;;
    --limit)
      limit="${2:-}"
      shift 2
      ;;
    --format)
      output_format="${2:-}"
      shift 2
      ;;
    --recent-window-days)
      recent_window_days="${2:-}"
      shift 2
      ;;
    --app-role)
      app_role="${2:-}"
      shift 2
      ;;
    --operator-role)
      if [[ -z "$operator_roles" ]]; then
        operator_roles="${2:-}"
      else
        operator_roles+=" ,${2:-}"
      fi
      shift 2
      ;;
    --require-release-ready)
      require_release_ready="true"
      shift
      ;;
    --apply)
      apply="true"
      shift
      ;;
    --allow-unfiltered)
      allow_unfiltered="true"
      shift
      ;;
    --actor)
      actor="${2:-}"
      shift 2
      ;;
    --ticket)
      ticket="${2:-}"
      shift 2
      ;;
    --set-actor)
      set_actor="${2:-}"
      shift 2
      ;;
    --set-ticket)
      set_ticket="${2:-}"
      shift 2
      ;;
    --constraint)
      constraint_name="${2:-}"
      shift 2
      ;;
    --lock-timeout-ms)
      lock_timeout_ms="${2:-}"
      shift 2
      ;;
    --statement-timeout-ms)
      statement_timeout_ms="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$database_url" ]]; then
  echo "ERROR: set DATABASE_URL or pass --database-url" >&2
  exit 1
fi

if ! is_positive_int "$limit"; then
  echo "ERROR: --limit must be a positive integer" >&2
  exit 1
fi

if [[ -n "$id_after" ]] && ! is_positive_int "$id_after"; then
  echo "ERROR: --id-after must be a positive integer" >&2
  exit 1
fi

if [[ -n "$id_before" ]] && ! is_positive_int "$id_before"; then
  echo "ERROR: --id-before must be a positive integer" >&2
  exit 1
fi

if ! is_positive_int "$lock_timeout_ms"; then
  echo "ERROR: --lock-timeout-ms must be a positive integer" >&2
  exit 1
fi

if ! is_positive_int "$statement_timeout_ms"; then
  echo "ERROR: --statement-timeout-ms must be a positive integer" >&2
  exit 1
fi

if ! is_positive_int "$recent_window_days"; then
  echo "ERROR: --recent-window-days must be a positive integer" >&2
  exit 1
fi

if [[ "$output_format" != "text" && "$output_format" != "json" ]]; then
  echo "ERROR: --format must be one of: text, json" >&2
  exit 1
fi

actor="$(trim_value "$actor")"
ticket="$(trim_value "$ticket")"
set_actor="$(trim_value "$set_actor")"
set_ticket="$(trim_value "$set_ticket")"
constraint_name="$(trim_value "$constraint_name")"
app_role="$(trim_value "$app_role")"
operator_roles="$(normalize_role_list "$operator_roles")"

if [[ "$command" == "validate-constraint" && -z "$constraint_name" ]]; then
  echo "ERROR: --constraint cannot be empty" >&2
  exit 1
fi

if [[ "$command" != "status" && "$output_format" != "text" ]]; then
  echo "ERROR: --format is only supported by the status command" >&2
  exit 1
fi

if [[ "$command" != "status" && "$require_release_ready" == "true" ]]; then
  echo "ERROR: --require-release-ready is only supported by the status command" >&2
  exit 1
fi

if [[ "$command" != "status" && -n "$app_role" ]]; then
  echo "ERROR: --app-role is only supported by the status command" >&2
  exit 1
fi

if [[ "$command" != "status" && -n "$operator_roles" ]]; then
  echo "ERROR: --operator-role is only supported by the status command" >&2
  exit 1
fi

if [[ "$command" == "backfill-noncompliant" ]]; then
  command="remediate-noncompliant"
fi

has_scope_filters="false"
if [[ -n "$created_after" || -n "$created_before" || -n "$id_after" || -n "$id_before" ]]; then
  has_scope_filters="true"
fi

if [[ "$command" == "remediate-noncompliant" && "$allow_unfiltered" != "true" && "$has_scope_filters" != "true" ]]; then
  echo "ERROR: remediate-noncompliant requires at least one scope filter" >&2
  echo "       (--created-after, --created-before, --id-after, --id-before)." >&2
  echo "       Use --allow-unfiltered only for explicitly approved broad remediation." >&2
  exit 1
fi

if [[ "$command" == "remediate-noncompliant" && "$apply" == "true" && -z "$actor" ]]; then
  echo "ERROR: --actor is required when using --apply" >&2
  exit 1
fi

if [[ "$command" == "remediate-noncompliant" && "$apply" == "true" && -z "$ticket" ]]; then
  echo "ERROR: --ticket is required when using --apply" >&2
  exit 1
fi

if [[ "$command" == "remediate-noncompliant" && "$apply" == "true" && "${actor,,}" == "unknown" ]]; then
  echo "ERROR: --actor value 'unknown' is not allowed with --apply" >&2
  exit 1
fi

if [[ "$command" == "remediate-noncompliant" && "$apply" == "true" && "${ticket,,}" == "unknown" ]]; then
  echo "ERROR: --ticket value 'unknown' is not allowed with --apply" >&2
  exit 1
fi

if [[ "$command" == "remediate-noncompliant" && "$apply" == "true" && -z "$set_actor" ]]; then
  set_actor="$actor"
fi

if [[ "$command" == "remediate-noncompliant" && "$apply" == "true" && -z "$set_ticket" ]]; then
  set_ticket="$ticket"
fi

if [[ "$command" == "remediate-noncompliant" && "$apply" == "true" && -z "$set_actor" ]]; then
  echo "ERROR: --set-actor cannot be empty in --apply mode" >&2
  exit 1
fi

if [[ "$command" == "remediate-noncompliant" && "$apply" == "true" && -z "$set_ticket" ]]; then
  echo "ERROR: --set-ticket cannot be empty in --apply mode" >&2
  exit 1
fi

if [[ "$command" == "remediate-noncompliant" && "$apply" == "true" && "${set_actor,,}" == "unknown" ]]; then
  echo "ERROR: --set-actor value 'unknown' is not allowed in --apply mode" >&2
  exit 1
fi

if [[ "$command" == "remediate-noncompliant" && "$apply" == "true" && "${set_ticket,,}" == "unknown" ]]; then
  echo "ERROR: --set-ticket value 'unknown' is not allowed in --apply mode" >&2
  exit 1
fi

if [[ "$command" == "remediate-noncompliant" && "$apply" == "true" ]] && ! is_valid_ere_pattern "$ticket_pattern"; then
  echo "ERROR: invalid ticket format regex in OUTBOX_REPLAY_TICKET_PATTERN" >&2
  echo "       Value: ${ticket_pattern}" >&2
  exit 1
fi

if [[ "$command" == "remediate-noncompliant" && "$apply" == "true" ]] && ! ticket_matches_pattern "$ticket"; then
  echo "ERROR: --ticket '${ticket}' does not match required format policy" >&2
  echo "       Regex (OUTBOX_REPLAY_TICKET_PATTERN): ${ticket_pattern}" >&2
  exit 1
fi

if [[ "$command" == "remediate-noncompliant" && "$apply" == "true" ]] && ! ticket_matches_pattern "$set_ticket"; then
  echo "ERROR: --set-ticket '${set_ticket}' does not match required format policy" >&2
  echo "       Regex (OUTBOX_REPLAY_TICKET_PATTERN): ${ticket_pattern}" >&2
  exit 1
fi

require_psql

run_psql() {
  local sql="$1"
  psql "$database_url" \
    -X \
    -v ON_ERROR_STOP=1 \
    -v created_after="$created_after" \
    -v created_before="$created_before" \
    -v id_after="$id_after" \
    -v id_before="$id_before" \
    -v row_limit="$limit" \
    -v apply_flag="$apply" \
    -v actor_identifier="$actor" \
    -v ticket_identifier="$ticket" \
    -v set_actor_identifier="$set_actor" \
    -v set_ticket_identifier="$set_ticket" \
    -v allow_unfiltered_flag="$allow_unfiltered" \
    -v constraint_name="$constraint_name" \
    -v lock_timeout_ms="$lock_timeout_ms" \
    -v statement_timeout_ms="$statement_timeout_ms" \
    -v output_format="$output_format" \
    -v recent_window_days="$recent_window_days" \
    -v app_role="$app_role" \
    -v operator_roles="$operator_roles" \
    -P pager=off \
    -f - <<<"$sql"
}

run_psql_scalar() {
  local sql="$1"
  psql "$database_url" \
    -X \
    -v ON_ERROR_STOP=1 \
    -v created_after="$created_after" \
    -v created_before="$created_before" \
    -v id_after="$id_after" \
    -v id_before="$id_before" \
    -v row_limit="$limit" \
    -v apply_flag="$apply" \
    -v actor_identifier="$actor" \
    -v ticket_identifier="$ticket" \
    -v set_actor_identifier="$set_actor" \
    -v set_ticket_identifier="$set_ticket" \
    -v allow_unfiltered_flag="$allow_unfiltered" \
    -v constraint_name="$constraint_name" \
    -v lock_timeout_ms="$lock_timeout_ms" \
    -v statement_timeout_ms="$statement_timeout_ms" \
    -v output_format="$output_format" \
    -v recent_window_days="$recent_window_days" \
    -v app_role="$app_role" \
    -v operator_roles="$operator_roles" \
    -P pager=off \
    -At \
    -f - <<<"$sql"
}

base_filters="
  ${is_noncompliant_expression}
  AND (NULLIF(:'created_after', '') IS NULL OR created_at >= NULLIF(:'created_after', '')::timestamptz)
  AND (NULLIF(:'created_before', '') IS NULL OR created_at < NULLIF(:'created_before', '')::timestamptz)
  AND (NULLIF(:'id_after', '') IS NULL OR id >= NULLIF(:'id_after', '')::bigint)
  AND (NULLIF(:'id_before', '') IS NULL OR id <= NULLIF(:'id_before', '')::bigint)
"

clamped_limit="GREATEST(1, LEAST(COALESCE(NULLIF(:'row_limit', '')::int, 100), 1000))"

case "$command" in
  inspect-noncompliant)
    run_psql "
      WITH selected AS (
        SELECT id,
               operation_type,
               actor_identifier,
               change_ticket,
               is_apply,
               created_at
        FROM outbox_replay_audit
        WHERE ${base_filters}
        ORDER BY created_at ASC, id ASC
        LIMIT ${clamped_limit}
      )
      SELECT id,
             operation_type,
             actor_identifier,
             change_ticket,
             is_apply,
             created_at
      FROM selected;
    "
    run_psql "
      SELECT COUNT(*)::bigint AS noncompliant_total
      FROM outbox_replay_audit
      WHERE ${base_filters};
    "
    ;;

  remediate-noncompliant)
    scope_noncompliant_total="$(run_psql_scalar "
      SELECT COUNT(*)::bigint
      FROM outbox_replay_audit
      WHERE ${base_filters};
    ")"

    if [[ -z "$scope_noncompliant_total" ]]; then
      echo "ERROR: failed to compute scope_noncompliant_total" >&2
      exit 1
    fi

    echo "INFO: scope_noncompliant_total=${scope_noncompliant_total} requested_limit=${limit}" >&2

    if [[ "$apply" != "true" ]]; then
      echo "WARNING: DRY-RUN mode. No rows will be mutated. Add --apply to execute remediation." >&2
      run_psql "
        WITH candidates AS (
          SELECT id,
                 actor_identifier,
                 change_ticket,
                 created_at
          FROM outbox_replay_audit
          WHERE ${base_filters}
          ORDER BY created_at ASC, id ASC
          LIMIT ${clamped_limit}
        )
        SELECT id,
               actor_identifier,
               change_ticket,
               created_at,
               CASE
                 WHEN NULLIF(BTRIM(actor_identifier), '') IS NULL OR LOWER(BTRIM(actor_identifier)) = 'unknown'
                   THEN COALESCE(NULLIF(:'set_actor_identifier', ''), '[missing --set-actor]')
                 ELSE actor_identifier
               END AS would_set_actor_identifier,
               CASE
                 WHEN NULLIF(BTRIM(change_ticket), '') IS NULL OR LOWER(BTRIM(change_ticket)) = 'unknown'
                   THEN COALESCE(NULLIF(:'set_ticket_identifier', ''), '[missing --set-ticket]')
                 ELSE change_ticket
               END AS would_set_change_ticket
        FROM candidates;
      "
      run_psql "
        SELECT COUNT(*)::bigint AS noncompliant_total
        FROM outbox_replay_audit
        WHERE ${base_filters};
      "
      exit 0
    fi

    echo "WARNING: APPLY mode requested. Rows in outbox_replay_audit can be mutated." >&2
    echo "WARNING: actor='${actor}' ticket='${ticket}' set_actor='${set_actor}' set_ticket='${set_ticket}'" >&2
    echo "WARNING: enabling break-glass maintenance override inside one transaction only." >&2
    echo "WARNING: override GUCs: ${maintenance_override_guc}, ${maintenance_actor_guc}, ${maintenance_ticket_guc}" >&2
    echo "CONFIRMATION: proceeding because --apply was explicitly provided." >&2

    run_psql "
      BEGIN;
      SELECT set_config('${maintenance_override_guc}', 'on', true) AS maintenance_override_enabled;
      SELECT set_config('${maintenance_actor_guc}', NULLIF(:'actor_identifier', ''), true) AS maintenance_actor;
      SELECT set_config('${maintenance_ticket_guc}', NULLIF(:'ticket_identifier', ''), true) AS maintenance_ticket;
      WITH candidates AS (
        SELECT id,
               actor_identifier,
               change_ticket,
               created_at
        FROM outbox_replay_audit
        WHERE ${base_filters}
        ORDER BY created_at ASC, id ASC
        LIMIT ${clamped_limit}
        FOR UPDATE SKIP LOCKED
      ),
      updated AS (
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
                  audit.created_at
      ),
      inserted_audit AS (
        INSERT INTO outbox_replay_audit (
          operation_type,
          actor_identifier,
          change_ticket,
          provider_filter,
          template_filter,
          failed_after_filter,
          failed_before_filter,
          row_limit,
          allow_unfiltered,
          is_apply,
          selected_count,
          updated_count,
          created_at
        )
        SELECT 'requeue',
                NULLIF(:'actor_identifier', ''),
                NULLIF(:'ticket_identifier', ''),
                NULL,
                'compliance_remediate_noncompliant',
                NULLIF(:'created_after', '')::timestamptz,
                NULLIF(:'created_before', '')::timestamptz,
                ${clamped_limit},
               COALESCE(NULLIF(:'allow_unfiltered_flag', '')::boolean, false),
               true,
               (SELECT COUNT(*)::bigint FROM candidates),
               (SELECT COUNT(*)::bigint FROM updated),
               NOW()
      )
      SELECT id,
             operation_type,
             actor_identifier,
             change_ticket,
             is_apply,
             created_at
      FROM updated
      ORDER BY created_at DESC, id DESC;
      COMMIT;
    "
    echo "INFO: maintenance override was requested and scoped to the remediation transaction." >&2
    run_psql "
      SELECT COUNT(*)::bigint AS remaining_noncompliant_total
      FROM outbox_replay_audit
      WHERE ${is_noncompliant_expression};
    "
    ;;

  validate-constraint)
    run_psql "
      SELECT c.conname,
             c.convalidated,
             pg_get_constraintdef(c.oid) AS definition
      FROM pg_constraint c
      WHERE c.conname = NULLIF(:'constraint_name', '')
        AND c.conrelid = 'outbox_replay_audit'::regclass;
    "
    run_psql "
      SELECT COUNT(*)::bigint AS noncompliant_total
      FROM outbox_replay_audit
      WHERE ${is_noncompliant_expression};
    "

    if [[ "$apply" != "true" ]]; then
      echo "DRY-RUN: constraint was not validated. Add --apply to execute ALTER TABLE ... VALIDATE CONSTRAINT." >&2
      exit 0
    fi

    run_psql "
      BEGIN;
      SELECT set_config('lock_timeout', NULLIF(:'lock_timeout_ms', '') || 'ms', true);
      SELECT set_config('statement_timeout', NULLIF(:'statement_timeout_ms', '') || 'ms', true);
      DO
      \$precheck\$
      BEGIN
        IF EXISTS (
          SELECT 1
          FROM outbox_replay_audit
          WHERE ${is_noncompliant_expression}
        ) THEN
          RAISE EXCEPTION 'Refusing to validate constraint. Noncompliant rows still exist.';
        END IF;
      END
      \$precheck\$;
      ALTER TABLE outbox_replay_audit VALIDATE CONSTRAINT :"constraint_name";
      COMMIT;
    "
    run_psql "
      SELECT c.conname,
             c.convalidated,
             pg_get_constraintdef(c.oid) AS definition
      FROM pg_constraint c
      WHERE c.conname = NULLIF(:'constraint_name', '')
        AND c.conrelid = 'outbox_replay_audit'::regclass;
    "
    ;;

  status)
    table_exists="$(run_psql_scalar "
      SELECT (to_regclass('public.outbox_replay_audit') IS NOT NULL);
    ")"

    if [[ "$table_exists" != "t" ]]; then
      if [[ "$output_format" == "json" ]]; then
        cat <<EOF
{"table_exists":false,"constraint_name":"${constraint_name}","constraint_exists":false,"constraint_validated":false,"has_block_update_trigger":false,"has_block_delete_trigger":false,"append_only_triggers_present":false,"historical_noncompliant_total":null,"recent_apply_window_days":${recent_window_days},"recent_apply_total":null,"maintenance_role_name":null,"maintenance_role_exists":false,"current_user_is_maintenance_member":false,"app_role_checked":$([[ -n "$app_role" ]] && echo true || echo false),"app_role_is_maintenance_member":null,"operator_roles_checked":null,"operator_roles_missing_membership_count":null,"operator_roles_missing_membership":null,"operator_roles_missing_membership_list":[],"release_ready":false}
EOF
      else
        echo "status=error reason=outbox_replay_audit_table_missing"
        echo "table_exists=false"
        echo "release_ready=false"
      fi

      if [[ "$require_release_ready" == "true" ]]; then
        echo "ERROR: release_ready=false while --require-release-ready is enabled" >&2
        exit 1
      fi

      exit 0
    fi

    if [[ "$output_format" == "json" ]]; then
      status_json_row="$(run_psql_scalar "
        WITH target AS (
          SELECT to_regclass('public.outbox_replay_audit') AS relid
        ),
        constraint_state AS (
          SELECT EXISTS (
                   SELECT 1
                   FROM pg_constraint c
                   CROSS JOIN target t
                   WHERE c.conrelid = t.relid
                     AND c.conname = NULLIF(:'constraint_name', '')
                 ) AS constraint_exists,
                 COALESCE((
                   SELECT c.convalidated
                   FROM pg_constraint c
                   CROSS JOIN target t
                   WHERE c.conrelid = t.relid
                     AND c.conname = NULLIF(:'constraint_name', '')
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
                     WHERE ${is_noncompliant_expression}
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
                   NULLIF(BTRIM(current_setting('${maintenance_role_guc}', true)), ''),
                   '${maintenance_role_default}'
                 ) AS maintenance_role_name,
                 EXISTS (
                   SELECT 1
                   FROM pg_roles r
                   WHERE r.rolname = COALESCE(
                     NULLIF(BTRIM(current_setting('${maintenance_role_guc}', true)), ''),
                     '${maintenance_role_default}'
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
        SELECT json_build_object(
                  'table_exists', (t.relid IS NOT NULL),
                  'constraint_name', NULLIF(:'constraint_name', ''),
                  'constraint_exists', cs.constraint_exists,
                 'constraint_validated', cs.constraint_validated,
                 'has_block_update_trigger', ts.has_block_update_trigger,
                 'has_block_delete_trigger', ts.has_block_delete_trigger,
                 'append_only_triggers_present', (ts.has_block_update_trigger AND ts.has_block_delete_trigger),
                  'historical_noncompliant_total', qs.historical_noncompliant_total,
                  'recent_apply_window_days', GREATEST(1, COALESCE(NULLIF(:'recent_window_days', '')::int, 7)),
                  'recent_apply_total', qs.recent_apply_total,
                  'maintenance_role_name', ms.maintenance_role_name,
                   'maintenance_role_exists', ms.maintenance_role_exists,
                   'current_user_is_maintenance_member', (
                     ms.maintenance_role_exists
                     AND pg_has_role(current_user, ms.maintenance_role_name, 'MEMBER')
                   ),
                    'app_role_checked', rds.app_role_checked,
                     'app_role_is_maintenance_member', rds.app_role_is_maintenance_member,
                     'operator_roles_checked', rds.operator_roles_checked,
                     'operator_roles_missing_membership_count', rds.operator_roles_missing_membership_count,
                     'operator_roles_missing_membership', rds.operator_roles_missing_membership,
                     'operator_roles_missing_membership_list', COALESCE((
                       SELECT json_agg(orm.role_name ORDER BY orm.role_name)
                       FROM operator_roles_missing orm
                     ), '[]'::json),
                     'release_ready', (
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
                    )
                  )::text,
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
                 )
        FROM target t
        CROSS JOIN constraint_state cs
        CROSS JOIN trigger_state ts
        CROSS JOIN quality_state qs
        CROSS JOIN maintenance_state ms
        CROSS JOIN role_drift_state rds;
      ")"

      IFS='|' read -r status_json release_ready <<<"$status_json_row"
      echo "$status_json"

      if [[ "$require_release_ready" == "true" && "$release_ready" != "t" ]]; then
        echo "ERROR: release_ready=false while --require-release-ready is enabled" >&2
        exit 1
      fi

      exit 0
    fi

    status_row="$(run_psql_scalar "
      WITH target AS (
        SELECT to_regclass('public.outbox_replay_audit') AS relid
      ),
      constraint_state AS (
        SELECT EXISTS (
                 SELECT 1
                 FROM pg_constraint c
                 CROSS JOIN target t
                 WHERE c.conrelid = t.relid
                   AND c.conname = NULLIF(:'constraint_name', '')
               ) AS constraint_exists,
               COALESCE((
                 SELECT c.convalidated
                 FROM pg_constraint c
                 CROSS JOIN target t
                 WHERE c.conrelid = t.relid
                   AND c.conname = NULLIF(:'constraint_name', '')
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
                   WHERE ${is_noncompliant_expression}
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
                 NULLIF(BTRIM(current_setting('${maintenance_role_guc}', true)), ''),
                 '${maintenance_role_default}'
               ) AS maintenance_role_name,
               EXISTS (
                 SELECT 1
                 FROM pg_roles r
                 WHERE r.rolname = COALESCE(
                   NULLIF(BTRIM(current_setting('${maintenance_role_guc}', true)), ''),
                   '${maintenance_role_default}'
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
      SELECT (t.relid IS NOT NULL),
             cs.constraint_exists,
             cs.constraint_validated,
             ts.has_block_update_trigger,
             ts.has_block_delete_trigger,
             COALESCE(qs.historical_noncompliant_total::text, 'null'),
             GREATEST(1, COALESCE(NULLIF(:'recent_window_days', '')::int, 7)),
             COALESCE(qs.recent_apply_total::text, 'null'),
             ms.maintenance_role_name,
             ms.maintenance_role_exists,
             (
               ms.maintenance_role_exists
               AND pg_has_role(current_user, ms.maintenance_role_name, 'MEMBER')
             ),
             rds.app_role_checked,
              COALESCE(rds.app_role_is_maintenance_member::text, 'null'),
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
               )
      FROM target t
      CROSS JOIN constraint_state cs
      CROSS JOIN trigger_state ts
      CROSS JOIN quality_state qs
      CROSS JOIN maintenance_state ms
      CROSS JOIN role_drift_state rds;
    ")"

    IFS='|' read -r table_exists constraint_exists constraint_validated has_block_update_trigger has_block_delete_trigger historical_noncompliant_total recent_apply_window_days recent_apply_total maintenance_role_name maintenance_role_exists current_user_is_maintenance_member app_role_checked app_role_is_maintenance_member operator_roles_checked operator_roles_missing_membership_count operator_roles_missing_membership release_ready <<<"$status_row"

    if [[ "$table_exists" != "t" ]]; then
      echo "status=error reason=outbox_replay_audit_table_missing"
      echo "table_exists=false"
      exit 1
    fi

    echo "status=ok"
    echo "constraint_name=${constraint_name}"
    echo "constraint_exists=$([[ "$constraint_exists" == "t" ]] && echo true || echo false)"
    echo "constraint_validated=$([[ "$constraint_validated" == "t" ]] && echo true || echo false)"
    echo "append_only_triggers_present=$([[ "$has_block_update_trigger" == "t" && "$has_block_delete_trigger" == "t" ]] && echo true || echo false)"
    echo "has_block_update_trigger=$([[ "$has_block_update_trigger" == "t" ]] && echo true || echo false)"
    echo "has_block_delete_trigger=$([[ "$has_block_delete_trigger" == "t" ]] && echo true || echo false)"
    echo "historical_noncompliant_total=${historical_noncompliant_total}"
    echo "recent_apply_window_days=${recent_apply_window_days}"
    echo "recent_apply_total=${recent_apply_total}"
    echo "maintenance_role_name=${maintenance_role_name}"
    echo "maintenance_role_exists=$([[ "$maintenance_role_exists" == "t" ]] && echo true || echo false)"
    echo "current_user_is_maintenance_member=$([[ "$current_user_is_maintenance_member" == "t" ]] && echo true || echo false)"
    echo "app_role_checked=$([[ "$app_role_checked" == "t" ]] && echo true || echo false)"
    if [[ "$app_role_is_maintenance_member" == "t" ]]; then
      echo "app_role_is_maintenance_member=true"
    elif [[ "$app_role_is_maintenance_member" == "f" ]]; then
      echo "app_role_is_maintenance_member=false"
    else
      echo "app_role_is_maintenance_member=null"
    fi
    echo "operator_roles_checked=${operator_roles_checked}"
    echo "operator_roles_missing_membership_count=${operator_roles_missing_membership_count}"
    echo "operator_roles_missing_membership=${operator_roles_missing_membership}"
    echo "release_ready=$([[ "$release_ready" == "t" ]] && echo true || echo false)"

    if [[ "$require_release_ready" == "true" && "$release_ready" != "t" ]]; then
      echo "status=error reason=release_not_ready" >&2
      exit 1
    fi
    ;;

  *)
    echo "ERROR: unknown command '$command'" >&2
    usage
    exit 1
    ;;
esac

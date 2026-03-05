#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"

usage() {
  cat <<'EOF'
Operational tooling for exhausted email outbox messages (dead-letter style).

Usage:
  scripts/outbox-dead-letter-tool.sh <command> [options]

Commands:
  inspect   List exhausted messages with filters (read-only)
  requeue   Requeue exhausted messages (dry-run by default)
  report    Summarize dead-letter counts by provider/template and age buckets
  audit     List recent replay audit operations

Common options:
  --database-url <url>   PostgreSQL URL (default: DATABASE_URL)
  --provider <name>      Filter by provider
  --template <name>      Filter by template
  --ticket <id>          Change ticket/case identifier (audit filter)
  --failed-after <ts>    Filter: failed_at >= timestamp (audit: created_at >= ts)
  --failed-before <ts>   Filter: failed_at < timestamp (audit: created_at < ts)
  --limit <n>            Max rows to inspect/requeue (default: 100, clamped 1..1000)

Requeue safety options:
  --apply                Execute UPDATE (without this flag, command is dry-run)
  --actor <id>           Operator identifier (required with --apply)
  --ticket <id>          Change ticket/case identifier (required with --apply)
  --allow-unfiltered     Allow requeue without provider/template/date filters

Ticket format policy (apply only):
  OUTBOX_REPLAY_TICKET_PATTERN
                         Optional ERE regex for --ticket format validation in --apply mode.
                         Default: ^((INC|CHG)[0-9]{5,}|CASE[-_ ]?[0-9]{1,12}|[A-Za-z][A-Za-z0-9]{1,14}-[0-9]{1,12})$

Examples:
  scripts/outbox-dead-letter-tool.sh inspect --provider sendgrid --limit 25
  scripts/outbox-dead-letter-tool.sh requeue --template verification --failed-after '2026-03-01T00:00:00Z'
  scripts/outbox-dead-letter-tool.sh requeue --provider sendgrid --limit 20 --apply --actor oncall.sre --ticket INC-12345
  scripts/outbox-dead-letter-tool.sh report --failed-after '2026-03-01T00:00:00Z'
  scripts/outbox-dead-letter-tool.sh audit --ticket INC-12345 --limit 50
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

command="${1:-}"
if [[ -z "$command" || "$command" == "-h" || "$command" == "--help" ]]; then
  usage
  exit 0
fi
shift

database_url="${DATABASE_URL:-}"
provider=""
template=""
failed_after=""
failed_before=""
limit="100"
apply="false"
allow_unfiltered="false"
actor=""
ticket=""
ticket_pattern_default='^((INC|CHG)[0-9]{5,}|CASE[-_ ]?[0-9]{1,12}|[A-Za-z][A-Za-z0-9]{1,14}-[0-9]{1,12})$'
ticket_pattern="${OUTBOX_REPLAY_TICKET_PATTERN:-$ticket_pattern_default}"

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --database-url)
      database_url="${2:-}"
      shift 2
      ;;
    --provider)
      provider="${2:-}"
      shift 2
      ;;
    --template)
      template="${2:-}"
      shift 2
      ;;
    --ticket)
      ticket="${2:-}"
      shift 2
      ;;
    --failed-after)
      failed_after="${2:-}"
      shift 2
      ;;
    --failed-before)
      failed_before="${2:-}"
      shift 2
      ;;
    --limit)
      limit="${2:-}"
      shift 2
      ;;
    --apply)
      apply="true"
      shift
      ;;
    --actor)
      actor="${2:-}"
      shift 2
      ;;
    --allow-unfiltered)
      allow_unfiltered="true"
      shift
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

if ! [[ "$limit" =~ ^[0-9]+$ ]]; then
  echo "ERROR: --limit must be a positive integer" >&2
  exit 1
fi

has_filters="false"
if [[ -n "$provider" || -n "$template" || -n "$failed_after" || -n "$failed_before" ]]; then
  has_filters="true"
fi

if [[ "$command" == "requeue" && "$allow_unfiltered" != "true" && "$has_filters" != "true" ]]; then
  echo "ERROR: requeue requires at least one filter (--provider/--template/--failed-after/--failed-before)" >&2
  echo "       Use --allow-unfiltered only when you intentionally want a broad replay." >&2
  exit 1
fi

if [[ "$command" == "requeue" ]]; then
  actor="$(trim_value "$actor")"
  ticket="$(trim_value "$ticket")"
fi

if [[ "$command" == "requeue" && "$apply" == "true" && -z "$actor" ]]; then
  echo "ERROR: --actor is required when using --apply (compliance audit requirement)" >&2
  exit 1
fi

if [[ "$command" == "requeue" && "$apply" == "true" && -z "$ticket" ]]; then
  echo "ERROR: --ticket is required when using --apply (change-control linkage requirement)" >&2
  exit 1
fi

if [[ "$command" == "requeue" && "$apply" == "true" && "${actor,,}" == "unknown" ]]; then
  echo "ERROR: --actor value 'unknown' is reserved for dry-run audit rows" >&2
  exit 1
fi

if [[ "$command" == "requeue" && "$apply" == "true" && "${ticket,,}" == "unknown" ]]; then
  echo "ERROR: --ticket value 'unknown' is reserved for dry-run audit rows" >&2
  exit 1
fi

if [[ "$command" == "requeue" && "$apply" == "true" ]] && ! is_valid_ere_pattern "$ticket_pattern"; then
  echo "ERROR: invalid ticket format regex in OUTBOX_REPLAY_TICKET_PATTERN" >&2
  echo "       Value: ${ticket_pattern}" >&2
  exit 1
fi

if [[ "$command" == "requeue" && "$apply" == "true" ]] && ! ticket_matches_pattern "$ticket"; then
  echo "ERROR: --ticket '${ticket}' does not match required format policy" >&2
  echo "       Regex (OUTBOX_REPLAY_TICKET_PATTERN): ${ticket_pattern}" >&2
  exit 1
fi

if [[ -z "$actor" ]]; then
  actor="unknown"
fi

if [[ "$command" == "requeue" && -z "$ticket" ]]; then
  ticket="unknown"
fi

require_psql

run_psql() {
  local sql="$1"
  psql "$database_url" \
    -X \
    -v ON_ERROR_STOP=1 \
    -v provider="$provider" \
    -v template="$template" \
    -v failed_after="$failed_after" \
    -v failed_before="$failed_before" \
    -v row_limit="$limit" \
    -v actor_identifier="$actor" \
    -v ticket_identifier="$ticket" \
    -v allow_unfiltered_flag="$allow_unfiltered" \
    -P pager=off \
    -f - <<<"$sql"
}

base_filters="
  status = 'failed'
  AND next_attempt_at IS NULL
  AND (NULLIF(:'provider', '') IS NULL OR provider = :'provider')
  AND (NULLIF(:'template', '') IS NULL OR template = :'template')
  AND (NULLIF(:'failed_after', '') IS NULL OR failed_at >= NULLIF(:'failed_after', '')::timestamptz)
  AND (NULLIF(:'failed_before', '') IS NULL OR failed_at < NULLIF(:'failed_before', '')::timestamptz)
"

clamped_limit="GREATEST(1, LEAST(COALESCE(NULLIF(:'row_limit', '')::int, 100), 1000))"

case "$command" in
  inspect)
    run_psql "
      SELECT id,
             provider,
             template,
             attempts,
             failed_at,
             last_error,
             updated_at
      FROM email_outbox
      WHERE ${base_filters}
      ORDER BY failed_at ASC NULLS LAST, updated_at ASC
      LIMIT ${clamped_limit};
    "
    ;;

  requeue)
    if [[ "$apply" != "true" ]]; then
      echo "DRY-RUN: no rows updated. Add --apply to execute requeue." >&2
      run_psql "
        WITH selected_total AS (
          SELECT COUNT(*)::bigint AS selected_count
          FROM email_outbox
          WHERE ${base_filters}
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
                 COALESCE(NULLIF(:'actor_identifier', ''), 'unknown'),
                 COALESCE(NULLIF(:'ticket_identifier', ''), 'unknown'),
                 NULLIF(:'provider', ''),
                 NULLIF(:'template', ''),
                 NULLIF(:'failed_after', '')::timestamptz,
                 NULLIF(:'failed_before', '')::timestamptz,
                 ${clamped_limit},
                 COALESCE(NULLIF(:'allow_unfiltered_flag', '')::boolean, false),
                 false,
                 selected_count,
                 0,
                 NOW()
          FROM selected_total
          RETURNING id,
                    created_at,
                    actor_identifier,
                    change_ticket,
                    selected_count,
                    updated_count,
                    is_apply
        )
        SELECT *
        FROM inserted_audit;
      "
      run_psql "
        SELECT id,
               provider,
               template,
               attempts,
               failed_at,
               last_error,
               updated_at
        FROM email_outbox
        WHERE ${base_filters}
        ORDER BY failed_at ASC NULLS LAST, updated_at ASC
        LIMIT ${clamped_limit};
      "
      exit 0
    fi

    run_psql "
      WITH candidates AS (
        SELECT id
        FROM email_outbox
        WHERE ${base_filters}
        ORDER BY failed_at ASC NULLS LAST, updated_at ASC
        LIMIT ${clamped_limit}
        FOR UPDATE SKIP LOCKED
      ),
      updated AS (
        UPDATE email_outbox AS outbox
        SET status = 'pending',
            attempts = 0,
            next_attempt_at = NOW(),
            last_error = NULL,
            failed_at = NULL,
            sent_at = NULL,
            last_attempt_at = NULL,
            processing_owner = NULL,
            lease_expires_at = NULL,
            updated_at = NOW()
        FROM candidates
        WHERE outbox.id = candidates.id
        RETURNING outbox.id,
                  outbox.provider,
                  outbox.template,
                  outbox.status,
                  outbox.next_attempt_at,
                  outbox.updated_at
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
               COALESCE(NULLIF(:'actor_identifier', ''), 'unknown'),
               COALESCE(NULLIF(:'ticket_identifier', ''), 'unknown'),
               NULLIF(:'provider', ''),
               NULLIF(:'template', ''),
               NULLIF(:'failed_after', '')::timestamptz,
               NULLIF(:'failed_before', '')::timestamptz,
               ${clamped_limit},
               COALESCE(NULLIF(:'allow_unfiltered_flag', '')::boolean, false),
               true,
               (SELECT COUNT(*)::bigint FROM candidates),
               (SELECT COUNT(*)::bigint FROM updated),
               NOW()
        RETURNING id,
                  created_at,
                  actor_identifier,
                  change_ticket,
                  selected_count,
                  updated_count,
                  is_apply
      )
      SELECT id,
             provider,
             template,
             status,
             next_attempt_at,
             updated_at
      FROM updated
      ORDER BY updated_at DESC;
    "
    ;;

  report)
    run_psql "
      WITH filtered AS (
        SELECT provider,
               template,
               NOW() - COALESCE(failed_at, updated_at) AS dead_letter_age
        FROM email_outbox
        WHERE ${base_filters}
      )
      SELECT provider,
             template,
             COUNT(*) FILTER (WHERE dead_letter_age < INTERVAL '1 hour') AS age_lt_1h,
             COUNT(*) FILTER (WHERE dead_letter_age >= INTERVAL '1 hour' AND dead_letter_age < INTERVAL '6 hours') AS age_1h_6h,
             COUNT(*) FILTER (WHERE dead_letter_age >= INTERVAL '6 hours' AND dead_letter_age < INTERVAL '24 hours') AS age_6h_24h,
             COUNT(*) FILTER (WHERE dead_letter_age >= INTERVAL '24 hours' AND dead_letter_age < INTERVAL '3 days') AS age_1d_3d,
             COUNT(*) FILTER (WHERE dead_letter_age >= INTERVAL '3 days') AS age_ge_3d,
             COUNT(*) AS total
      FROM filtered
      GROUP BY provider, template
      ORDER BY total DESC, provider ASC, template ASC
      LIMIT ${clamped_limit};
    "
    ;;

  audit)
    run_psql "
      SELECT id,
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
      FROM outbox_replay_audit
      WHERE (NULLIF(:'provider', '') IS NULL OR provider_filter = :'provider')
        AND (NULLIF(:'template', '') IS NULL OR template_filter = :'template')
        AND (NULLIF(:'ticket_identifier', '') IS NULL OR change_ticket = :'ticket_identifier')
        AND (NULLIF(:'failed_after', '') IS NULL OR created_at >= NULLIF(:'failed_after', '')::timestamptz)
        AND (NULLIF(:'failed_before', '') IS NULL OR created_at < NULLIF(:'failed_before', '')::timestamptz)
      ORDER BY created_at DESC
      LIMIT ${clamped_limit};
    "
    ;;

  *)
    echo "ERROR: unknown command '$command'" >&2
    usage
    exit 1
    ;;
esac

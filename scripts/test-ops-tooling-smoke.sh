#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

usage() {
  cat <<'EOF'
Reproducible smoke test for replay-audit/dead-letter operator tooling.

Usage:
  scripts/test-ops-tooling-smoke.sh [--postgres-url <admin_url>] [--keep-db]

Options:
  --postgres-url <url>  Admin PostgreSQL URL (defaults to DATABASE_URL or local postgres)
  --keep-db             Keep temporary smoke-test database for manual inspection
  -h, --help            Show this help

Notes:
  - Creates an ephemeral database: auth_ops_smoke_<timestamp>_<random>
  - Applies all SQL migrations in migrations/*.sql
  - Provisions role drift posture for strict status checks:
      outbox_replay_maintainer, ops_replay_oncall, auth_app_runtime
  - Runs fail-fast checkpoints and prints a PASS/FAIL summary
EOF
}

require_bin() {
  local bin="$1"
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "ERROR: required binary '$bin' not found in PATH" >&2
    exit 1
  fi
}

default_postgres_url() {
  if [[ -n "${DATABASE_URL:-}" ]]; then
    printf '%s\n' "${DATABASE_URL}"
    return
  fi

  local host="${PGHOST:-127.0.0.1}"
  local port="${PGPORT:-5432}"
  local user="${PGUSER:-postgres}"
  local database="${PGDATABASE:-postgres}"

  printf 'postgres://%s@%s:%s/%s\n' "$user" "$host" "$port" "$database"
}

build_database_url() {
  local admin_url="$1"
  local database_name="$2"

  python3 - "$admin_url" "$database_name" <<'PY'
import sys
import urllib.parse

admin_url = sys.argv[1]
database_name = sys.argv[2]

parts = urllib.parse.urlsplit(admin_url)
if parts.scheme not in ("postgres", "postgresql"):
    raise SystemExit(f"ERROR: unsupported postgres URL scheme: {parts.scheme}")

path = "/" + database_name
print(urllib.parse.urlunsplit((parts.scheme, parts.netloc, path, parts.query, parts.fragment)))
PY
}

psql_exec() {
  local database_url="$1"
  local sql="$2"
  psql "$database_url" -X -v ON_ERROR_STOP=1 -P pager=off -f - <<<"$sql"
}

admin_url=""
keep_db="false"

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --postgres-url)
      admin_url="${2:-}"
      shift 2
      ;;
    --keep-db)
      keep_db="true"
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

require_bin psql
require_bin python3

if [[ -z "$admin_url" ]]; then
  admin_url="$(default_postgres_url)"
fi

timestamp="$(date +%Y%m%d%H%M%S)"
database_name="auth_ops_smoke_${timestamp}_${RANDOM}"
smoke_url="$(build_database_url "$admin_url" "$database_name")"

declare -a checkpoints=()
overall_status="PASS"

print_summary() {
  local exit_code="$1"

  echo
  echo "== Ops Tooling Smoke Test =="
  echo "Result: ${overall_status}"
  echo "Database: ${database_name}"
  echo "Keep DB: ${keep_db}"
  echo "Checkpoints:"
  local checkpoint
  for checkpoint in "${checkpoints[@]}"; do
    echo "  - ${checkpoint}"
  done

  if [[ "$exit_code" -ne 0 ]]; then
    echo "Exit code: ${exit_code}"
  fi
}

cleanup_db() {
  if [[ "$keep_db" == "true" ]]; then
    return
  fi

  psql_exec "$admin_url" "
    SELECT pg_terminate_backend(pid)
    FROM pg_stat_activity
    WHERE datname = '${database_name}'
      AND pid <> pg_backend_pid();

    DROP DATABASE IF EXISTS \"${database_name}\";
  " >/dev/null 2>&1 || true
}

on_exit() {
  local exit_code=$?
  if [[ "$exit_code" -ne 0 ]]; then
    overall_status="FAIL"
  fi

  cleanup_db
  print_summary "$exit_code"
}

trap on_exit EXIT

run_checkpoint() {
  local label="$1"
  shift

  echo "[checkpoint] ${label}"
  if "$@"; then
    checkpoints+=("PASS: ${label}")
  else
    checkpoints+=("FAIL: ${label}")
    overall_status="FAIL"
    return 1
  fi
}

run_checkpoint "Create temporary database" \
  psql_exec "$admin_url" "CREATE DATABASE \"${database_name}\";"

run_checkpoint "Apply migrations" bash -c '
  set -euo pipefail
  for migration in "$1"/migrations/*.sql; do
    psql "$2" -X -v ON_ERROR_STOP=1 -P pager=off -f "$migration" >/dev/null
  done
' bash "$REPO_ROOT" "$smoke_url"

run_checkpoint "Provision maintenance/operator/runtime roles" \
  psql_exec "$admin_url" "
    DO
    \$\$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'outbox_replay_maintainer') THEN
        CREATE ROLE outbox_replay_maintainer NOLOGIN;
      END IF;

      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ops_replay_oncall') THEN
        CREATE ROLE ops_replay_oncall NOLOGIN;
      END IF;

      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auth_app_runtime') THEN
        CREATE ROLE auth_app_runtime NOLOGIN;
      END IF;
    END
    \$\$;

    GRANT outbox_replay_maintainer TO ops_replay_oncall;
    REVOKE outbox_replay_maintainer FROM auth_app_runtime;
  "

run_checkpoint "Compliance status JSON" \
  bash "$REPO_ROOT/scripts/outbox-replay-audit-compliance-tool.sh" \
    status \
    --database-url "$smoke_url" \
    --format json

run_checkpoint "Validate constraint apply" \
  bash "$REPO_ROOT/scripts/outbox-replay-audit-compliance-tool.sh" \
    validate-constraint \
    --database-url "$smoke_url" \
    --apply

run_checkpoint "Strict release-ready status JSON" \
  bash "$REPO_ROOT/scripts/outbox-replay-audit-compliance-tool.sh" \
    status \
    --database-url "$smoke_url" \
    --format json \
    --app-role auth_app_runtime \
    --operator-role ops_replay_oncall \
    --require-release-ready

run_checkpoint "Dead-letter audit limit 1" \
  bash "$REPO_ROOT/scripts/outbox-dead-letter-tool.sh" \
    audit \
    --database-url "$smoke_url" \
    --limit 1

#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   PGPASSWORD='<local_password>' scripts/test-postgres-local.sh
#   AUTH_TEST_DATABASE_URL='postgres://user:pass@127.0.0.1:5432/postgres' scripts/test-postgres-local.sh
#   PGPASSWORD='<local_password>' scripts/test-postgres-local.sh adapters::postgres::tests::

if [[ -z "${AUTH_TEST_DATABASE_URL:-}" ]]; then
  : "${PGPASSWORD:?Set PGPASSWORD or AUTH_TEST_DATABASE_URL}"

  pg_host="${PGHOST:-127.0.0.1}"
  pg_port="${PGPORT:-5432}"
  pg_user="${PGUSER:-postgres}"
  pg_database="${PGDATABASE:-postgres}"

  encoded_password="$(python3 -c 'import os, urllib.parse; print(urllib.parse.quote(os.environ["PGPASSWORD"], safe=""))')"
  export AUTH_TEST_DATABASE_URL="postgres://${pg_user}:${encoded_password}@${pg_host}:${pg_port}/${pg_database}"
fi

if [[ "$#" -gt 0 ]]; then
  cargo test "$@"
else
  cargo test
fi

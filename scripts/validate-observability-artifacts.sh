#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

validate_json() {
  local file="$1"
  python3 - "$file" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
with path.open('r', encoding='utf-8') as f:
    json.load(f)

print(f"OK json: {path}")
PY
}

validate_rules_with_promtool() {
  local rules_file="docs/alerts/auth-refresh-alert-rules.yaml"

  if command -v promtool >/dev/null 2>&1; then
    promtool check rules "$rules_file"
    return 0
  fi

  if command -v docker >/dev/null 2>&1; then
    docker run --rm -v "${ROOT_DIR}:/work" -w /work prom/prometheus:v2.53.0 \
      promtool check rules "$rules_file"
    return 0
  fi

  if [[ "${STRICT_PROMTOOL:-false}" == "true" ]]; then
    echo "ERROR: promtool not available (no local binary and no docker)" >&2
    return 1
  fi

  echo "WARN: skipping promtool validation (set STRICT_PROMTOOL=true to enforce)" >&2
  return 0
}

main() {
  cd "$ROOT_DIR"

  for dashboard in docs/grafana/*.json; do
    validate_json "$dashboard"
  done

  validate_rules_with_promtool

  echo "Observability artifacts validation completed"
}

main "$@"

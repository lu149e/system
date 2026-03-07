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
    docker run --rm --entrypoint=promtool -v "${ROOT_DIR}:/work" -w /work prom/prometheus:v2.53.0 \
      check rules "$rules_file"
    return 0
  fi

  if [[ "${STRICT_PROMTOOL:-false}" == "true" ]]; then
    echo "ERROR: promtool not available (no local binary and no docker)" >&2
    return 1
  fi

  echo "WARN: skipping promtool validation (set STRICT_PROMTOOL=true to enforce)" >&2
  return 0
}

validate_auth_v2_dashboard_contract() {
  local dashboard_file="docs/grafana/auth-refresh-runtime-prometheus.json"

  python3 - "$dashboard_file" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
dashboard = json.loads(path.read_text(encoding="utf-8"))
payload = json.dumps(dashboard, sort_keys=True)

required_fragments = [
    "auth_v2_methods_requests_total",
    "auth_v2_password_finish_requests_total",
    "auth_v2_legacy_fallback_total",
    "auth_v2_auth_flows_expired_pending_total",
    "auth_v2_auth_flows_oldest_expired_pending_age_seconds",
    "auth_v2_auth_flow_prune_runs_total",
    "auth:auth_v2_password_finish_error_ratio_10m",
    "auth:auth_v2_legacy_fallback_ratio_15m",
    "auth:auth_v2_auth_flow_prune_errors_10m",
    "auth:auth_v2_auth_flow_oldest_expired_pending_age_seconds_max_15m",
]

missing = [fragment for fragment in required_fragments if fragment not in payload]
if missing:
    print(
        "ERROR: auth v2 dashboard is missing required rollout queries: "
        + ", ".join(missing),
        file=sys.stderr,
    )
    sys.exit(1)

print(f"OK auth v2 dashboard contract: {path}")
PY
}

validate_auth_v2_alert_contract() {
  local rules_file="docs/alerts/auth-refresh-alert-rules.yaml"

  python3 - "$rules_file" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
content = path.read_text(encoding="utf-8")

required_fragments = [
    "auth:auth_v2_password_finish_error_ratio_10m",
    "auth:auth_v2_legacy_fallback_ratio_15m",
    "auth:auth_v2_auth_flow_prune_errors_10m",
    "auth:auth_v2_auth_flow_oldest_expired_pending_age_seconds_max_15m",
    "AuthV2PasswordFinishErrorRatioHigh",
    "AuthV2PasswordFinishErrorRatioCritical",
    "AuthV2LegacyFallbackRatioHigh",
    "AuthV2AuthFlowPruneErrorsSustained",
    "AuthV2AuthFlowExpiredBacklogHigh",
]

missing = [fragment for fragment in required_fragments if fragment not in content]
if missing:
    print(
        "ERROR: auth v2 alert rules are missing required rollout records/alerts: "
        + ", ".join(missing),
        file=sys.stderr,
    )
    sys.exit(1)

print(f"OK auth v2 alert contract: {path}")
PY
}

main() {
  cd "$ROOT_DIR"

  for dashboard in docs/grafana/*.json; do
    validate_json "$dashboard"
  done

  validate_rules_with_promtool
  validate_auth_v2_dashboard_contract
  validate_auth_v2_alert_contract

  echo "Observability artifacts validation completed"
}

main "$@"

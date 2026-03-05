#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${AUTH_PERF_OUT_DIR:-${ROOT_DIR}/artifacts/perf}"

require_command() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $cmd" >&2
    exit 1
  fi
}

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "ERROR: required env var is missing: $name" >&2
    exit 1
  fi
}

run_mode() {
  local mode="$1"
  local duration="$2"
  local rate="$3"
  local pre_allocated_vus="$4"
  local max_vus="$5"

  local raw_summary="${OUT_DIR}/k6-summary-${mode}.json"
  local kpi_summary="${OUT_DIR}/kpi-summary-${mode}.json"

  echo "Running auth perf mode=${mode} duration=${duration} rate=${rate}/s"
  k6 run "${ROOT_DIR}/scripts/perf/auth-load-soak.js" \
    --summary-export "${raw_summary}" \
    -e AUTH_BASE_URL="${AUTH_BASE_URL}" \
    -e AUTH_PERF_EMAIL="${AUTH_PERF_EMAIL}" \
    -e AUTH_PERF_PASSWORD="${AUTH_PERF_PASSWORD}" \
    -e AUTH_PERF_MODE="${mode}" \
    -e AUTH_PERF_DURATION="${duration}" \
    -e AUTH_PERF_RATE="${rate}" \
    -e AUTH_PERF_PREALLOCATED_VUS="${pre_allocated_vus}" \
    -e AUTH_PERF_MAX_VUS="${max_vus}"

  python3 "${ROOT_DIR}/scripts/perf/evaluate-k6-summary.py" \
    --summary "${raw_summary}" \
    --output "${kpi_summary}" \
    --mode "${mode}" \
    --login-p95-ms "${AUTH_PERF_LOGIN_P95_MS:-300}" \
    --refresh-p95-ms "${AUTH_PERF_REFRESH_P95_MS:-200}" \
    --me-p95-ms "${AUTH_PERF_ME_P95_MS:-250}" \
    --max-error-rate "${AUTH_PERF_MAX_ERROR_RATE:-0.01}" \
    --min-throughput-rps "${AUTH_PERF_MIN_THROUGHPUT_RPS:-200}"
}

main() {
  local mode="${1:-load}"

  require_command k6
  require_command python3

  require_env AUTH_BASE_URL
  require_env AUTH_PERF_EMAIL
  require_env AUTH_PERF_PASSWORD

  mkdir -p "${OUT_DIR}"

  local load_duration="${AUTH_PERF_LOAD_DURATION:-3m}"
  local load_rate="${AUTH_PERF_LOAD_RATE:-200}"
  local load_preallocated_vus="${AUTH_PERF_LOAD_PREALLOCATED_VUS:-200}"
  local load_max_vus="${AUTH_PERF_LOAD_MAX_VUS:-600}"

  local soak_duration="${AUTH_PERF_SOAK_DURATION:-30m}"
  local soak_rate="${AUTH_PERF_SOAK_RATE:-80}"
  local soak_preallocated_vus="${AUTH_PERF_SOAK_PREALLOCATED_VUS:-100}"
  local soak_max_vus="${AUTH_PERF_SOAK_MAX_VUS:-300}"

  case "${mode}" in
    load)
      run_mode "load" "${load_duration}" "${load_rate}" "${load_preallocated_vus}" "${load_max_vus}"
      ;;
    soak)
      run_mode "soak" "${soak_duration}" "${soak_rate}" "${soak_preallocated_vus}" "${soak_max_vus}"
      ;;
    both)
      run_mode "load" "${load_duration}" "${load_rate}" "${load_preallocated_vus}" "${load_max_vus}"
      run_mode "soak" "${soak_duration}" "${soak_rate}" "${soak_preallocated_vus}" "${soak_max_vus}"
      ;;
    *)
      echo "ERROR: unsupported mode '${mode}'. Use: load | soak | both" >&2
      exit 1
      ;;
  esac

  python3 - "${OUT_DIR}" "${mode}" <<'PY'
import json
import pathlib
import sys

out_dir = pathlib.Path(sys.argv[1])
mode = sys.argv[2]

files = []
for name in ("load", "soak"):
    path = out_dir / f"kpi-summary-{name}.json"
    if path.exists():
        files.append(path)

if not files:
    raise SystemExit("No KPI summaries found")

payloads = [json.loads(path.read_text(encoding="utf-8")) for path in files]
aggregate = {
    "requested_mode": mode,
    "overall_pass": all(item.get("overall_pass", False) for item in payloads),
    "results": payloads,
}

target = out_dir / "kpi-summary.json"
target.write_text(json.dumps(aggregate, indent=2), encoding="utf-8")
print(f"Machine-readable summary written to {target}")
PY

  if [[ -f "${OUT_DIR}/kpi-summary.json" ]]; then
    if python3 - "${OUT_DIR}/kpi-summary.json" <<'PY'
import json
import sys

payload = json.loads(open(sys.argv[1], encoding="utf-8").read())
raise SystemExit(0 if payload.get("overall_pass") else 1)
PY
    then
      echo "Auth performance gate: PASS"
    else
      echo "Auth performance gate: FAIL" >&2
      exit 1
    fi
  fi
}

main "$@"

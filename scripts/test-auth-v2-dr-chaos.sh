#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEFAULT_ARTIFACT_DIR="${ROOT_DIR}/artifacts/auth-v2-dr-chaos"
DEFAULT_DEPLOY_READINESS_SCRIPT="${ROOT_DIR}/scripts/validate-deploy-readiness.sh"

artifact_dir="${DEFAULT_ARTIFACT_DIR}"
deploy_readiness_script="${DEFAULT_DEPLOY_READINESS_SCRIPT}"
drain_readyz_file=""
drain_metrics_file=""
brownout_readyz_file=""
pre_recovery_metrics_file=""
post_recovery_metrics_file=""
jwt_rollback_restore_jwks_file=""
jwt_rollback_restore_check_file=""
jwt_rollback_retire_jwks_file=""
jwt_rollback_retire_check_file=""
skip_deploy_readiness="false"

declare -a checkpoints=()
overall_status="PASS"

usage() {
  cat <<'EOF'
Deterministic auth-v2 DR and chaos verification.

Usage:
  scripts/test-auth-v2-dr-chaos.sh \
    --drain-readyz <file.json> \
    --drain-metrics <file.prom> \
    --brownout-readyz <file.json> \
    --pre-recovery-metrics <file.prom> \
    --post-recovery-metrics <file.prom>

  Optional JWT rollback evidence (required when the drill overlaps JWT key rollback):
    --jwt-rollback-restore-jwks <file.json> \
    --jwt-rollback-restore-check <file.txt> \
    --jwt-rollback-retire-jwks <file.json> \
    --jwt-rollback-retire-check <file.txt>

Options:
  --artifact-dir <dir>              Output directory for drill reports
  --deploy-readiness-script <path>  Script to validate rollout readiness
  --jwt-rollback-restore-jwks <file> Captured JWKS after rollback key restore
  --jwt-rollback-restore-check <file> Key=value evidence for rollback restore validation
  --jwt-rollback-retire-jwks <file>  Captured JWKS after old key retirement
  --jwt-rollback-retire-check <file> Key=value evidence for post-recovery retirement validation
  --skip-deploy-readiness           Skip rollout validation hook
  --self-test                       Run deterministic self-test fixtures
  -h, --help                        Show this help

Notes:
  - This script validates captured readiness/metrics evidence; it does not inject faults itself.
  - Capture files with curl during drills, then feed them here for repeatable PASS/FAIL validation.
  - The artifact directory includes operator notes with suggested capture commands.
EOF
}

require_bin() {
  local bin="$1"
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "ERROR: required binary '$bin' not found in PATH" >&2
    exit 1
  fi
}

require_file() {
  local file_path="$1"
  local label="$2"
  if [[ ! -f "${file_path}" ]]; then
    echo "ERROR: missing ${label}: ${file_path}" >&2
    exit 1
  fi
}

print_summary() {
  local exit_code="$1"

  echo
  echo "== Auth V2 DR Chaos Drill =="
  echo "Result: ${overall_status}"
  echo "Artifacts: ${artifact_dir}"
  echo "Checkpoints:"
  local checkpoint
  for checkpoint in "${checkpoints[@]}"; do
    echo "  - ${checkpoint}"
  done

  if [[ "${exit_code}" -ne 0 ]]; then
    echo "Exit code: ${exit_code}"
  fi
}

on_exit() {
  local exit_code=$?
  if [[ "${exit_code}" -ne 0 ]]; then
    overall_status="FAIL"
  fi
  print_summary "${exit_code}"
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

write_operator_notes() {
  cat >"${artifact_dir}/operator-notes.txt" <<'EOF'
Capture suggestions for the live drill:
- Drain readyz: curl -fsS http://127.0.0.1:8080/readyz > drain-readyz.json
- Drain metrics: curl -fsS http://127.0.0.1:8080/metrics > drain-metrics.prom
- Brownout readyz: curl -fsS http://127.0.0.1:8080/readyz > brownout-readyz.json
- Backlog before recovery: curl -fsS http://127.0.0.1:8080/metrics > backlog-before.prom
- Backlog after recovery: curl -fsS http://127.0.0.1:8080/metrics > backlog-after.prom
- JWT rollback restore JWKS: curl -fsS http://127.0.0.1:8080/.well-known/jwks.json > jwt-rollback-restore-jwks.json
- JWT rollback restore check: write key=value evidence (rollback_kid, primary_kid, rollback_key_published=true, old_token_valid=true, primary_token_valid=true)
- JWT rollback retire JWKS: curl -fsS http://127.0.0.1:8080/.well-known/jwks.json > jwt-rollback-retire-jwks.json
- JWT rollback retire check: write key=value evidence (retired_kid, primary_kid, retired_kid_absent=true, retired_token_rejected=true, primary_token_valid=true)

Expected evidence:
- drain-readyz.json -> status=error, components.app.status=draining
- drain-metrics.prom -> auth_runtime_draining 1 and auth_runtime_shutdowns_total{reason="sigterm"} > 0
- brownout-readyz.json -> at least one dependency component error/degraded
- backlog-before.prom -> expired pending backlog > 0
- backlog-after.prom -> success prune run > 0, pruned_total > 0, expired pending backlog == 0
- jwt-rollback-restore-jwks.json -> publishes both rollback and primary kids during recovery
- jwt-rollback-restore-check.txt -> confirms rollback key republished and affected tokens validate again
- jwt-rollback-retire-jwks.json -> removes the retired kid while keeping the promoted kid active
- jwt-rollback-retire-check.txt -> confirms the retired kid is rejected and the promoted kid still validates
EOF
}

jwt_rollback_requested() {
  [[ -n "${jwt_rollback_restore_jwks_file}" || -n "${jwt_rollback_restore_check_file}" || -n "${jwt_rollback_retire_jwks_file}" || -n "${jwt_rollback_retire_check_file}" ]]
}

validate_readyz_json() {
  local mode="$1"
  local input_file="$2"
  local report_file="$3"

  python3 - "$mode" "$input_file" "$report_file" <<'PY'
import json
import pathlib
import sys

mode = sys.argv[1]
input_path = pathlib.Path(sys.argv[2])
report_path = pathlib.Path(sys.argv[3])
payload = json.loads(input_path.read_text(encoding="utf-8"))
components = payload.get("components", {})
errors = []
lines = [f"Validated {mode} readiness payload from {input_path}."]

if payload.get("status") != "error":
    errors.append(f"expected payload.status='error', found {payload.get('status')!r}")
else:
    lines.append("OK payload.status=error")

app = components.get("app", {})
if mode == "drain":
    if app.get("status") != "draining":
        errors.append(f"expected app.status='draining', found {app.get('status')!r}")
    else:
        lines.append("OK app.status=draining")
    detail = app.get("detail") or ""
    if "shutdown_reason=" not in detail:
        errors.append("drain readiness detail must include shutdown_reason=")
    else:
        lines.append(f"OK app.detail={detail!r}")
else:
    dependency_states = {
        name: value.get("status")
        for name, value in components.items()
        if name in {"database", "redis", "auth_flow_janitor"}
    }
    if not any(status in {"error", "degraded"} for status in dependency_states.values()):
        errors.append("expected database/redis/auth_flow_janitor to report error or degraded")
    else:
        lines.append(f"OK dependency states={dependency_states}")

report_lines = list(lines)
if errors:
    report_lines.append("")
    report_lines.append("Errors:")
    report_lines.extend(f"- {error}" for error in errors)
report_path.write_text("\n".join(report_lines) + "\n", encoding="utf-8")

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    sys.exit(1)
PY
}

validate_metrics_contract() {
  local mode="$1"
  local input_file="$2"
  local report_file="$3"

  python3 - "$mode" "$input_file" "$report_file" <<'PY'
import pathlib
import re
import sys

mode = sys.argv[1]
input_path = pathlib.Path(sys.argv[2])
report_path = pathlib.Path(sys.argv[3])
text = input_path.read_text(encoding="utf-8")
errors = []
lines = [f"Validated {mode} metrics payload from {input_path}."]

def metric_value(name: str, labels=None):
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if labels is None:
            if line.startswith(name + " "):
                return float(line.split()[-1])
        else:
            prefix = name + "{" + labels + "} "
            if line.startswith(prefix):
                return float(line.split()[-1])
    return None

if mode == "drain":
    draining = metric_value("auth_runtime_draining")
    shutdowns = metric_value("auth_runtime_shutdowns_total", 'reason="sigterm"')
    if draining != 1:
        errors.append(f"expected auth_runtime_draining=1, found {draining!r}")
    else:
        lines.append("OK auth_runtime_draining=1")
    if shutdowns is None or shutdowns <= 0:
        errors.append("expected auth_runtime_shutdowns_total{reason=\"sigterm\"} > 0")
    else:
        lines.append(f"OK auth_runtime_shutdowns_total{{reason=\"sigterm\"}}={shutdowns}")
elif mode == "pre_recovery":
    backlog = metric_value("auth_v2_auth_flows_expired_pending_total")
    oldest = metric_value("auth_v2_auth_flows_oldest_expired_pending_age_seconds")
    if backlog is None or backlog <= 0:
        errors.append("expected expired backlog > 0 before recovery")
    else:
        lines.append(f"OK expired backlog before recovery={backlog}")
    if oldest is None or oldest <= 0:
        errors.append("expected oldest expired backlog age > 0 before recovery")
    else:
        lines.append(f"OK oldest expired backlog age={oldest}")
elif mode == "post_recovery":
    backlog = metric_value("auth_v2_auth_flows_expired_pending_total")
    prune_runs = metric_value("auth_v2_auth_flow_prune_runs_total", 'outcome="success"')
    pruned_total = metric_value("auth_v2_auth_flow_pruned_total")
    if backlog != 0:
        errors.append(f"expected expired backlog == 0 after recovery, found {backlog!r}")
    else:
        lines.append("OK expired backlog after recovery=0")
    if prune_runs is None or prune_runs <= 0:
        errors.append("expected auth_v2_auth_flow_prune_runs_total{outcome=\"success\"} > 0")
    else:
        lines.append(f"OK prune success runs={prune_runs}")
    if pruned_total is None or pruned_total <= 0:
        errors.append("expected auth_v2_auth_flow_pruned_total > 0")
    else:
        lines.append(f"OK pruned total={pruned_total}")
else:
    errors.append(f"unsupported metrics validation mode: {mode}")

report_lines = list(lines)
if errors:
    report_lines.append("")
    report_lines.append("Errors:")
    report_lines.extend(f"- {error}" for error in errors)
report_path.write_text("\n".join(report_lines) + "\n", encoding="utf-8")

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    sys.exit(1)
PY
}

validate_jwt_rollback_restore() {
  local jwks_file="$1"
  local check_file="$2"
  local report_file="$3"

  python3 - "$jwks_file" "$check_file" "$report_file" <<'PY'
import json
import pathlib
import sys

jwks_path = pathlib.Path(sys.argv[1])
check_path = pathlib.Path(sys.argv[2])
report_path = pathlib.Path(sys.argv[3])

errors = []
lines = [f"Validated JWT rollback restore evidence from {jwks_path} and {check_path}."]

payload = json.loads(jwks_path.read_text(encoding="utf-8"))
kids = {key.get("kid") for key in payload.get("keys", []) if key.get("kid")}

checks = {}
for raw_line in check_path.read_text(encoding="utf-8").splitlines():
    line = raw_line.strip()
    if not line or line.startswith("#"):
        continue
    if "=" not in line:
        errors.append(f"invalid rollback restore evidence line: {raw_line!r}")
        continue
    key, value = line.split("=", 1)
    checks[key.strip()] = value.strip()

rollback_kid = checks.get("rollback_kid")
primary_kid = checks.get("primary_kid")
if not rollback_kid:
    errors.append("missing rollback_kid in rollback restore evidence")
if not primary_kid:
    errors.append("missing primary_kid in rollback restore evidence")

for key in ("rollback_key_published", "old_token_valid", "primary_token_valid"):
    if checks.get(key) != "true":
        errors.append(f"expected {key}=true in rollback restore evidence")
    else:
        lines.append(f"OK {key}=true")

if rollback_kid:
    if rollback_kid not in kids:
        errors.append(f"rollback kid {rollback_kid!r} missing from restore JWKS")
    else:
        lines.append(f"OK restore JWKS publishes rollback kid {rollback_kid!r}")

if primary_kid:
    if primary_kid not in kids:
        errors.append(f"primary kid {primary_kid!r} missing from restore JWKS")
    else:
        lines.append(f"OK restore JWKS publishes primary kid {primary_kid!r}")

report_lines = list(lines)
if errors:
    report_lines.append("")
    report_lines.append("Errors:")
    report_lines.extend(f"- {error}" for error in errors)
report_path.write_text("\n".join(report_lines) + "\n", encoding="utf-8")

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    sys.exit(1)
PY
}

validate_jwt_rollback_retire() {
  local jwks_file="$1"
  local check_file="$2"
  local report_file="$3"

  python3 - "$jwks_file" "$check_file" "$report_file" <<'PY'
import json
import pathlib
import sys

jwks_path = pathlib.Path(sys.argv[1])
check_path = pathlib.Path(sys.argv[2])
report_path = pathlib.Path(sys.argv[3])

errors = []
lines = [f"Validated JWT rollback retirement evidence from {jwks_path} and {check_path}."]

payload = json.loads(jwks_path.read_text(encoding="utf-8"))
kids = {key.get("kid") for key in payload.get("keys", []) if key.get("kid")}

checks = {}
for raw_line in check_path.read_text(encoding="utf-8").splitlines():
    line = raw_line.strip()
    if not line or line.startswith("#"):
        continue
    if "=" not in line:
        errors.append(f"invalid rollback retirement evidence line: {raw_line!r}")
        continue
    key, value = line.split("=", 1)
    checks[key.strip()] = value.strip()

retired_kid = checks.get("retired_kid")
primary_kid = checks.get("primary_kid")
if not retired_kid:
    errors.append("missing retired_kid in rollback retirement evidence")
if not primary_kid:
    errors.append("missing primary_kid in rollback retirement evidence")

for key in ("retired_kid_absent", "retired_token_rejected", "primary_token_valid"):
    if checks.get(key) != "true":
        errors.append(f"expected {key}=true in rollback retirement evidence")
    else:
        lines.append(f"OK {key}=true")

if retired_kid:
    if retired_kid in kids:
        errors.append(f"retired kid {retired_kid!r} should not appear in retirement JWKS")
    else:
        lines.append(f"OK retirement JWKS excludes retired kid {retired_kid!r}")

if primary_kid:
    if primary_kid not in kids:
        errors.append(f"primary kid {primary_kid!r} missing from retirement JWKS")
    else:
        lines.append(f"OK retirement JWKS keeps primary kid {primary_kid!r}")

report_lines = list(lines)
if errors:
    report_lines.append("")
    report_lines.append("Errors:")
    report_lines.extend(f"- {error}" for error in errors)
report_path.write_text("\n".join(report_lines) + "\n", encoding="utf-8")

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    sys.exit(1)
PY
}

validate_docs_runtime_contract() {
  local report_file="$1"

  python3 - "$ROOT_DIR" "$report_file" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
report_path = pathlib.Path(sys.argv[2])

checks = [
    (
        root / "docs/runtime-assumptions.md",
        [
            "AUTH_SHUTDOWN_GRACE_PERIOD_SECONDS=25",
            "terminationGracePeriodSeconds=40",
            "scripts/test-auth-v2-dr-chaos.sh",
            "scripts/validate-deploy-readiness.sh",
        ],
    ),
    (
        root / "docs/jwt-key-rotation-runbook.md",
        [
            "./scripts/validate-deploy-readiness.sh",
            "./scripts/test-auth-v2-dr-chaos.sh",
            "--jwt-rollback-restore-jwks",
            "--jwt-rollback-retire-jwks",
        ],
    ),
    (
        root / "docs/deployment-production-checklist.md",
        [
            "./scripts/validate-deploy-readiness.sh",
            "./scripts/test-auth-v2-dr-chaos.sh",
            "--drain-readyz",
            "--jwt-rollback-restore-jwks",
        ],
    ),
    (
        root / "scripts/validate-deploy-readiness.sh",
        [
            'AUTH_SHUTDOWN_GRACE_PERIOD_SECONDS="${AUTH_SHUTDOWN_GRACE_PERIOD_SECONDS:-25}"',
            "terminationGracePeriodSeconds",
            "/readyz",
        ],
    ),
    (
        root / "deploy/k8s/deployment.yaml",
        [
            "terminationGracePeriodSeconds: 40",
            "path: /readyz",
        ],
    ),
]

errors = []
lines = []

for file_path, required_markers in checks:
    if not file_path.is_file():
        errors.append(f"missing contract file: {file_path}")
        continue
    content = file_path.read_text(encoding="utf-8")
    lines.append(f"Validated contract markers in {file_path}.")
    for marker in required_markers:
        if marker not in content:
            errors.append(f"missing marker {marker!r} in {file_path}")
        else:
            lines.append(f"OK {file_path.name} contains {marker!r}")

report_lines = list(lines)
if errors:
    report_lines.append("")
    report_lines.append("Errors:")
    report_lines.extend(f"- {error}" for error in errors)
report_path.write_text("\n".join(report_lines) + "\n", encoding="utf-8")

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    sys.exit(1)
PY
}

run_deploy_readiness() {
  if [[ "${skip_deploy_readiness}" == "true" ]]; then
    echo "Skipped deploy readiness validation by request" >"${artifact_dir}/deploy-readiness.log"
    return 0
  fi

  require_file "${deploy_readiness_script}" "deploy readiness script"
  bash "${deploy_readiness_script}" >"${artifact_dir}/deploy-readiness.log" 2>&1
}

self_test() {
  local temp_dir
  temp_dir="$(mktemp -d)"

  cat >"${temp_dir}/drain-readyz.json" <<'EOF'
{"status":"error","runtime":"postgres_redis","components":{"app":{"status":"draining","detail":"shutdown_reason=sigterm"},"database":{"status":"ok"},"redis":{"status":"ok"},"passkey_challenge_janitor":{"status":"not_configured"},"auth_flow_janitor":{"status":"starting","detail":"waiting for first auth flow janitor execution"}}}
EOF

  cat >"${temp_dir}/brownout-readyz.json" <<'EOF'
{"status":"error","runtime":"postgres_redis","components":{"app":{"status":"ok"},"database":{"status":"ok"},"redis":{"status":"error","detail":"redis connect failed: connection refused"},"passkey_challenge_janitor":{"status":"not_configured"},"auth_flow_janitor":{"status":"degraded","detail":"last_failure_detail=db timeout"}}}
EOF

  cat >"${temp_dir}/drain-metrics.prom" <<'EOF'
# TYPE auth_runtime_draining gauge
auth_runtime_draining 1
# TYPE auth_runtime_shutdowns_total counter
auth_runtime_shutdowns_total{reason="sigterm"} 1
EOF

  cat >"${temp_dir}/pre-recovery.prom" <<'EOF'
auth_v2_auth_flows_expired_pending_total 3
auth_v2_auth_flows_oldest_expired_pending_age_seconds 120
EOF

  cat >"${temp_dir}/post-recovery.prom" <<'EOF'
auth_v2_auth_flows_expired_pending_total 0
auth_v2_auth_flow_prune_runs_total{outcome="success"} 2
auth_v2_auth_flow_pruned_total 3
EOF

  cat >"${temp_dir}/jwt-rollback-restore-jwks.json" <<'EOF'
{"keys":[{"kid":"auth-ed25519-v1"},{"kid":"auth-ed25519-v2"}]}
EOF

  cat >"${temp_dir}/jwt-rollback-retire-jwks.json" <<'EOF'
{"keys":[{"kid":"auth-ed25519-v2"}]}
EOF

  cat >"${temp_dir}/jwt-rollback-restore-check.txt" <<'EOF'
rollback_kid=auth-ed25519-v1
primary_kid=auth-ed25519-v2
rollback_key_published=true
old_token_valid=true
primary_token_valid=true
EOF

  cat >"${temp_dir}/jwt-rollback-retire-check.txt" <<'EOF'
retired_kid=auth-ed25519-v1
primary_kid=auth-ed25519-v2
retired_kid_absent=true
retired_token_rejected=true
primary_token_valid=true
EOF

  cat >"${temp_dir}/fake-validate-deploy-readiness.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "fake deploy readiness passed"
EOF
  chmod +x "${temp_dir}/fake-validate-deploy-readiness.sh"

  bash "$0" \
    --artifact-dir "${temp_dir}/artifacts" \
    --deploy-readiness-script "${temp_dir}/fake-validate-deploy-readiness.sh" \
    --drain-readyz "${temp_dir}/drain-readyz.json" \
    --drain-metrics "${temp_dir}/drain-metrics.prom" \
    --brownout-readyz "${temp_dir}/brownout-readyz.json" \
    --pre-recovery-metrics "${temp_dir}/pre-recovery.prom" \
    --post-recovery-metrics "${temp_dir}/post-recovery.prom" \
    --jwt-rollback-restore-jwks "${temp_dir}/jwt-rollback-restore-jwks.json" \
    --jwt-rollback-restore-check "${temp_dir}/jwt-rollback-restore-check.txt" \
    --jwt-rollback-retire-jwks "${temp_dir}/jwt-rollback-retire-jwks.json" \
    --jwt-rollback-retire-check "${temp_dir}/jwt-rollback-retire-check.txt"

  cat >"${temp_dir}/jwt-rollback-retire-check-bad.txt" <<'EOF'
retired_kid=auth-ed25519-v1
primary_kid=auth-ed25519-v2
retired_kid_absent=true
retired_token_rejected=false
primary_token_valid=true
EOF

  if bash "$0" \
    --artifact-dir "${temp_dir}/failing-artifacts" \
    --deploy-readiness-script "${temp_dir}/fake-validate-deploy-readiness.sh" \
    --drain-readyz "${temp_dir}/drain-readyz.json" \
    --drain-metrics "${temp_dir}/drain-metrics.prom" \
    --brownout-readyz "${temp_dir}/brownout-readyz.json" \
    --pre-recovery-metrics "${temp_dir}/pre-recovery.prom" \
    --post-recovery-metrics "${temp_dir}/post-recovery.prom" \
    --jwt-rollback-restore-jwks "${temp_dir}/jwt-rollback-restore-jwks.json" \
    --jwt-rollback-restore-check "${temp_dir}/jwt-rollback-restore-check.txt" \
    --jwt-rollback-retire-jwks "${temp_dir}/jwt-rollback-retire-jwks.json" \
    --jwt-rollback-retire-check "${temp_dir}/jwt-rollback-retire-check-bad.txt"; then
    echo "self-test failed: contradictory JWT rollback retirement evidence should fail" >&2
    exit 1
  fi

  rm -rf "${temp_dir}"
  echo "auth v2 dr chaos self-test passed"
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --artifact-dir)
      artifact_dir="${2:-}"
      shift 2
      ;;
    --deploy-readiness-script)
      deploy_readiness_script="${2:-}"
      shift 2
      ;;
    --drain-readyz)
      drain_readyz_file="${2:-}"
      shift 2
      ;;
    --drain-metrics)
      drain_metrics_file="${2:-}"
      shift 2
      ;;
    --brownout-readyz)
      brownout_readyz_file="${2:-}"
      shift 2
      ;;
    --pre-recovery-metrics)
      pre_recovery_metrics_file="${2:-}"
      shift 2
      ;;
    --post-recovery-metrics)
      post_recovery_metrics_file="${2:-}"
      shift 2
      ;;
    --jwt-rollback-restore-jwks)
      jwt_rollback_restore_jwks_file="${2:-}"
      shift 2
      ;;
    --jwt-rollback-restore-check)
      jwt_rollback_restore_check_file="${2:-}"
      shift 2
      ;;
    --jwt-rollback-retire-jwks)
      jwt_rollback_retire_jwks_file="${2:-}"
      shift 2
      ;;
    --jwt-rollback-retire-check)
      jwt_rollback_retire_check_file="${2:-}"
      shift 2
      ;;
    --skip-deploy-readiness)
      skip_deploy_readiness="true"
      shift
      ;;
    --self-test)
      trap - EXIT
      self_test
      exit 0
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

require_bin python3

if [[ -z "${drain_readyz_file}" || -z "${drain_metrics_file}" || -z "${brownout_readyz_file}" || -z "${pre_recovery_metrics_file}" || -z "${post_recovery_metrics_file}" ]]; then
  echo "ERROR: drill evidence inputs are required" >&2
  usage
  exit 1
fi

require_file "${drain_readyz_file}" "drain readiness payload"
require_file "${drain_metrics_file}" "drain metrics payload"
require_file "${brownout_readyz_file}" "brownout readiness payload"
require_file "${pre_recovery_metrics_file}" "pre-recovery metrics payload"
require_file "${post_recovery_metrics_file}" "post-recovery metrics payload"

if jwt_rollback_requested; then
  if [[ -z "${jwt_rollback_restore_jwks_file}" || -z "${jwt_rollback_restore_check_file}" || -z "${jwt_rollback_retire_jwks_file}" || -z "${jwt_rollback_retire_check_file}" ]]; then
    echo "ERROR: all JWT rollback evidence inputs are required when any JWT rollback artifact is provided" >&2
    exit 1
  fi

  require_file "${jwt_rollback_restore_jwks_file}" "JWT rollback restore JWKS payload"
  require_file "${jwt_rollback_restore_check_file}" "JWT rollback restore evidence"
  require_file "${jwt_rollback_retire_jwks_file}" "JWT rollback retirement JWKS payload"
  require_file "${jwt_rollback_retire_check_file}" "JWT rollback retirement evidence"
fi

mkdir -p "${artifact_dir}"
write_operator_notes

run_checkpoint "Validate drain readiness withdrawal" \
  validate_readyz_json drain "${drain_readyz_file}" "${artifact_dir}/drain-readyz-report.txt"
run_checkpoint "Validate drain metrics evidence" \
  validate_metrics_contract drain "${drain_metrics_file}" "${artifact_dir}/drain-metrics-report.txt"
run_checkpoint "Validate dependency brownout readiness posture" \
  validate_readyz_json brownout "${brownout_readyz_file}" "${artifact_dir}/brownout-readyz-report.txt"
run_checkpoint "Validate backlog presence before recovery" \
  validate_metrics_contract pre_recovery "${pre_recovery_metrics_file}" "${artifact_dir}/pre-recovery-report.txt"
run_checkpoint "Validate backlog clears after recovery" \
  validate_metrics_contract post_recovery "${post_recovery_metrics_file}" "${artifact_dir}/post-recovery-report.txt"
if jwt_rollback_requested; then
  run_checkpoint "Validate JWT rollback restore evidence" \
    validate_jwt_rollback_restore "${jwt_rollback_restore_jwks_file}" "${jwt_rollback_restore_check_file}" "${artifact_dir}/jwt-rollback-restore-report.txt"
  run_checkpoint "Validate JWT rollback retirement evidence" \
    validate_jwt_rollback_retire "${jwt_rollback_retire_jwks_file}" "${jwt_rollback_retire_check_file}" "${artifact_dir}/jwt-rollback-retire-report.txt"
else
  checkpoints+=("SKIP: JWT rollback evidence not provided")
fi
run_checkpoint "Validate docs and runtime contract markers" \
  validate_docs_runtime_contract "${artifact_dir}/docs-runtime-contract-report.txt"
run_checkpoint "Validate deploy readiness contract" run_deploy_readiness

cat >"${artifact_dir}/summary.txt" <<EOF
Auth V2 DR chaos drill result: ${overall_status}
Artifacts directory: ${artifact_dir}
Generated reports:
- drain-readyz-report.txt
- drain-metrics-report.txt
- brownout-readyz-report.txt
- pre-recovery-report.txt
- post-recovery-report.txt
- jwt-rollback-restore-report.txt (when JWT rollback artifacts are provided)
- jwt-rollback-retire-report.txt (when JWT rollback artifacts are provided)
- docs-runtime-contract-report.txt
- deploy-readiness.log
- operator-notes.txt
EOF
